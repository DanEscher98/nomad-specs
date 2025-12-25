"""
Replay attack resistance tests.

Tests the anti-replay protection mechanisms including sliding window,
nonce tracking, and replay check ordering.

Test mapping: specs/1-SECURITY.md § "Anti-Replay Protection"
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    NomadCodec,
    construct_nonce,
    deterministic_bytes,
    xchacha20_poly1305_encrypt,
)

# =============================================================================
# Anti-Replay Constants (from spec)
# =============================================================================


REPLAY_WINDOW_SIZE = 2048  # Minimum window size in bits
MAX_NONCE_COUNTER = 2**64 - 1


# =============================================================================
# Sliding Window Implementation
# =============================================================================


@dataclass
class ReplayWindow:
    """Sliding window for replay protection.

    Implements a bitmap-based sliding window that tracks seen nonces
    and rejects replays.

    Per spec:
    - Window size: 2048 bits minimum
    - Below window: MUST reject
    - Seen nonce: MUST reject
    - Above highest: Update window
    """

    window_size: int = REPLAY_WINDOW_SIZE
    highest_seen: int = -1
    bitmap: int = 0  # Bitmask of seen nonces relative to highest

    def is_replay(self, nonce_counter: int) -> bool:
        """Check if nonce is a replay.

        Args:
            nonce_counter: The nonce counter to check.

        Returns:
            True if this is a replay (should be rejected), False otherwise.
        """
        # First nonce ever
        if self.highest_seen < 0:
            return False

        # Below window - definitely a replay or very old
        if nonce_counter <= self.highest_seen - self.window_size:
            return True

        # Above highest - not a replay (new)
        if nonce_counter > self.highest_seen:
            return False

        # Within window - check bitmap
        offset = self.highest_seen - nonce_counter
        if offset >= 0 and offset < self.window_size:
            return (self.bitmap & (1 << offset)) != 0

        return False

    def mark_seen(self, nonce_counter: int) -> None:
        """Mark a nonce as seen after successful verification.

        Should only be called AFTER AEAD verification succeeds.

        Args:
            nonce_counter: The nonce counter to mark as seen.
        """
        if nonce_counter > self.highest_seen:
            # Shift window
            shift = nonce_counter - self.highest_seen
            if shift >= self.window_size:
                self.bitmap = 0
            else:
                self.bitmap <<= shift
            self.highest_seen = nonce_counter
            self.bitmap |= 1  # Mark current position
        else:
            # Within window - set bit
            offset = self.highest_seen - nonce_counter
            if offset < self.window_size:
                self.bitmap |= 1 << offset


# =============================================================================
# Frame Processor with Replay Protection
# =============================================================================


@dataclass
class SecureFrameProcessor:
    """Frame processor with proper replay protection ordering.

    Per spec: Replay check MUST occur BEFORE AEAD verification.
    This prevents CPU exhaustion attacks via replayed packets.
    """

    window: ReplayWindow = field(default_factory=ReplayWindow)
    key: bytes = field(default_factory=lambda: b"\x00" * 32)
    epoch: int = 0
    direction: int = 0

    # Counters for testing
    replay_rejections: int = 0
    aead_failures: int = 0
    successful_frames: int = 0

    def process_frame(self, nonce_counter: int, ciphertext: bytes, aad: bytes) -> bool:
        """Process a frame with proper security checks.

        Order per spec:
        1. Replay check FIRST (cheap)
        2. AEAD verification (expensive)
        3. Update replay window only after success

        Returns:
            True if frame was accepted, False if rejected.
        """
        from cryptography.exceptions import InvalidTag

        from lib.reference import xchacha20_poly1305_decrypt

        # 1. Replay check FIRST (cheap, prevents DoS)
        if self.window.is_replay(nonce_counter):
            self.replay_rejections += 1
            return False

        # 2. AEAD verification (expensive)
        nonce = construct_nonce(self.epoch, self.direction, nonce_counter)
        try:
            xchacha20_poly1305_decrypt(self.key, nonce, ciphertext, aad)
        except InvalidTag:
            self.aead_failures += 1
            return False

        # 3. Update replay window only after successful verification
        self.window.mark_seen(nonce_counter)
        self.successful_frames += 1
        return True


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def replay_window() -> ReplayWindow:
    """Fresh replay window."""
    return ReplayWindow()


@pytest.fixture
def processor() -> SecureFrameProcessor:
    """Secure frame processor with test key."""
    key = deterministic_bytes("test-key", 32)
    return SecureFrameProcessor(key=key)


@pytest.fixture
def codec() -> NomadCodec:
    """NomadCodec instance."""
    return NomadCodec()


# =============================================================================
# Replay Window Tests
# =============================================================================


class TestReplayWindow:
    """Test sliding window replay protection."""

    def test_first_nonce_accepted(self, replay_window: ReplayWindow) -> None:
        """First nonce is always accepted."""
        assert not replay_window.is_replay(0)

    def test_sequential_nonces_accepted(self, replay_window: ReplayWindow) -> None:
        """Sequential nonces are all accepted."""
        for i in range(100):
            assert not replay_window.is_replay(i)
            replay_window.mark_seen(i)

    def test_duplicate_nonce_rejected(self, replay_window: ReplayWindow) -> None:
        """Duplicate nonce is rejected."""
        replay_window.mark_seen(5)
        assert replay_window.is_replay(5)

    def test_old_nonce_within_window_rejected(self, replay_window: ReplayWindow) -> None:
        """Old nonce within window is rejected if seen."""
        # Mark nonces 0-100
        for i in range(100):
            replay_window.mark_seen(i)

        # Replay of nonce 50 should be rejected
        assert replay_window.is_replay(50)

    def test_old_nonce_within_window_accepted_if_unseen(
        self, replay_window: ReplayWindow
    ) -> None:
        """Old nonce within window is accepted if not seen (out-of-order delivery)."""
        # Mark only even nonces
        for i in range(0, 100, 2):
            replay_window.mark_seen(i)

        # Odd nonces should be accepted (not seen yet)
        for i in range(1, 100, 2):
            assert not replay_window.is_replay(i)

    def test_nonce_below_window_rejected(self, replay_window: ReplayWindow) -> None:
        """Nonce below window is always rejected."""
        # Advance window past position 0
        for i in range(REPLAY_WINDOW_SIZE + 100):
            replay_window.mark_seen(i)

        # Nonce 0 is now below window
        assert replay_window.is_replay(0)

    def test_nonce_above_window_accepted(self, replay_window: ReplayWindow) -> None:
        """Nonce above current window is accepted."""
        replay_window.mark_seen(100)

        # Much higher nonce should be accepted
        assert not replay_window.is_replay(10000)

    def test_window_shifts_correctly(self, replay_window: ReplayWindow) -> None:
        """Window shifts when new high nonce is marked."""
        replay_window.mark_seen(100)
        replay_window.mark_seen(200)

        assert replay_window.highest_seen == 200

        # Old nonces should still be tracked within window
        assert replay_window.is_replay(100)  # 200 - 100 = 100 < 2048

    def test_window_size_minimum(self) -> None:
        """Window size is at least 2048 bits."""
        window = ReplayWindow()
        assert window.window_size >= 2048


class TestReplayWindowEdgeCases:
    """Edge case tests for replay window."""

    def test_max_nonce_counter(self, replay_window: ReplayWindow) -> None:
        """Maximum nonce counter is handled correctly."""
        max_counter = MAX_NONCE_COUNTER
        assert not replay_window.is_replay(max_counter)
        replay_window.mark_seen(max_counter)
        assert replay_window.is_replay(max_counter)

    def test_large_gap_in_sequence(self, replay_window: ReplayWindow) -> None:
        """Large gap in sequence clears old bitmap."""
        # Mark some nonces
        for i in range(10):
            replay_window.mark_seen(i)

        # Jump way ahead - beyond window
        big_gap = REPLAY_WINDOW_SIZE + 100
        replay_window.mark_seen(big_gap)

        # Old nonces should be below window now
        assert replay_window.is_replay(0)

    def test_out_of_order_delivery(self, replay_window: ReplayWindow) -> None:
        """Out-of-order delivery is handled correctly."""
        # Receive nonces out of order: 3, 1, 2, 0
        replay_window.mark_seen(3)
        assert not replay_window.is_replay(1)
        replay_window.mark_seen(1)
        assert not replay_window.is_replay(2)
        replay_window.mark_seen(2)
        assert not replay_window.is_replay(0)
        replay_window.mark_seen(0)

        # All should now be marked as replays
        for i in range(4):
            assert replay_window.is_replay(i)


# =============================================================================
# Replay Check Ordering Tests
# =============================================================================


class TestReplayCheckOrdering:
    """Test that replay check occurs before AEAD verification."""

    def test_replay_rejection_before_aead(self, processor: SecureFrameProcessor) -> None:
        """Replayed frame is rejected without AEAD computation."""
        # Create valid frame
        nonce = construct_nonce(processor.epoch, processor.direction, 0)
        plaintext = b"test message"
        aad = b"\x03\x00" + b"\x00" * 14  # Data frame header
        ciphertext = xchacha20_poly1305_encrypt(processor.key, nonce, plaintext, aad)

        # First frame succeeds
        assert processor.process_frame(0, ciphertext, aad)
        assert processor.successful_frames == 1
        assert processor.aead_failures == 0

        # Replay is rejected WITHOUT AEAD computation
        initial_aead_failures = processor.aead_failures
        assert not processor.process_frame(0, ciphertext, aad)
        assert processor.replay_rejections == 1
        assert processor.aead_failures == initial_aead_failures  # No new AEAD computation

    def test_invalid_aead_counted_separately(self, processor: SecureFrameProcessor) -> None:
        """Invalid AEAD is counted separately from replay rejections."""
        # Send frame with invalid ciphertext
        invalid_ciphertext = b"\x00" * 32  # Wrong ciphertext
        aad = b"\x03\x00" + b"\x00" * 14

        # Should fail AEAD verification (not replay check)
        assert not processor.process_frame(0, invalid_ciphertext, aad)
        assert processor.aead_failures == 1
        assert processor.replay_rejections == 0

    def test_replay_check_is_cheap(self, processor: SecureFrameProcessor) -> None:
        """Replay check should be fast (no crypto operations)."""
        import time

        # Warm up window
        processor.window.mark_seen(100)

        # Time replay check (should be very fast)
        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            processor.window.is_replay(50)
        elapsed = time.perf_counter() - start

        # Should complete in < 100ms for 10k iterations
        assert elapsed < 0.1, f"Replay check too slow: {elapsed}s for {iterations} iterations"


# =============================================================================
# Nonce Reuse Detection Tests
# =============================================================================


class TestNonceReuseDetection:
    """Test detection of nonce reuse attempts."""

    def test_same_nonce_different_message_detected(
        self, processor: SecureFrameProcessor
    ) -> None:
        """Same nonce with different message is detected as replay."""
        nonce_counter = 42
        nonce = construct_nonce(processor.epoch, processor.direction, nonce_counter)
        aad = b"\x03\x00" + b"\x00" * 14

        # First message
        msg1 = xchacha20_poly1305_encrypt(processor.key, nonce, b"message one", aad)
        assert processor.process_frame(nonce_counter, msg1, aad)

        # Different message, same nonce - should be rejected
        msg2 = xchacha20_poly1305_encrypt(processor.key, nonce, b"message two", aad)
        assert not processor.process_frame(nonce_counter, msg2, aad)
        assert processor.replay_rejections == 1

    def test_nonce_uniqueness_per_direction(self, replay_window: ReplayWindow) -> None:
        """Nonces are unique per direction (separate windows in real impl)."""
        # In real implementation, each direction has its own replay window
        # This test documents the behavior
        initiator_window = ReplayWindow()
        responder_window = ReplayWindow()

        # Same counter value in different directions
        initiator_window.mark_seen(100)
        assert not responder_window.is_replay(100)  # Different window

    def test_nonce_uniqueness_per_epoch(self, replay_window: ReplayWindow) -> None:
        """Nonces are unique per epoch (windows reset on rekey)."""
        # Mark nonce in epoch 0
        replay_window.mark_seen(100)

        # After rekey (new window for new epoch), same counter is valid
        new_epoch_window = ReplayWindow()
        assert not new_epoch_window.is_replay(100)


# =============================================================================
# Epoch Protection Tests
# =============================================================================


class TestEpochProtection:
    """Test epoch number protection."""

    def test_epoch_in_nonce_prevents_cross_epoch_replay(self) -> None:
        """Different epochs produce different nonces, preventing replay."""
        nonce_epoch_0 = construct_nonce(epoch=0, direction=0, counter=100)
        nonce_epoch_1 = construct_nonce(epoch=1, direction=0, counter=100)

        assert nonce_epoch_0 != nonce_epoch_1


# =============================================================================
# DoS Resistance Tests
# =============================================================================


class TestDoSResistance:
    """Test resistance to denial-of-service via replay flood."""

    def test_replay_flood_no_crypto(self, processor: SecureFrameProcessor) -> None:
        """Replay flood doesn't cause expensive crypto operations."""
        # First, establish a valid nonce
        nonce = construct_nonce(processor.epoch, processor.direction, 0)
        aad = b"\x03\x00" + b"\x00" * 14
        ciphertext = xchacha20_poly1305_encrypt(processor.key, nonce, b"test", aad)
        processor.process_frame(0, ciphertext, aad)

        # Now flood with replays
        initial_aead = processor.aead_failures
        for _ in range(1000):
            processor.process_frame(0, ciphertext, aad)

        # Should all be rejected at replay check, no new AEAD operations
        assert processor.replay_rejections == 1000
        assert processor.aead_failures == initial_aead

    def test_random_nonce_flood(self, processor: SecureFrameProcessor) -> None:
        """Random invalid nonces cause replay checks, not AEAD."""

        # Flood with random (likely invalid) frames
        aad = b"\x03\x00" + b"\x00" * 14
        random_ciphertext = b"\x00" * 32

        # Mark some nonces as seen first
        for i in range(100):
            processor.window.mark_seen(i)

        # Try replaying those nonces
        for i in range(100):
            processor.process_frame(i, random_ciphertext, aad)

        # All should be caught at replay check
        assert processor.replay_rejections == 100


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestReplayWindowProperties:
    """Property-based tests for replay window."""

    @given(nonces=st.lists(st.integers(min_value=0, max_value=10000), min_size=1, max_size=100))
    @settings(max_examples=50)
    def test_marked_nonces_are_replays(self, nonces: list[int]) -> None:
        """Any nonce that was marked is detected as replay (within window)."""
        window = ReplayWindow()

        for nonce in nonces:
            window.mark_seen(nonce)

        # Check nonces still within window
        for nonce in nonces:
            if nonce > window.highest_seen - window.window_size:
                assert window.is_replay(nonce)

    @given(
        first=st.integers(min_value=0, max_value=10000),
        second=st.integers(min_value=0, max_value=10000),
    )
    @settings(max_examples=100)
    def test_unseen_nonces_not_replays(self, first: int, second: int) -> None:
        """Unseen nonces are not detected as replays (if within window)."""
        window = ReplayWindow()

        if first != second:
            window.mark_seen(first)
            # Second nonce not seen yet
            if second > window.highest_seen - window.window_size:
                assert not window.is_replay(second)

    @given(nonce=st.integers(min_value=0, max_value=MAX_NONCE_COUNTER))
    @settings(max_examples=50)
    def test_any_nonce_can_be_marked(self, nonce: int) -> None:
        """Any valid nonce counter can be marked without error."""
        window = ReplayWindow()
        window.mark_seen(nonce)
        assert window.is_replay(nonce)
