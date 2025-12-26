"""
Nonce Reuse Tests for NOMAD Protocol.

These tests verify that implementations prevent catastrophic nonce reuse
in AEAD encryption.

Per spec (1-SECURITY.md §Counter Exhaustion):
- CRITICAL: Nonce reuse with the same key is catastrophic for AEAD security
- Implementations MUST enforce hard limits
- Counter never wraps (terminates at limit)
- Session MUST be terminated if counter reaches 2^64 - 1

Security property: Nonce uniqueness ensures each encryption uses a unique
key/nonce pair, preventing XOR attacks on ciphertext.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_NONCE_SIZE,
    NomadCodec,
)

# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


# Protocol constants
MAX_NONCE_COUNTER = 2**64 - 1


@dataclass
class NonceTracker:
    """Tracks nonce usage to prevent reuse.

    This simulates the nonce tracking a proper implementation must do.
    """

    # Current send nonce counter
    send_nonce: int = 0

    # Highest received nonce
    recv_nonce_highest: int = 0

    # Seen nonces (for replay window)
    seen_nonces: set[int] = None

    # Current epoch
    epoch: int = 0

    def __post_init__(self) -> None:
        if self.seen_nonces is None:
            self.seen_nonces = set()

    def get_next_send_nonce(self) -> int:
        """Get next nonce for sending, incrementing counter.

        Raises:
            RuntimeError: If counter would exceed limit.
        """
        if self.send_nonce >= MAX_NONCE_COUNTER:
            raise RuntimeError("Nonce counter exhausted - MUST terminate session")

        nonce = self.send_nonce
        self.send_nonce += 1
        return nonce

    def check_recv_nonce(self, nonce: int) -> bool:
        """Check if received nonce is valid (not seen before).

        Returns:
            True if nonce is valid and not a replay.
        """
        if nonce in self.seen_nonces:
            return False  # Replay

        # Below window - reject
        return nonce >= self.recv_nonce_highest - 2048

    def mark_nonce_seen(self, nonce: int) -> None:
        """Mark a nonce as seen after successful verification."""
        self.seen_nonces.add(nonce)
        if nonce > self.recv_nonce_highest:
            self.recv_nonce_highest = nonce
            # Trim old nonces from seen set
            min_nonce = self.recv_nonce_highest - 2048
            self.seen_nonces = {n for n in self.seen_nonces if n >= min_nonce}


class TestNonceMonotonicity:
    """Tests for monotonically increasing nonces."""

    def test_send_nonce_always_increments(self) -> None:
        """Send nonce MUST always increment (never repeat).

        Spec: 1-SECURITY.md §Nonce Construction
        "Counter: Monotonically increasing frame counter, starts at 0"
        """
        tracker = NonceTracker()

        # Get sequence of nonces
        nonces = [tracker.get_next_send_nonce() for _ in range(100)]

        # Must be strictly increasing
        for i in range(1, len(nonces)):
            assert nonces[i] > nonces[i - 1], (
                f"Nonce must strictly increase: {nonces[i - 1]} -> {nonces[i]}"
            )

        # Must be consecutive (0, 1, 2, ...)
        assert nonces == list(range(100))

    def test_send_nonce_starts_at_zero(self) -> None:
        """Send nonce MUST start at 0."""
        tracker = NonceTracker()
        first_nonce = tracker.get_next_send_nonce()
        assert first_nonce == 0

    def test_send_nonce_never_repeats(self) -> None:
        """Same nonce MUST never be used twice for encryption.

        This is the fundamental AEAD security requirement.
        """
        tracker = NonceTracker()

        used_nonces: set[int] = set()

        for _ in range(10000):
            nonce = tracker.get_next_send_nonce()
            assert nonce not in used_nonces, f"Nonce {nonce} was reused - CRITICAL VULNERABILITY"
            used_nonces.add(nonce)

    @given(initial=st.integers(min_value=0, max_value=2**62))
    @settings(max_examples=20)
    def test_nonce_always_advances(self, initial: int) -> None:
        """Nonce must always advance, regardless of starting point."""
        tracker = NonceTracker()
        tracker.send_nonce = initial

        prev = tracker.get_next_send_nonce()
        for _ in range(10):
            curr = tracker.get_next_send_nonce()
            assert curr > prev
            prev = curr


class TestNonceNoWrap:
    """Tests for nonce counter no-wrap behavior."""

    def test_counter_does_not_wrap_at_max(self) -> None:
        """Counter MUST NOT wrap at 2^64 - 1.

        Spec: 1-SECURITY.md §Counter Exhaustion
        "If counter reaches 2^64 - 1, the session MUST be terminated
         immediately. Do NOT wrap the counter."
        """
        tracker = NonceTracker()

        # Set counter just below max
        tracker.send_nonce = MAX_NONCE_COUNTER

        # Attempting to get next nonce must fail
        with pytest.raises(RuntimeError, match="exhausted"):
            tracker.get_next_send_nonce()

    def test_counter_approaching_max_still_works(self) -> None:
        """Counter should work up to the limit."""
        tracker = NonceTracker()

        # Set counter near max
        tracker.send_nonce = MAX_NONCE_COUNTER - 5

        # Can still get a few nonces
        for expected in range(MAX_NONCE_COUNTER - 5, MAX_NONCE_COUNTER):
            nonce = tracker.get_next_send_nonce()
            assert nonce == expected

        # Now at max, next must fail
        assert tracker.send_nonce == MAX_NONCE_COUNTER
        with pytest.raises(RuntimeError):
            tracker.get_next_send_nonce()

    def test_nonce_wrap_would_be_catastrophic(self) -> None:
        """Demonstrate why wrap would be catastrophic.

        If nonce wrapped from 2^64-1 to 0, we'd reuse nonces,
        allowing XOR of plaintexts.
        """
        # This test is informational - showing the attack
        key = b"k" * 32
        nonce = b"n" * 24

        codec = NomadCodec()

        # Two messages encrypted with same key/nonce
        msg1 = b"secret message one"
        msg2 = b"another secret two"

        ct1 = codec.encrypt(key, nonce, msg1, b"aad")
        ct2 = codec.encrypt(key, nonce, msg2, b"aad")

        # XOR of ciphertexts reveals XOR of plaintexts
        # (This is the catastrophic failure mode)
        ct1_bytes = ct1[:-16]  # Remove tag
        ct2_bytes = ct2[:-16]

        min_len = min(len(ct1_bytes), len(ct2_bytes))
        xor_cts = bytes(
            a ^ b for a, b in zip(ct1_bytes[:min_len], ct2_bytes[:min_len], strict=True)
        )

        # XOR of plaintexts
        xor_pts = bytes(a ^ b for a, b in zip(msg1[:min_len], msg2[:min_len], strict=True))

        # They match! This leaks information about both plaintexts
        assert xor_cts == xor_pts, (
            "XOR of ciphertexts equals XOR of plaintexts when nonce is reused"
        )


class TestNonceConstruction:
    """Tests for proper nonce construction."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_nonce_structure(self, codec: NomadCodec) -> None:
        """Verify nonce has correct structure.

        Spec: 1-SECURITY.md §Nonce Construction
        - Bytes 0-3: Epoch (LE32)
        - Byte 4: Direction
        - Bytes 5-15: Zeros
        - Bytes 16-23: Counter (LE64)
        """
        nonce = codec.construct_nonce(epoch=1, direction=0, counter=42)

        assert len(nonce) == AEAD_NONCE_SIZE  # 24 bytes

        # Parse components
        epoch = struct.unpack_from("<I", nonce, 0)[0]
        direction = nonce[4]
        zeros = nonce[5:16]
        counter = struct.unpack_from("<Q", nonce, 16)[0]

        assert epoch == 1
        assert direction == 0
        assert zeros == b"\x00" * 11
        assert counter == 42

    def test_different_directions_different_nonces(self, codec: NomadCodec) -> None:
        """Different directions produce different nonces.

        This allows same counter value in both directions without collision.
        """
        nonce_i2r = codec.construct_nonce(epoch=0, direction=0, counter=100)
        nonce_r2i = codec.construct_nonce(epoch=0, direction=1, counter=100)

        assert nonce_i2r != nonce_r2i

    def test_different_epochs_different_nonces(self, codec: NomadCodec) -> None:
        """Different epochs produce different nonces.

        After rekey, epoch increments, resetting counter is safe.
        """
        nonce_e0 = codec.construct_nonce(epoch=0, direction=0, counter=0)
        nonce_e1 = codec.construct_nonce(epoch=1, direction=0, counter=0)

        assert nonce_e0 != nonce_e1

    @given(
        epoch=st.integers(min_value=0, max_value=2**32 - 1),
        direction=st.integers(min_value=0, max_value=1),
        counter=st.integers(min_value=0, max_value=2**64 - 1),
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_nonce_uniqueness(
        self, codec: NomadCodec, epoch: int, direction: int, counter: int
    ) -> None:
        """Each (epoch, direction, counter) tuple produces unique nonce."""
        nonce = codec.construct_nonce(epoch, direction, counter)
        parsed = codec.parse_nonce(nonce)

        assert parsed.epoch == epoch
        assert parsed.direction == direction
        assert parsed.counter == counter


class TestNonceReuseDetection:
    """Tests for detecting nonce reuse attempts."""

    def test_replay_detection_catches_reuse(self) -> None:
        """Replay detection catches nonce reuse on receive side."""
        tracker = NonceTracker()

        # Receive nonce 100
        assert tracker.check_recv_nonce(100) is True
        tracker.mark_nonce_seen(100)

        # Same nonce again should be rejected
        assert tracker.check_recv_nonce(100) is False

    def test_nonce_below_window_rejected(self) -> None:
        """Nonces below sliding window are rejected."""
        tracker = NonceTracker()

        # Advance window by receiving high nonce
        tracker.recv_nonce_highest = 5000
        tracker.seen_nonces = set(range(4900, 5001))

        # Old nonce (below window) rejected
        assert tracker.check_recv_nonce(1000) is False

    @given(nonces=st.lists(st.integers(min_value=0, max_value=10000), min_size=10, max_size=100))
    @settings(max_examples=20)
    def test_no_nonce_accepted_twice(self, nonces: list[int]) -> None:
        """No nonce should ever be accepted twice."""
        tracker = NonceTracker()
        accepted: set[int] = set()

        for nonce in nonces:
            if tracker.check_recv_nonce(nonce):
                assert nonce not in accepted
                accepted.add(nonce)
                tracker.mark_nonce_seen(nonce)
            else:
                # Either replay or below window - both valid rejections
                pass


class TestEpochBehavior:
    """Tests for epoch behavior during rekey."""

    def test_epoch_increments_on_rekey(self) -> None:
        """Epoch MUST increment on rekey.

        This allows resetting nonce counter safely.
        """
        tracker = NonceTracker()

        # Use some nonces
        for _ in range(100):
            tracker.get_next_send_nonce()

        # Simulate rekey
        tracker.epoch += 1
        tracker.send_nonce = 0  # Reset counter
        tracker.recv_nonce_highest = 0
        tracker.seen_nonces.clear()

        # Can use nonce 0 again (different epoch)
        first_after_rekey = tracker.get_next_send_nonce()
        assert first_after_rekey == 0

    def test_epoch_in_nonce_prevents_collision(self) -> None:
        """Epoch in nonce ensures uniqueness across rekeys."""
        codec = NomadCodec()

        # Same counter, different epochs
        nonce_e0 = codec.construct_nonce(epoch=0, direction=0, counter=0)
        nonce_e1 = codec.construct_nonce(epoch=1, direction=0, counter=0)
        nonce_e2 = codec.construct_nonce(epoch=2, direction=0, counter=0)

        # All unique
        assert len({nonce_e0, nonce_e1, nonce_e2}) == 3


class TestNonceReuseVectors:
    """Test vectors for nonce reuse scenarios."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_nonce_reuse_attack_vector(self, codec: NomadCodec) -> None:
        """Demonstrate nonce reuse attack.

        This test shows what an attacker could learn if nonces were reused.
        """
        key = codec.deterministic_bytes("nonce-reuse-key", 32)
        session_id = codec.deterministic_bytes("nonce-reuse-session", 6)

        # Two different messages
        msg1 = b"password: hunter2"
        msg2 = b"credit card: 1234"

        sync1 = codec.create_sync_message(1, 0, 0, msg1)
        sync2 = codec.create_sync_message(2, 0, 0, msg2)

        # If implementation INCORRECTLY reused nonce...
        # (This should NEVER happen in correct implementation)
        SAME_NONCE = 42  # Bug: using same nonce

        frame1 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=SAME_NONCE,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync1,
        )

        frame2 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=SAME_NONCE,  # WRONG! Same nonce!
            key=key,
            epoch=0,
            direction=0,
            timestamp=2000,
            timestamp_echo=1000,
            sync_message=sync2,
        )

        # XOR reveals relationship between plaintexts
        # Attacker can now perform cryptanalysis on:
        #   ciphertext1[16:-16] XOR ciphertext2[16:-16]
        # This test documents the vulnerability

        # Verify frames were created (demonstrates the scenario)
        assert len(frame1) > 32
        assert len(frame2) > 32

        # Proper implementation prevents this by NEVER reusing nonces
        # The NonceTracker class enforces this


class TestNonceReuseIntegration:
    """Integration tests for nonce reuse prevention."""

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_capture_and_verify_unique_nonces(
        self,
        attacker,
        server_container,
        client_container,
    ) -> None:
        """Integration test: verify all captured frames have unique nonces.

        Captures traffic and verifies no nonce is ever reused.
        """
        # Capture many frames
        frames = attacker.capture_traffic(count=100, timeout=30.0)

        if len(frames) < 10:
            pytest.skip("Not enough frames captured")

        # Track nonces per (session_id, direction) pair
        nonces_seen: dict[tuple[bytes, str], set[int]] = {}

        for frame in frames:
            if len(frame.data) < 16:
                continue

            session_id = frame.data[2:8]
            nonce = struct.unpack_from("<Q", frame.data, 8)[0]

            # Determine direction from addresses
            direction = "c2s" if "172.31.0.20" in frame.src_ip else "s2c"
            key = (session_id, direction)

            if key not in nonces_seen:
                nonces_seen[key] = set()

            assert nonce not in nonces_seen[key], (
                f"Nonce {nonce} reused in session {session_id.hex()} {direction}"
            )
            nonces_seen[key].add(nonce)
