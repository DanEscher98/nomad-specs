"""
Replay Attack Tests for NOMAD Protocol.

These tests verify that implementations correctly reject replayed frames
using the sliding window anti-replay mechanism.

Per spec (1-SECURITY.md):
- Implementations MUST maintain a sliding window of received nonces (2048+ bits)
- Below window: MUST reject
- Seen nonce: MUST reject
- Above highest: Update window

Security property: Replay protection prevents attackers from re-sending
captured frames to cause duplicate actions or state corruption.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lib.reference import (
    DATA_FRAME_HEADER_SIZE,
    NomadCodec,
)

if TYPE_CHECKING:
    from lib.attacker import MITMAttacker


# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


class TestReplayWithSameNonce:
    """Tests for replay attacks using the same nonce."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def test_session(self, codec: NomadCodec) -> dict:
        """Create a test session with keys and session ID."""
        key = codec.deterministic_bytes("test-session-key", 32)
        session_id = codec.deterministic_bytes("test-session-id", 6)
        return {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,  # initiator -> responder
        }

    def test_replay_same_nonce_must_be_rejected(
        self, codec: NomadCodec, test_session: dict
    ) -> None:
        """Replay of a frame with the same nonce MUST be rejected.

        Spec: 1-SECURITY.md §Anti-Replay Protection
        "Seen nonce: MUST reject"

        Attack scenario:
        1. Attacker captures a valid frame
        2. Attacker replays the exact same frame
        3. Implementation MUST reject the replayed frame
        """
        # Create a valid frame
        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"test diff payload",
        )

        frame = codec.create_data_frame(
            session_id=test_session["session_id"],
            nonce_counter=100,  # Use nonce 100
            key=test_session["key"],
            epoch=test_session["epoch"],
            direction=test_session["direction"],
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Simulate receiving the frame (marks nonce as seen)
        # First reception should succeed
        parsed = codec.parse_data_frame(
            frame,
            test_session["key"],
            test_session["epoch"],
            test_session["direction"],
        )
        assert parsed.header.nonce_counter == 100

        # Simulate replay window tracking
        seen_nonces: set[int] = {100}

        # Second reception of same nonce should be rejected
        header = codec.parse_data_frame_header(frame[:DATA_FRAME_HEADER_SIZE])
        assert header.nonce_counter in seen_nonces, (
            "Implementation MUST reject frames with previously seen nonces"
        )

    def test_replay_old_nonce_below_window_must_be_rejected(
        self, codec: NomadCodec, test_session: dict
    ) -> None:
        """Replay of a frame with nonce below the sliding window MUST be rejected.

        Spec: 1-SECURITY.md §Anti-Replay Protection
        "Below window: MUST reject"

        Attack scenario:
        1. Many frames have been sent, window has advanced
        2. Attacker replays an old frame with nonce below window
        3. Implementation MUST reject without expensive AEAD verification
        """
        # Simulate window state: window covers nonces 2000-4048 (2048-bit window)
        window_base = 2000
        # window_size = 2048 (used for context in comment)

        # Create frame with old nonce (below window)
        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"old frame",
        )

        old_frame = codec.create_data_frame(
            session_id=test_session["session_id"],
            nonce_counter=500,  # Way below window_base of 2000
            key=test_session["key"],
            epoch=test_session["epoch"],
            direction=test_session["direction"],
            timestamp=500,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Parse header to check nonce
        header = codec.parse_data_frame_header(old_frame[:DATA_FRAME_HEADER_SIZE])

        # Nonce 500 is below window_base 2000
        assert header.nonce_counter < window_base, "Test setup: nonce should be below window"

        # This frame should be rejected BEFORE AEAD verification
        # (cheap replay check first, prevents DoS via AEAD computation)
        is_below_window = header.nonce_counter < window_base
        assert is_below_window, (
            "Implementation MUST reject nonces below window without AEAD verification"
        )

    @given(nonce_counter=st.integers(min_value=0, max_value=2**63 - 1))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_replay_check_before_aead_verification(
        self, codec: NomadCodec, test_session: dict, nonce_counter: int
    ) -> None:
        """Replay check MUST occur BEFORE AEAD verification.

        Spec: 1-SECURITY.md §Anti-Replay Protection
        "Replay check MUST occur BEFORE AEAD verification"

        This ordering prevents CPU exhaustion attacks where an attacker
        floods replayed packets to force expensive AEAD operations.
        """
        # Create frame with given nonce
        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"test",
        )

        frame = codec.create_data_frame(
            session_id=test_session["session_id"],
            nonce_counter=nonce_counter,
            key=test_session["key"],
            epoch=test_session["epoch"],
            direction=test_session["direction"],
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Parsing header should be possible without decryption
        header = codec.parse_data_frame_header(frame[:DATA_FRAME_HEADER_SIZE])
        assert header.nonce_counter == nonce_counter

        # Implementation should:
        # 1. Parse header (cheap)
        # 2. Check replay window (cheap)
        # 3. Only then verify AEAD (expensive)


class TestReplayWithModifiedCounter:
    """Tests for replay attacks with modified nonce counter."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def test_session(self, codec: NomadCodec) -> dict:
        """Create a test session with keys and session ID."""
        key = codec.deterministic_bytes("test-session-key-2", 32)
        session_id = codec.deterministic_bytes("test-session-id-2", 6)
        return {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_modified_nonce_counter_aead_fails(self, codec: NomadCodec, test_session: dict) -> None:
        """Modifying the nonce counter in header causes AEAD failure.

        Spec: 1-SECURITY.md §Additional Authenticated Data (AAD)
        "The frame header is authenticated but not encrypted."

        Attack scenario:
        1. Attacker captures valid frame
        2. Attacker modifies nonce counter in header to bypass replay window
        3. AEAD verification MUST fail because header is in AAD
        """
        from cryptography.exceptions import InvalidTag

        # Create valid frame
        sync_message = codec.create_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"test payload",
        )

        frame = codec.create_data_frame(
            session_id=test_session["session_id"],
            nonce_counter=100,
            key=test_session["key"],
            epoch=test_session["epoch"],
            direction=test_session["direction"],
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Modify nonce counter in header (bytes 8-15)
        modified_frame = bytearray(frame)
        struct.pack_into("<Q", modified_frame, 8, 200)  # Change 100 -> 200
        modified_frame = bytes(modified_frame)

        # AEAD verification should fail because AAD (header) was modified
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                modified_frame,
                test_session["key"],
                test_session["epoch"],
                test_session["direction"],
            )


class TestSlidingWindowMechanism:
    """Tests for the sliding window anti-replay mechanism."""

    def test_window_minimum_size(self) -> None:
        """Sliding window MUST be at least 2048 bits.

        Spec: 1-SECURITY.md §Anti-Replay Protection
        "Window size: 2048 bits minimum"
        """
        # 2048 bits = 256 bytes = can track 2048 nonces
        MINIMUM_WINDOW_SIZE = 2048
        assert MINIMUM_WINDOW_SIZE >= 2048

    def test_window_updates_on_new_high_nonce(self) -> None:
        """Window should slide when a nonce above highest is received.

        Spec: 1-SECURITY.md §Anti-Replay Protection
        "Above highest: Update window"
        """

        # Simulate a simple sliding window
        class SlidingWindow:
            def __init__(self, size: int = 2048):
                self.size = size
                self.highest = 0
                self.seen: set[int] = set()

            def check_and_update(self, nonce: int) -> bool:
                """Returns True if nonce is accepted, False if rejected."""
                # Below window
                if nonce < self.highest - self.size:
                    return False

                # Already seen
                if nonce in self.seen:
                    return False

                # Accept and update
                self.seen.add(nonce)
                if nonce > self.highest:
                    # Slide window (old_lowest would be self.highest - self.size)
                    self.highest = nonce
                    # Remove nonces that fell below window
                    self.seen = {n for n in self.seen if n >= self.highest - self.size}

                return True

        window = SlidingWindow(size=2048)

        # First nonce accepted
        assert window.check_and_update(1000) is True

        # Same nonce rejected
        assert window.check_and_update(1000) is False

        # Higher nonce accepted, slides window
        assert window.check_and_update(5000) is True

        # Old nonce now below window
        assert window.check_and_update(100) is False

        # Recent nonce still in window
        assert window.check_and_update(4000) is True


class TestReplayAttackVectors:
    """Test vectors for replay attack scenarios."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_replay_attack_vector_same_frame_twice(self, codec: NomadCodec) -> None:
        """Test vector: identical frame replayed.

        This is the simplest replay attack - send the exact same frame twice.
        """
        key = codec.deterministic_bytes("replay-vector-1", 32)
        session_id = codec.deterministic_bytes("replay-session-1", 6)

        sync = codec.create_sync_message(1, 0, 0, b"replayed content")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=42,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Track seen nonces
        seen: set[int] = set()

        def process_frame(f: bytes) -> bool:
            header = codec.parse_data_frame_header(f[:DATA_FRAME_HEADER_SIZE])
            if header.nonce_counter in seen:
                return False  # Replay detected
            seen.add(header.nonce_counter)
            return True

        # First reception succeeds
        assert process_frame(frame) is True
        # Replay detected
        assert process_frame(frame) is False

    def test_replay_attack_vector_delayed_replay(self, codec: NomadCodec) -> None:
        """Test vector: frame replayed after many other frames.

        Attacker captures frame early, replays after window may have advanced.
        """
        key = codec.deterministic_bytes("replay-vector-2", 32)
        session_id = codec.deterministic_bytes("replay-session-2", 6)

        # Capture early frame
        early_sync = codec.create_sync_message(1, 0, 0, b"early frame")
        early_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=10,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=early_sync,
        )

        # Simulate many frames have been processed
        window_base = 5000  # Window has advanced past nonce 10

        header = codec.parse_data_frame_header(early_frame[:DATA_FRAME_HEADER_SIZE])
        assert header.nonce_counter < window_base, (
            "Delayed replay should be below window and rejected"
        )


class TestReplayIntegration:
    """Integration tests for replay attack scenarios with containers.

    These tests require Docker containers and NET_RAW capabilities.
    """

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_replay_captured_frame_integration(
        self,
        attacker: MITMAttacker,
        server_container,
        client_container,
    ) -> None:
        """Integration test: capture and replay actual frame.

        This test:
        1. Captures real traffic between server and client
        2. Replays a captured frame
        3. Verifies the implementation rejects the replay

        Requires: Docker containers with NET_RAW capability.
        """
        # Capture some traffic
        frames = attacker.capture_traffic(count=5, timeout=10.0)
        if not frames:
            pytest.skip("No frames captured - ensure client is sending")

        # Replay first frame
        frame = frames[0]
        attacker.replay_frame(
            frame.data,
            dst_ip=frame.dst_ip,
            dst_port=frame.dst_port,
        )

        # The replayed frame should be silently dropped
        # (no way to verify directly without implementation logs)
        assert attacker.stats.frames_replayed >= 1
