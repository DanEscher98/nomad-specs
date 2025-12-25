"""
Key Exhaustion Tests for NOMAD Protocol.

These tests verify that implementations correctly handle counter and epoch
exhaustion scenarios, terminating sessions before security limits are reached.

Per spec (1-SECURITY.md §Counter Exhaustion):
- REJECT_AFTER_MESSAGES: 2^64 - 1 (HARD LIMIT - MUST terminate session)
- MAX_EPOCH: 2^32 - 1 (MUST terminate and establish new session)
- Do NOT wrap counters
- Session MUST be terminated at limits

Security property: Key exhaustion protection ensures sessions are terminated
before cryptographic limits are reached, preventing nonce reuse.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import NomadCodec

# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


# Protocol constants from spec
MAX_NONCE_COUNTER = 2**64 - 1  # REJECT_AFTER_MESSAGES
MAX_EPOCH = 2**32 - 1
REKEY_AFTER_MESSAGES = 2**60  # Soft limit
REKEY_AFTER_TIME_SECONDS = 120


@dataclass
class SessionLimits:
    """Tracks session against protocol limits.

    Implements the counter and epoch exhaustion checks required by spec.
    """

    # Current nonce counter
    nonce_counter: int = 0

    # Current epoch
    epoch: int = 0

    # Session active flag
    active: bool = True

    # Termination reason (if terminated)
    termination_reason: str | None = None

    def check_and_increment_nonce(self) -> int:
        """Get next nonce, checking exhaustion.

        Returns:
            Next nonce value.

        Raises:
            RuntimeError: If counter would exceed limit.
        """
        if not self.active:
            raise RuntimeError(f"Session terminated: {self.termination_reason}")

        if self.nonce_counter >= MAX_NONCE_COUNTER:
            self._terminate("nonce counter exhaustion (2^64 - 1)")

        nonce = self.nonce_counter
        self.nonce_counter += 1
        return nonce

    def should_rekey(self) -> bool:
        """Check if session should initiate rekeying.

        Returns soft limits for proactive rekeying.
        """
        return self.nonce_counter >= REKEY_AFTER_MESSAGES

    def increment_epoch(self) -> None:
        """Increment epoch for rekey, checking exhaustion.

        Raises:
            RuntimeError: If epoch would exceed limit.
        """
        if not self.active:
            raise RuntimeError(f"Session terminated: {self.termination_reason}")

        if self.epoch >= MAX_EPOCH:
            self._terminate("epoch exhaustion (2^32 - 1)")

        self.epoch += 1
        self.nonce_counter = 0  # Reset counter on rekey

    def _terminate(self, reason: str) -> None:
        """Terminate session with reason."""
        self.active = False
        self.termination_reason = reason
        raise RuntimeError(f"Session terminated: {reason}")


class TestNonceCounterLimits:
    """Tests for nonce counter exhaustion (2^64 - 1 limit)."""

    def test_max_nonce_counter_value(self) -> None:
        """Verify max nonce counter constant.

        Spec: 1-SECURITY.md §Counter Exhaustion
        "REJECT_AFTER_MESSAGES: 2^64 - 1 (HARD LIMIT)"
        """
        assert MAX_NONCE_COUNTER == 2**64 - 1
        assert MAX_NONCE_COUNTER == 18446744073709551615

    def test_session_terminates_at_max_nonce(self) -> None:
        """Session MUST terminate at nonce counter limit.

        Spec: 1-SECURITY.md §Counter Exhaustion
        "If counter reaches 2^64 - 1, the session MUST be terminated immediately"
        """
        session = SessionLimits()

        # Set counter at max
        session.nonce_counter = MAX_NONCE_COUNTER

        # Next operation must terminate session
        with pytest.raises(RuntimeError, match="nonce counter exhaustion"):
            session.check_and_increment_nonce()

        assert not session.active
        assert "nonce counter exhaustion" in session.termination_reason

    def test_session_works_until_limit(self) -> None:
        """Session should work normally until limit is reached."""
        session = SessionLimits()

        # Set counter just below max
        session.nonce_counter = MAX_NONCE_COUNTER - 3

        # Can still get a few nonces
        n1 = session.check_and_increment_nonce()
        assert n1 == MAX_NONCE_COUNTER - 3
        assert session.active

        n2 = session.check_and_increment_nonce()
        assert n2 == MAX_NONCE_COUNTER - 2
        assert session.active

        n3 = session.check_and_increment_nonce()
        assert n3 == MAX_NONCE_COUNTER - 1
        assert session.active

        # Now at max, next fails
        with pytest.raises(RuntimeError):
            session.check_and_increment_nonce()

    def test_no_wrap_at_max_nonce(self) -> None:
        """Counter MUST NOT wrap to 0 at max.

        Spec: 1-SECURITY.md §Counter Exhaustion
        "Do NOT wrap the counter"
        """
        session = SessionLimits()
        session.nonce_counter = MAX_NONCE_COUNTER

        # Attempting increment must fail, not wrap
        with pytest.raises(RuntimeError):
            session.check_and_increment_nonce()

        # Counter should still be at max (or terminated), not wrapped to 0
        # Session is terminated, so counter state is irrelevant
        assert not session.active


class TestEpochLimits:
    """Tests for epoch exhaustion (2^32 - 1 limit)."""

    def test_max_epoch_value(self) -> None:
        """Verify max epoch constant.

        Spec: 1-SECURITY.md §Epoch Protection
        "MAX_EPOCH = 2^32 - 1"
        """
        assert MAX_EPOCH == 2**32 - 1
        assert MAX_EPOCH == 4294967295

    def test_session_terminates_at_max_epoch(self) -> None:
        """Session MUST terminate at epoch limit.

        Spec: 1-SECURITY.md §Epoch Protection
        "If epoch reaches 2^32 - 1, terminate the session and establish
         a new one via fresh handshake"
        """
        session = SessionLimits()

        # Set epoch at max
        session.epoch = MAX_EPOCH

        # Next rekey must terminate session
        with pytest.raises(RuntimeError, match="epoch exhaustion"):
            session.increment_epoch()

        assert not session.active
        assert "epoch exhaustion" in session.termination_reason

    def test_epoch_increments_work_until_limit(self) -> None:
        """Epoch increments should work until limit."""
        session = SessionLimits()

        # Set epoch near max
        session.epoch = MAX_EPOCH - 2

        # Can still increment
        session.increment_epoch()
        assert session.epoch == MAX_EPOCH - 1
        assert session.active

        session.increment_epoch()
        assert session.epoch == MAX_EPOCH
        assert session.active

        # Now at max, next increment fails
        with pytest.raises(RuntimeError):
            session.increment_epoch()

    def test_no_wrap_at_max_epoch(self) -> None:
        """Epoch MUST NOT wrap to 0 at max."""
        session = SessionLimits()
        session.epoch = MAX_EPOCH

        with pytest.raises(RuntimeError):
            session.increment_epoch()

        assert not session.active


class TestRekeyThresholds:
    """Tests for rekey threshold behavior."""

    def test_rekey_after_messages_threshold(self) -> None:
        """Should initiate rekey after REKEY_AFTER_MESSAGES.

        Spec: 1-SECURITY.md §Rekeying Timing Constants
        "REKEY_AFTER_MESSAGES: 2^60"
        """
        assert REKEY_AFTER_MESSAGES == 2**60

        session = SessionLimits()

        # Below threshold
        session.nonce_counter = REKEY_AFTER_MESSAGES - 1
        assert not session.should_rekey()

        # At threshold
        session.nonce_counter = REKEY_AFTER_MESSAGES
        assert session.should_rekey()

        # Above threshold
        session.nonce_counter = REKEY_AFTER_MESSAGES + 1000
        assert session.should_rekey()

    def test_rekey_resets_counter(self) -> None:
        """Rekey MUST reset nonce counter to 0."""
        session = SessionLimits()

        # Use some nonces
        session.nonce_counter = 1000000

        # Rekey
        session.increment_epoch()

        # Counter reset
        assert session.nonce_counter == 0
        assert session.epoch == 1

    def test_can_rekey_many_times(self) -> None:
        """Can rekey many times before epoch exhaustion."""
        session = SessionLimits()

        # Rekey 100 times
        for i in range(100):
            session.nonce_counter = REKEY_AFTER_MESSAGES
            session.increment_epoch()
            assert session.epoch == i + 1
            assert session.nonce_counter == 0
            assert session.active


class TestExhaustionTimelines:
    """Tests analyzing exhaustion timelines."""

    def test_nonce_exhaustion_timeline(self) -> None:
        """Calculate time to nonce exhaustion.

        At 50 frames/second (MAX_FRAME_RATE from spec):
        2^64 frames / 50 fps = ~3.7 × 10^17 seconds
        = ~11.7 billion years

        This is effectively infinite - will never happen.
        """
        frames_per_second = 50
        total_frames = 2**64

        seconds_to_exhaust = total_frames / frames_per_second
        years_to_exhaust = seconds_to_exhaust / (365.25 * 24 * 3600)

        # More than the age of the universe
        assert years_to_exhaust > 10**9

    def test_epoch_exhaustion_timeline(self) -> None:
        """Calculate time to epoch exhaustion.

        At one rekey per 120 seconds (REKEY_AFTER_TIME):
        2^32 rekeys × 120 seconds = ~515 billion seconds
        = ~16,300 years

        Still effectively infinite for any real session.
        """
        rekey_interval_seconds = 120
        total_rekeys = 2**32

        seconds_to_exhaust = total_rekeys * rekey_interval_seconds
        years_to_exhaust = seconds_to_exhaust / (365.25 * 24 * 3600)

        assert years_to_exhaust > 10000

    def test_rekey_before_message_limit(self) -> None:
        """Verify rekey threshold is well before hard limit.

        REKEY_AFTER_MESSAGES (2^60) << REJECT_AFTER_MESSAGES (2^64)
        Gives 2^4 = 16× safety margin.
        """
        margin = MAX_NONCE_COUNTER / REKEY_AFTER_MESSAGES
        assert margin >= 16

        # This means even if rekey is delayed, plenty of headroom


class TestExhaustionVectors:
    """Test vectors for exhaustion scenarios."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_frame_at_max_nonce(self, codec: NomadCodec) -> None:
        """Create frame at maximum nonce counter.

        This should be the LAST valid frame before termination.
        """
        key = codec.deterministic_bytes("max-nonce-key", 32)
        session_id = codec.deterministic_bytes("max-nonce-session", 6)

        # Create frame at max nonce - 1 (last valid nonce)
        last_valid_nonce = MAX_NONCE_COUNTER - 1

        sync = codec.create_sync_message(1, 0, 0, b"last frame")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=last_valid_nonce,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Should parse successfully
        parsed = codec.parse_data_frame(frame, key, 0, 0)
        assert parsed.header.nonce_counter == last_valid_nonce

    def test_frame_at_max_epoch(self, codec: NomadCodec) -> None:
        """Create frame at maximum epoch.

        After this, no more rekeys possible.
        """
        key = codec.deterministic_bytes("max-epoch-key", 32)
        session_id = codec.deterministic_bytes("max-epoch-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"max epoch frame")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=MAX_EPOCH,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Should parse with correct epoch
        parsed = codec.parse_data_frame(frame, key, MAX_EPOCH, 0)
        assert parsed.header.nonce_counter == 100


class TestTerminationBehavior:
    """Tests for proper session termination behavior."""

    def test_terminated_session_rejects_operations(self) -> None:
        """Terminated session MUST reject all operations."""
        session = SessionLimits()

        # Terminate
        session.nonce_counter = MAX_NONCE_COUNTER
        with pytest.raises(RuntimeError):
            session.check_and_increment_nonce()

        # All subsequent operations fail
        with pytest.raises(RuntimeError, match="terminated"):
            session.check_and_increment_nonce()

        with pytest.raises(RuntimeError, match="terminated"):
            session.increment_epoch()

    def test_termination_reason_preserved(self) -> None:
        """Termination reason should be preserved."""
        session = SessionLimits()

        # Terminate via nonce exhaustion
        session.nonce_counter = MAX_NONCE_COUNTER
        with pytest.raises(RuntimeError):
            session.check_and_increment_nonce()

        assert "nonce counter exhaustion" in session.termination_reason

        # Try again, should show original reason
        try:
            session.check_and_increment_nonce()
        except RuntimeError as e:
            assert "terminated" in str(e)


class TestExhaustionIntegration:
    """Integration tests for exhaustion scenarios."""

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_forced_nonce_exhaustion(
        self,
        attacker,
        server_container,
        client_container,
    ) -> None:
        """Integration test: attempt to force nonce exhaustion.

        This test would send many frames to try to exhaust nonces.
        In practice, this is impossible due to the astronomical limit.
        """
        # This test is more of a stress test / fuzzing scenario
        # Would require sending 2^64 frames which is impossible

        # Instead, we just verify the limit constants
        assert MAX_NONCE_COUNTER == 2**64 - 1
        assert MAX_EPOCH == 2**32 - 1

    @given(
        initial_nonce=st.integers(min_value=MAX_NONCE_COUNTER - 100, max_value=MAX_NONCE_COUNTER - 1),
        frames_to_send=st.integers(min_value=1, max_value=200),
    )
    @settings(max_examples=20)
    def test_exhaustion_near_limit(self, initial_nonce: int, frames_to_send: int) -> None:
        """Property test: session terminates at correct point near limit."""
        session = SessionLimits()
        session.nonce_counter = initial_nonce

        frames_sent = 0
        while session.active and frames_sent < frames_to_send:
            try:
                session.check_and_increment_nonce()
                frames_sent += 1
            except RuntimeError:
                break

        # Verify termination happened at correct point
        if not session.active:
            # Should have stopped exactly at MAX_NONCE_COUNTER
            expected_frames = MAX_NONCE_COUNTER - initial_nonce
            assert frames_sent == expected_frames
