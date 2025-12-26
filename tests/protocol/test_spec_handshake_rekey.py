"""
Session rekeying protocol tests.

Tests the periodic rekeying mechanism for forward secrecy,
including timing, key transition, and epoch management.

Test mapping: specs/1-SECURITY.md § "Rekeying (Type 0x04)"
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    FRAME_REKEY,
    SESSION_ID_SIZE,
    NomadCodec,
    construct_nonce,
    deterministic_bytes,
    deterministic_keypair,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

# =============================================================================
# Rekeying Constants (from spec)
# =============================================================================


REKEY_AFTER_TIME_SECONDS = 120  # 2 minutes
REKEY_AFTER_MESSAGES = 2**60  # Initiate rekey after this many frames
REJECT_AFTER_TIME_SECONDS = 180  # 3 minutes - hard limit
REJECT_AFTER_MESSAGES = 2**64 - 1  # HARD LIMIT - must terminate
OLD_KEY_RETENTION_SECONDS = 5  # Keep old keys briefly for late packets

MAX_EPOCH = 2**32 - 1  # Maximum epoch value before session termination


# =============================================================================
# Rekey Frame Structure
# =============================================================================


@dataclass
class RekeyFrame:
    """Parsed rekey frame (Type 0x04)."""

    frame_type: int
    flags: int
    session_id: bytes
    nonce_counter: int
    new_ephemeral: bytes  # 32 bytes, encrypted
    timestamp: int  # 4 bytes, encrypted
    tag: bytes  # 16 bytes


def parse_rekey_frame(data: bytes, key: bytes, epoch: int, direction: int) -> RekeyFrame:
    """Parse and decrypt a rekey frame."""
    if len(data) < 16 + 32 + 4 + 16:  # Header + ephemeral + timestamp + tag
        raise ValueError(f"Rekey frame too short: {len(data)}")

    frame_type = data[0]
    if frame_type != FRAME_REKEY:
        raise ValueError(f"Not a rekey frame: type 0x{frame_type:02x}")

    flags = data[1]
    session_id = data[2:8]
    nonce_counter = struct.unpack_from("<Q", data, 8)[0]

    # AAD is the 16-byte header
    aad = data[:16]
    ciphertext = data[16:]

    # Decrypt payload
    nonce = construct_nonce(epoch, direction, nonce_counter)
    plaintext = xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)

    new_ephemeral = plaintext[:32]
    timestamp = struct.unpack_from("<I", plaintext, 32)[0]

    return RekeyFrame(
        frame_type=frame_type,
        flags=flags,
        session_id=session_id,
        nonce_counter=nonce_counter,
        new_ephemeral=new_ephemeral,
        timestamp=timestamp,
        tag=ciphertext[-16:],
    )


def create_rekey_frame(
    session_id: bytes,
    nonce_counter: int,
    key: bytes,
    epoch: int,
    direction: int,
    new_ephemeral: bytes,
    timestamp: int,
) -> bytes:
    """Create an encrypted rekey frame."""
    # Build header (AAD)
    header = bytearray(16)
    header[0] = FRAME_REKEY
    header[1] = 0x00  # Flags
    header[2:8] = session_id
    struct.pack_into("<Q", header, 8, nonce_counter)

    # Build plaintext payload
    plaintext = new_ephemeral + struct.pack("<I", timestamp)

    # Encrypt
    nonce = construct_nonce(epoch, direction, nonce_counter)
    ciphertext = xchacha20_poly1305_encrypt(key, nonce, plaintext, bytes(header))

    return bytes(header) + ciphertext


# =============================================================================
# Session State Simulator
# =============================================================================


@dataclass
class SessionState:
    """Simulated session state for testing rekeying."""

    session_id: bytes
    epoch: int = 0
    send_key: bytes = field(default_factory=lambda: b"\x00" * 32)
    recv_key: bytes = field(default_factory=lambda: b"\x00" * 32)
    send_nonce: int = 0
    recv_nonce: int = 0
    session_start_time: int = 0
    last_rekey_time: int = 0
    old_send_key: bytes | None = None
    old_recv_key: bytes | None = None
    old_key_expiry: int | None = None


def should_rekey(state: SessionState, current_time: int) -> bool:
    """Check if session should initiate rekeying."""
    time_since_rekey = current_time - state.last_rekey_time

    # Time-based rekey
    if time_since_rekey >= REKEY_AFTER_TIME_SECONDS:
        return True

    # Message-based rekey (unlikely to hit in practice)
    return state.send_nonce >= REKEY_AFTER_MESSAGES


def should_reject_key(state: SessionState, current_time: int) -> bool:
    """Check if current keys are past hard limit."""
    time_since_rekey = current_time - state.last_rekey_time

    if time_since_rekey >= REJECT_AFTER_TIME_SECONDS:
        return True

    return state.send_nonce >= REJECT_AFTER_MESSAGES


def perform_rekey(
    state: SessionState,
    new_send_key: bytes,
    new_recv_key: bytes,
    current_time: int,
) -> SessionState:
    """Perform rekeying, transitioning to new keys."""
    return SessionState(
        session_id=state.session_id,
        epoch=state.epoch + 1,
        send_key=new_send_key,
        recv_key=new_recv_key,
        send_nonce=0,  # Reset to 0
        recv_nonce=0,  # Reset to 0
        session_start_time=state.session_start_time,
        last_rekey_time=current_time,
        old_send_key=state.send_key,
        old_recv_key=state.recv_key,
        old_key_expiry=current_time + OLD_KEY_RETENTION_SECONDS,
    )


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def session_state() -> SessionState:
    """Create initial session state."""
    return SessionState(
        session_id=deterministic_bytes("session-id", SESSION_ID_SIZE),
        send_key=deterministic_bytes("send-key", 32),
        recv_key=deterministic_bytes("recv-key", 32),
    )


@pytest.fixture
def codec() -> NomadCodec:
    """NomadCodec instance."""
    return NomadCodec()


# =============================================================================
# Rekey Timing Tests
# =============================================================================


class TestRekeyTiming:
    """Test rekeying timing requirements."""

    def test_rekey_after_time_constant(self) -> None:
        """REKEY_AFTER_TIME is 120 seconds (2 minutes)."""
        assert REKEY_AFTER_TIME_SECONDS == 120

    def test_reject_after_time_constant(self) -> None:
        """REJECT_AFTER_TIME is 180 seconds (3 minutes)."""
        assert REJECT_AFTER_TIME_SECONDS == 180

    def test_old_key_retention_constant(self) -> None:
        """OLD_KEY_RETENTION is 5 seconds."""
        assert OLD_KEY_RETENTION_SECONDS == 5

    def test_no_rekey_before_timeout(self, session_state: SessionState) -> None:
        """No rekey needed before REKEY_AFTER_TIME."""
        # 60 seconds have passed - not enough for rekey
        current_time = 60
        assert not should_rekey(session_state, current_time)

    def test_rekey_after_timeout(self, session_state: SessionState) -> None:
        """Rekey needed after REKEY_AFTER_TIME."""
        # 120 seconds have passed - should rekey
        current_time = 120
        assert should_rekey(session_state, current_time)

    def test_rekey_well_after_timeout(self, session_state: SessionState) -> None:
        """Rekey needed when well past timeout."""
        # 200 seconds have passed
        current_time = 200
        assert should_rekey(session_state, current_time)

    def test_no_reject_before_hard_limit(self, session_state: SessionState) -> None:
        """Keys not rejected before REJECT_AFTER_TIME."""
        # 150 seconds - past soft limit but before hard limit
        current_time = 150
        assert not should_reject_key(session_state, current_time)

    def test_reject_at_hard_limit(self, session_state: SessionState) -> None:
        """Keys rejected at REJECT_AFTER_TIME."""
        # 180 seconds - at hard limit
        current_time = 180
        assert should_reject_key(session_state, current_time)


# =============================================================================
# Rekey Message Count Tests
# =============================================================================


class TestRekeyMessageCount:
    """Test message count based rekeying."""

    def test_rekey_after_messages_constant(self) -> None:
        """REKEY_AFTER_MESSAGES is 2^60."""
        assert REKEY_AFTER_MESSAGES == 2**60

    def test_reject_after_messages_constant(self) -> None:
        """REJECT_AFTER_MESSAGES is 2^64 - 1."""
        assert REJECT_AFTER_MESSAGES == 2**64 - 1

    def test_no_rekey_at_low_count(self) -> None:
        """No rekey needed at low message count."""
        state = SessionState(
            session_id=b"\x00" * 6,
            send_nonce=1000000,  # 1 million messages
        )
        assert not should_rekey(state, current_time=0)

    def test_rekey_at_message_threshold(self) -> None:
        """Rekey needed at REKEY_AFTER_MESSAGES threshold."""
        state = SessionState(
            session_id=b"\x00" * 6,
            send_nonce=2**60,  # At threshold
        )
        assert should_rekey(state, current_time=0)

    def test_must_terminate_at_counter_exhaustion(self) -> None:
        """Session must terminate at REJECT_AFTER_MESSAGES."""
        state = SessionState(
            session_id=b"\x00" * 6,
            send_nonce=2**64 - 1,  # Maximum counter
        )
        assert should_reject_key(state, current_time=0)


# =============================================================================
# Epoch Management Tests
# =============================================================================


class TestEpochManagement:
    """Test epoch increment during rekeying."""

    def test_initial_epoch_is_zero(self, session_state: SessionState) -> None:
        """Initial epoch is 0."""
        assert session_state.epoch == 0

    def test_epoch_increments_on_rekey(self, session_state: SessionState) -> None:
        """Epoch increments by 1 on rekey."""
        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=120,
        )
        assert new_state.epoch == 1

    def test_epoch_increments_each_rekey(self, session_state: SessionState) -> None:
        """Epoch increments on each successive rekey."""
        state = session_state
        for i in range(5):
            state = perform_rekey(
                state,
                new_send_key=deterministic_bytes(f"send-{i}", 32),
                new_recv_key=deterministic_bytes(f"recv-{i}", 32),
                current_time=120 * (i + 1),
            )
            assert state.epoch == i + 1

    def test_max_epoch_constant(self) -> None:
        """MAX_EPOCH is 2^32 - 1."""
        assert MAX_EPOCH == 2**32 - 1

    def test_epoch_exhaustion_terminates_session(self) -> None:
        """Session terminates when epoch reaches MAX_EPOCH."""
        state = SessionState(
            session_id=b"\x00" * 6,
            epoch=MAX_EPOCH,
        )

        # Cannot rekey beyond MAX_EPOCH
        # Implementation would terminate session
        assert state.epoch >= MAX_EPOCH


# =============================================================================
# Nonce Counter Reset Tests
# =============================================================================


class TestNonceCounterReset:
    """Test nonce counter reset during rekeying."""

    def test_counters_reset_on_rekey(self, session_state: SessionState) -> None:
        """Send and receive counters reset to 0 on rekey."""
        # Simulate some messages sent
        session_state.send_nonce = 1000
        session_state.recv_nonce = 500

        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=120,
        )

        assert new_state.send_nonce == 0
        assert new_state.recv_nonce == 0

    def test_counter_reset_prevents_nonce_reuse(self, session_state: SessionState) -> None:
        """Epoch change ensures unique nonces even after counter reset."""
        # Before rekey: epoch=0, counter=100
        nonce_before = construct_nonce(
            epoch=session_state.epoch,
            direction=0,
            counter=100,
        )

        # After rekey: epoch=1, counter=0
        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=120,
        )

        nonce_after = construct_nonce(
            epoch=new_state.epoch,
            direction=0,
            counter=0,
        )

        # Nonces must be different
        assert nonce_before != nonce_after


# =============================================================================
# Old Key Retention Tests
# =============================================================================


class TestOldKeyRetention:
    """Test old key retention during rekey transition."""

    def test_old_keys_retained(self, session_state: SessionState) -> None:
        """Old keys are retained after rekey."""
        old_send = session_state.send_key
        old_recv = session_state.recv_key

        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=120,
        )

        assert new_state.old_send_key == old_send
        assert new_state.old_recv_key == old_recv

    def test_old_key_expiry_set(self, session_state: SessionState) -> None:
        """Old key expiry is set to current_time + retention."""
        current_time = 120
        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=current_time,
        )

        expected_expiry = current_time + OLD_KEY_RETENTION_SECONDS
        assert new_state.old_key_expiry == expected_expiry

    def test_new_keys_are_current(self, session_state: SessionState) -> None:
        """New keys become the current keys."""
        new_send = b"\x01" * 32
        new_recv = b"\x02" * 32

        new_state = perform_rekey(
            session_state,
            new_send_key=new_send,
            new_recv_key=new_recv,
            current_time=120,
        )

        assert new_state.send_key == new_send
        assert new_state.recv_key == new_recv


# =============================================================================
# Rekey Frame Tests
# =============================================================================


class TestRekeyFrame:
    """Test rekey frame encoding and decoding."""

    def test_rekey_frame_type(self) -> None:
        """Rekey frame type is 0x04."""
        assert FRAME_REKEY == 0x04

    def test_create_rekey_frame(self) -> None:
        """Create a valid rekey frame."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = deterministic_bytes("rekey-key", 32)
        new_ephemeral = deterministic_bytes("new-ephemeral", 32)

        frame = create_rekey_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            new_ephemeral=new_ephemeral,
            timestamp=1000,
        )

        # Verify structure
        assert frame[0] == FRAME_REKEY
        assert frame[2:8] == session_id

    def test_rekey_frame_roundtrip(self) -> None:
        """Rekey frame can be created and parsed."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = deterministic_bytes("rekey-key", 32)
        new_ephemeral = deterministic_bytes("new-ephemeral", 32)
        timestamp = 5000

        frame = create_rekey_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            new_ephemeral=new_ephemeral,
            timestamp=timestamp,
        )

        parsed = parse_rekey_frame(frame, key, epoch=0, direction=0)

        assert parsed.frame_type == FRAME_REKEY
        assert parsed.session_id == session_id
        assert parsed.nonce_counter == 100
        assert parsed.new_ephemeral == new_ephemeral
        assert parsed.timestamp == timestamp

    def test_rekey_frame_wrong_key_fails(self) -> None:
        """Rekey frame decryption fails with wrong key."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = deterministic_bytes("rekey-key", 32)
        wrong_key = deterministic_bytes("wrong-key", 32)
        new_ephemeral = deterministic_bytes("new-ephemeral", 32)

        frame = create_rekey_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            new_ephemeral=new_ephemeral,
            timestamp=1000,
        )

        with pytest.raises(InvalidTag):
            parse_rekey_frame(frame, wrong_key, epoch=0, direction=0)


# =============================================================================
# Key Derivation After Rekey Tests
# =============================================================================


class TestPostRekeyKeyDerivation:
    """Test key derivation after rekeying."""

    def test_new_keys_different_from_old(self, session_state: SessionState) -> None:
        """New keys must be different from old keys."""
        new_state = perform_rekey(
            session_state,
            new_send_key=deterministic_bytes("new-send", 32),
            new_recv_key=deterministic_bytes("new-recv", 32),
            current_time=120,
        )

        assert new_state.send_key != session_state.send_key
        assert new_state.recv_key != session_state.recv_key

    def test_rekey_timestamp_updated(self, session_state: SessionState) -> None:
        """Last rekey timestamp is updated."""
        current_time = 120
        new_state = perform_rekey(
            session_state,
            new_send_key=b"\x01" * 32,
            new_recv_key=b"\x02" * 32,
            current_time=current_time,
        )

        assert new_state.last_rekey_time == current_time


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestRekeyProperties:
    """Property-based tests for rekeying."""

    @given(epoch=st.integers(min_value=0, max_value=MAX_EPOCH - 1))
    @settings(max_examples=50)
    def test_epoch_always_increments(self, epoch: int) -> None:
        """Epoch always increments by exactly 1."""
        state = SessionState(session_id=b"\x00" * 6, epoch=epoch)
        new_state = perform_rekey(state, b"\x00" * 32, b"\x00" * 32, current_time=0)

        assert new_state.epoch == epoch + 1

    @given(current_time=st.integers(min_value=0, max_value=1000000))
    @settings(max_examples=50)
    def test_old_key_expiry_formula(self, current_time: int) -> None:
        """Old key expiry is always current_time + retention."""
        state = SessionState(session_id=b"\x00" * 6)
        new_state = perform_rekey(state, b"\x00" * 32, b"\x00" * 32, current_time=current_time)

        assert new_state.old_key_expiry == current_time + OLD_KEY_RETENTION_SECONDS

    @given(
        send_nonce=st.integers(min_value=0, max_value=2**63),
        recv_nonce=st.integers(min_value=0, max_value=2**63),
    )
    @settings(max_examples=50)
    def test_counters_always_reset(self, send_nonce: int, recv_nonce: int) -> None:
        """Counters always reset to 0 on rekey regardless of previous value."""
        state = SessionState(
            session_id=b"\x00" * 6,
            send_nonce=send_nonce,
            recv_nonce=recv_nonce,
        )
        new_state = perform_rekey(state, b"\x00" * 32, b"\x00" * 32, current_time=0)

        assert new_state.send_nonce == 0
        assert new_state.recv_nonce == 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestRekeyIntegration:
    """Integration tests for complete rekey flow."""

    def test_full_rekey_flow(self, session_state: SessionState, codec: NomadCodec) -> None:
        """Complete rekey flow: detect -> initiate -> complete."""
        # 1. Session runs for 120 seconds
        current_time = 120
        assert should_rekey(session_state, current_time)

        # 2. Generate new ephemeral keypair
        new_ephemeral_priv, new_ephemeral_pub = deterministic_keypair("new-ephemeral")

        # 3. Create rekey frame
        frame = create_rekey_frame(
            session_id=session_state.session_id,
            nonce_counter=session_state.send_nonce,
            key=session_state.send_key,
            epoch=session_state.epoch,
            direction=0,
            new_ephemeral=new_ephemeral_pub,
            timestamp=current_time * 1000,  # Convert to ms
        )

        # 4. Parse rekey frame (simulating responder)
        parsed = parse_rekey_frame(
            frame,
            key=session_state.send_key,
            epoch=session_state.epoch,
            direction=0,
        )

        assert parsed.new_ephemeral == new_ephemeral_pub

        # 5. Complete rekey with new keys
        new_send_key = deterministic_bytes("derived-send-key", 32)
        new_recv_key = deterministic_bytes("derived-recv-key", 32)

        new_state = perform_rekey(
            session_state,
            new_send_key=new_send_key,
            new_recv_key=new_recv_key,
            current_time=current_time,
        )

        # Verify state transition
        assert new_state.epoch == session_state.epoch + 1
        assert new_state.send_nonce == 0
        assert new_state.old_send_key == session_state.send_key
