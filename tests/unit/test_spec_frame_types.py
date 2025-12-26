"""
Frame Type Tests

Tests handling of different frame types: Data, Close, and special frames
like keepalives (ACK_ONLY Data frames).

Spec reference: specs/2-TRANSPORT.md
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_NONCE_SIZE,
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FLAG_ACK_ONLY,
    FLAG_HAS_EXTENSION,
    FRAME_CLOSE,
    FRAME_DATA,
    FRAME_HANDSHAKE_INIT,
    FRAME_HANDSHAKE_RESP,
    FRAME_REKEY,
    SESSION_ID_SIZE,
    NomadCodec,
    construct_nonce,
    encode_data_frame_header,
    encode_sync_message,
    parse_data_frame_header,
    parse_nonce,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec instance."""
    return NomadCodec()


# =============================================================================
# Frame Type Constants Tests
# =============================================================================


class TestFrameTypeConstants:
    """Test frame type constant values match spec."""

    def test_handshake_init_type(self) -> None:
        """Handshake Init is type 0x01."""
        assert FRAME_HANDSHAKE_INIT == 0x01

    def test_handshake_resp_type(self) -> None:
        """Handshake Response is type 0x02."""
        assert FRAME_HANDSHAKE_RESP == 0x02

    def test_data_type(self) -> None:
        """Data is type 0x03."""
        assert FRAME_DATA == 0x03

    def test_rekey_type(self) -> None:
        """Rekey is type 0x04."""
        assert FRAME_REKEY == 0x04

    def test_close_type(self) -> None:
        """Close is type 0x05."""
        assert FRAME_CLOSE == 0x05

    def test_types_are_sequential(self) -> None:
        """Frame types are sequential from 0x01 to 0x05."""
        types = [
            FRAME_HANDSHAKE_INIT,
            FRAME_HANDSHAKE_RESP,
            FRAME_DATA,
            FRAME_REKEY,
            FRAME_CLOSE,
        ]
        assert types == [1, 2, 3, 4, 5]


class TestFlagConstants:
    """Test flag constant values match spec."""

    def test_ack_only_flag(self) -> None:
        """ACK_ONLY is bit 0 (0x01)."""
        assert FLAG_ACK_ONLY == 0x01

    def test_has_extension_flag(self) -> None:
        """HAS_EXTENSION is bit 1 (0x02)."""
        assert FLAG_HAS_EXTENSION == 0x02

    def test_flags_are_orthogonal(self) -> None:
        """Flags can be combined without overlap."""
        combined = FLAG_ACK_ONLY | FLAG_HAS_EXTENSION
        assert combined == 0x03
        assert combined & FLAG_ACK_ONLY == FLAG_ACK_ONLY
        assert combined & FLAG_HAS_EXTENSION == FLAG_HAS_EXTENSION


# =============================================================================
# Data Frame Type Tests
# =============================================================================


class TestDataFrameType:
    """Test Data frame (type 0x03) handling."""

    def test_data_frame_type_byte(self) -> None:
        """Data frame header starts with type 0x03."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        header = encode_data_frame_header(
            flags=0,
            session_id=session_id,
            nonce_counter=0,
        )
        assert header[0] == FRAME_DATA

    def test_data_frame_with_ack_only(self) -> None:
        """Data frame with ACK_ONLY flag (keepalive pattern)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        header = encode_data_frame_header(
            flags=FLAG_ACK_ONLY,
            session_id=session_id,
            nonce_counter=0,
        )

        parsed = parse_data_frame_header(header)
        assert parsed.flags & FLAG_ACK_ONLY == FLAG_ACK_ONLY

    def test_data_frame_with_extension(self) -> None:
        """Data frame with HAS_EXTENSION flag."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        header = encode_data_frame_header(
            flags=FLAG_HAS_EXTENSION,
            session_id=session_id,
            nonce_counter=0,
        )

        parsed = parse_data_frame_header(header)
        assert parsed.flags & FLAG_HAS_EXTENSION == FLAG_HAS_EXTENSION

    def test_data_frame_combined_flags(self) -> None:
        """Data frame with multiple flags set."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        combined_flags = FLAG_ACK_ONLY | FLAG_HAS_EXTENSION

        header = encode_data_frame_header(
            flags=combined_flags,
            session_id=session_id,
            nonce_counter=0,
        )

        parsed = parse_data_frame_header(header)
        assert parsed.flags == combined_flags


# =============================================================================
# Keepalive Frame Tests (ACK_ONLY Data Frame)
# =============================================================================


class TestKeepaliveFrame:
    """Test keepalive frames (Data with ACK_ONLY flag, empty diff).

    Per spec: A keepalive is a Data frame (0x03) with:
    - Flags: ACK_ONLY (0x01)
    - Payload: Zero-length sync message (just the ack)
    """

    def test_keepalive_is_data_frame(self, codec: NomadCodec) -> None:
        """Keepalive is a Data frame with ACK_ONLY flag."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive", 32)

        # Empty sync message (ack only)
        sync_message = encode_sync_message(
            sender_state_num=10,
            acked_state_num=10,
            base_state_num=0,
            diff=b"",  # Empty diff
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=900,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Verify it's a Data frame with ACK_ONLY
        assert frame[0] == FRAME_DATA
        assert frame[1] == FLAG_ACK_ONLY

    def test_keepalive_roundtrip(self, codec: NomadCodec) -> None:
        """Keepalive can be created and parsed."""
        session_id = b"\xaa\xbb\xcc\xdd\xee\xff"
        key = codec.deterministic_bytes("keepalive_rt", 32)

        sync_message = encode_sync_message(
            sender_state_num=42,
            acked_state_num=41,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=1,
            timestamp=5000,
            timestamp_echo=4500,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=1,
        )

        assert parsed.header.flags == FLAG_ACK_ONLY
        assert parsed.sync_message.diff == b""

    def test_keepalive_minimal_size(self, codec: NomadCodec) -> None:
        """Keepalive has minimal frame size (header + empty sync + tag)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keepalive_size", 32)

        sync_message = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Header (16) + PayloadHeader (10) + SyncMessage (28) + Tag (16) = 70
        assert len(frame) == DATA_FRAME_HEADER_SIZE + 10 + 28 + AEAD_TAG_SIZE


# =============================================================================
# Nonce Construction Tests
# =============================================================================


class TestNonceConstruction:
    """Test nonce construction for frame encryption."""

    def test_nonce_size(self) -> None:
        """Nonce is exactly 24 bytes (XChaCha20)."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        assert len(nonce) == AEAD_NONCE_SIZE

    def test_nonce_epoch_position(self) -> None:
        """Epoch is at bytes 0-3 (LE32)."""
        nonce = construct_nonce(epoch=0x04030201, direction=0, counter=0)

        # Little-endian: LSB first
        assert nonce[0:4] == b"\x01\x02\x03\x04"

    def test_nonce_direction_position(self) -> None:
        """Direction is at byte 4."""
        nonce_initiator = construct_nonce(epoch=0, direction=0, counter=0)
        nonce_responder = construct_nonce(epoch=0, direction=1, counter=0)

        assert nonce_initiator[4] == 0
        assert nonce_responder[4] == 1

    def test_nonce_padding_zeros(self) -> None:
        """Bytes 5-15 are zeros (padding)."""
        nonce = construct_nonce(epoch=0xFFFFFFFF, direction=1, counter=0xFFFFFFFFFFFFFFFF)

        # Padding should be zeros
        assert nonce[5:16] == b"\x00" * 11

    def test_nonce_counter_position(self) -> None:
        """Counter is at bytes 16-23 (LE64)."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0x0807060504030201)

        # Little-endian: LSB first
        assert nonce[16:24] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_nonce_roundtrip(self) -> None:
        """Construct -> Parse preserves all components."""
        epoch = 42
        direction = 1
        counter = 123456789

        nonce = construct_nonce(epoch=epoch, direction=direction, counter=counter)
        components = parse_nonce(nonce)

        assert components.epoch == epoch
        assert components.direction == direction
        assert components.counter == counter

    @given(
        epoch=st.integers(min_value=0, max_value=2**32 - 1),
        direction=st.integers(min_value=0, max_value=1),
        counter=st.integers(min_value=0, max_value=2**64 - 1),
    )
    @settings(max_examples=100)
    def test_nonce_roundtrip_property(self, epoch: int, direction: int, counter: int) -> None:
        """Any valid nonce components can be round-tripped."""
        nonce = construct_nonce(epoch=epoch, direction=direction, counter=counter)
        components = parse_nonce(nonce)

        assert components.epoch == epoch
        assert components.direction == direction
        assert components.counter == counter


# =============================================================================
# Close Frame Tests
# =============================================================================


class TestCloseFrame:
    """Test Close frame (type 0x05) format.

    Note: Close frame encoding is not yet in the reference codec,
    but we can test the expected structure.
    """

    def test_close_frame_structure(self) -> None:
        """Close frame follows spec structure.

        Layout:
        - Byte 0: Type (0x05)
        - Byte 1: Flags (0x00)
        - Bytes 2-7: Session ID (6 bytes)
        - Bytes 8-15: Nonce Counter (LE64)
        - Bytes 16-23: Encrypted Final Ack (8 bytes)
        - Bytes 24-39: AEAD Tag (16 bytes)

        Total: 40 bytes
        """
        # Build expected close frame structure
        close_frame = bytearray(40)
        close_frame[0] = FRAME_CLOSE  # Type
        close_frame[1] = 0x00  # Flags

        session_id = b"\x01\x02\x03\x04\x05\x06"
        close_frame[2:8] = session_id

        nonce_counter = 100
        struct.pack_into("<Q", close_frame, 8, nonce_counter)

        # Verify structure
        assert close_frame[0] == 0x05
        assert len(close_frame) == 40

    def test_close_frame_type_value(self) -> None:
        """Close frame type is 0x05."""
        assert FRAME_CLOSE == 0x05


# =============================================================================
# Frame Direction Tests
# =============================================================================


class TestFrameDirection:
    """Test frame direction handling in nonces."""

    def test_initiator_direction(self, codec: NomadCodec) -> None:
        """Direction 0 is initiator -> responder."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("direction", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        # Create frame as initiator (direction=0)
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Must parse with same direction
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,  # Same direction
        )

        assert parsed.sync_message.diff == b"test"

    def test_responder_direction(self, codec: NomadCodec) -> None:
        """Direction 1 is responder -> initiator."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("direction2", 32)

        sync_message = encode_sync_message(1, 0, 0, b"response")

        # Create frame as responder (direction=1)
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=1,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Must parse with same direction
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=1,
        )

        assert parsed.sync_message.diff == b"response"

    def test_directions_are_distinct(self, codec: NomadCodec) -> None:
        """Same key but different direction produces different nonces."""
        nonce_init = construct_nonce(epoch=0, direction=0, counter=0)
        nonce_resp = construct_nonce(epoch=0, direction=1, counter=0)

        # Nonces must be different (to prevent nonce reuse)
        assert nonce_init != nonce_resp


# =============================================================================
# Epoch Tests
# =============================================================================


class TestEpoch:
    """Test epoch handling for rekeying."""

    def test_epoch_zero_initial(self, codec: NomadCodec) -> None:
        """Initial epoch is 0."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("epoch0", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        assert parsed is not None

    def test_epoch_in_nonce(self) -> None:
        """Epoch is encoded in nonce at bytes 0-3."""
        nonce_epoch_0 = construct_nonce(epoch=0, direction=0, counter=0)
        nonce_epoch_1 = construct_nonce(epoch=1, direction=0, counter=0)
        nonce_epoch_max = construct_nonce(epoch=0xFFFFFFFF, direction=0, counter=0)

        # Different epochs produce different nonces
        assert nonce_epoch_0 != nonce_epoch_1
        assert nonce_epoch_0 != nonce_epoch_max

        # Parse and verify
        assert parse_nonce(nonce_epoch_0).epoch == 0
        assert parse_nonce(nonce_epoch_1).epoch == 1
        assert parse_nonce(nonce_epoch_max).epoch == 0xFFFFFFFF


# =============================================================================
# Session ID Tests
# =============================================================================


class TestSessionId:
    """Test session ID handling in frames."""

    def test_session_id_size(self) -> None:
        """Session ID is exactly 6 bytes."""
        assert SESSION_ID_SIZE == 6

    def test_session_id_preserved(self) -> None:
        """Session ID is preserved in header encoding."""
        session_id = b"\xde\xad\xbe\xef\xca\xfe"

        header = encode_data_frame_header(
            flags=0,
            session_id=session_id,
            nonce_counter=0,
        )

        parsed = parse_data_frame_header(header)
        assert parsed.session_id == session_id

    def test_session_id_in_aad(self, codec: NomadCodec) -> None:
        """Session ID is authenticated (in AAD)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        wrong_session_id = b"\xff\xfe\xfd\xfc\xfb\xfa"
        key = codec.deterministic_bytes("session_aad", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(
            codec.create_data_frame(
                session_id=session_id,
                nonce_counter=0,
                key=key,
                epoch=0,
                direction=0,
                timestamp=0,
                timestamp_echo=0,
                sync_message=sync_message,
            )
        )

        # Modify session ID in header (bytes 2-7)
        frame[2:8] = wrong_session_id

        # Decryption should fail (AAD mismatch)
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=bytes(frame),
                key=key,
                epoch=0,
                direction=0,
            )

    @given(session_id=st.binary(min_size=SESSION_ID_SIZE, max_size=SESSION_ID_SIZE))
    @settings(max_examples=50)
    def test_any_session_id_works(self, session_id: bytes) -> None:
        """Any 6-byte session ID can be encoded."""
        header = encode_data_frame_header(
            flags=0,
            session_id=session_id,
            nonce_counter=0,
        )

        parsed = parse_data_frame_header(header)
        assert parsed.session_id == session_id
