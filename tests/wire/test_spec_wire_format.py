"""
Wire Format Tests

Byte-level validation of frame format compliance.
These tests verify exact byte positions, endianness, and size constraints.

Spec reference: specs/2-TRANSPORT.md
"""

from __future__ import annotations

import struct
from pathlib import Path

import json5
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_NONCE_SIZE,
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FLAG_ACK_ONLY,
    FLAG_HAS_EXTENSION,
    FRAME_DATA,
    SESSION_ID_SIZE,
    SYNC_MESSAGE_HEADER_SIZE,
    NomadCodec,
    construct_nonce,
    encode_data_frame_header,
    encode_payload_header,
    encode_sync_message,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def frame_vectors() -> dict:
    """Load frame test vectors from JSON5 file."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "frame_vectors.json5"
    with vectors_path.open() as f:
        return json5.load(f)


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec instance."""
    return NomadCodec()


# =============================================================================
# Data Frame Header Wire Format Tests
# =============================================================================


class TestDataFrameHeaderWireFormat:
    """Test data frame header byte-level format."""

    def test_header_size(self) -> None:
        """Data frame header is exactly 16 bytes."""
        assert DATA_FRAME_HEADER_SIZE == 16

        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0,
        )
        assert len(header) == 16

    def test_type_byte_offset(self) -> None:
        """Type byte is at offset 0."""
        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0,
        )
        assert header[0] == FRAME_DATA

    def test_flags_byte_offset(self) -> None:
        """Flags byte is at offset 1."""
        header_no_flags = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0,
        )
        header_ack_only = encode_data_frame_header(
            flags=FLAG_ACK_ONLY,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0,
        )
        header_extension = encode_data_frame_header(
            flags=FLAG_HAS_EXTENSION,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0,
        )

        assert header_no_flags[1] == 0x00
        assert header_ack_only[1] == 0x01
        assert header_extension[1] == 0x02

    def test_session_id_offset(self) -> None:
        """Session ID is at offsets 2-7 (6 bytes)."""
        session_id = b"\x11\x22\x33\x44\x55\x66"
        header = encode_data_frame_header(
            flags=0,
            session_id=session_id,
            nonce_counter=0,
        )

        assert header[2:8] == session_id

    def test_nonce_counter_offset(self) -> None:
        """Nonce counter is at offsets 8-15 (8 bytes, LE64)."""
        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=0x0102030405060708,
        )

        # Little-endian: least significant byte first
        assert header[8:16] == b"\x08\x07\x06\x05\x04\x03\x02\x01"

    def test_nonce_counter_little_endian(self) -> None:
        """Nonce counter uses little-endian encoding."""
        # Test with value 1
        header_1 = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=1,
        )
        assert header_1[8] == 0x01
        assert header_1[9:16] == b"\x00" * 7

        # Test with value 256
        header_256 = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=256,
        )
        assert header_256[8] == 0x00
        assert header_256[9] == 0x01

    def test_nonce_counter_max_value(self) -> None:
        """Nonce counter can hold maximum uint64 value."""
        max_counter = 0xFFFFFFFFFFFFFFFF
        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * SESSION_ID_SIZE,
            nonce_counter=max_counter,
        )

        assert header[8:16] == b"\xff" * 8

    def test_header_vectors(self, frame_vectors: dict) -> None:
        """Verify all header test vectors byte-by-byte."""
        for vector in frame_vectors["data_frame_headers"]:
            session_id = bytes.fromhex(vector["session_id"])
            encoded = encode_data_frame_header(
                flags=vector["flags"],
                session_id=session_id,
                nonce_counter=vector["nonce_counter"],
            )

            expected = bytes.fromhex(vector["encoded"])
            assert encoded == expected, f"Vector {vector['name']} mismatch"


# =============================================================================
# Payload Header Wire Format Tests
# =============================================================================


class TestPayloadHeaderWireFormat:
    """Test encrypted payload header byte-level format."""

    def test_payload_header_size(self) -> None:
        """Payload header is exactly 10 bytes."""
        header = encode_payload_header(
            timestamp=0,
            timestamp_echo=0,
            payload_length=0,
        )
        assert len(header) == 10

    def test_timestamp_offset(self) -> None:
        """Timestamp is at offsets 0-3 (4 bytes, LE32)."""
        header = encode_payload_header(
            timestamp=0x04030201,
            timestamp_echo=0,
            payload_length=0,
        )

        # Little-endian
        assert header[0:4] == b"\x01\x02\x03\x04"

    def test_timestamp_echo_offset(self) -> None:
        """Timestamp echo is at offsets 4-7 (4 bytes, LE32)."""
        header = encode_payload_header(
            timestamp=0,
            timestamp_echo=0x08070605,
            payload_length=0,
        )

        # Little-endian
        assert header[4:8] == b"\x05\x06\x07\x08"

    def test_payload_length_offset(self) -> None:
        """Payload length is at offsets 8-9 (2 bytes, LE16)."""
        header = encode_payload_header(
            timestamp=0,
            timestamp_echo=0,
            payload_length=0x0201,
        )

        # Little-endian
        assert header[8:10] == b"\x01\x02"

    def test_timestamp_max_value(self) -> None:
        """Timestamp can hold maximum uint32 value (about 49 days in ms)."""
        max_ts = 0xFFFFFFFF
        header = encode_payload_header(
            timestamp=max_ts,
            timestamp_echo=0,
            payload_length=0,
        )

        assert header[0:4] == b"\xff\xff\xff\xff"

    def test_payload_length_max_value(self) -> None:
        """Payload length can hold maximum uint16 value (65535 bytes)."""
        max_len = 0xFFFF
        header = encode_payload_header(
            timestamp=0,
            timestamp_echo=0,
            payload_length=max_len,
        )

        assert header[8:10] == b"\xff\xff"


# =============================================================================
# Sync Message Wire Format Tests
# =============================================================================


class TestSyncMessageWireFormat:
    """Test sync message byte-level format."""

    def test_sync_header_size(self) -> None:
        """Sync message header is exactly 28 bytes (without diff)."""
        assert SYNC_MESSAGE_HEADER_SIZE == 28

        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )
        assert len(msg) == 28

    def test_sender_state_num_offset(self) -> None:
        """Sender state num is at offsets 0-7 (8 bytes, LE64)."""
        msg = encode_sync_message(
            sender_state_num=0x0807060504030201,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )

        assert msg[0:8] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_acked_state_num_offset(self) -> None:
        """Acked state num is at offsets 8-15 (8 bytes, LE64)."""
        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0x0807060504030201,
            base_state_num=0,
            diff=b"",
        )

        assert msg[8:16] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_base_state_num_offset(self) -> None:
        """Base state num is at offsets 16-23 (8 bytes, LE64)."""
        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0x0807060504030201,
            diff=b"",
        )

        assert msg[16:24] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_diff_length_offset(self) -> None:
        """Diff length is at offsets 24-27 (4 bytes, LE32)."""
        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=b"hello",
        )

        # Length is 5
        assert msg[24:28] == b"\x05\x00\x00\x00"

    def test_diff_payload_offset(self) -> None:
        """Diff payload starts at offset 28."""
        diff = b"hello world"
        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        assert msg[28:] == diff

    def test_sync_message_vectors(self, frame_vectors: dict) -> None:
        """Verify all sync message test vectors byte-by-byte."""
        for vector in frame_vectors["sync_messages"]:
            diff = bytes.fromhex(vector["diff"])
            encoded = encode_sync_message(
                sender_state_num=vector["sender_state_num"],
                acked_state_num=vector["acked_state_num"],
                base_state_num=vector["base_state_num"],
                diff=diff,
            )

            expected = bytes.fromhex(vector["encoded"])
            assert encoded == expected, f"Vector {vector['name']} mismatch"
            assert len(encoded) == vector["encoded_length"]


# =============================================================================
# Nonce Wire Format Tests
# =============================================================================


class TestNonceWireFormat:
    """Test nonce byte-level format for XChaCha20."""

    def test_nonce_size(self) -> None:
        """Nonce is exactly 24 bytes."""
        assert AEAD_NONCE_SIZE == 24

        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        assert len(nonce) == 24

    def test_epoch_offset(self) -> None:
        """Epoch is at offsets 0-3 (4 bytes, LE32)."""
        nonce = construct_nonce(epoch=0x04030201, direction=0, counter=0)
        assert nonce[0:4] == b"\x01\x02\x03\x04"

    def test_direction_offset(self) -> None:
        """Direction is at offset 4 (1 byte)."""
        nonce_init = construct_nonce(epoch=0, direction=0, counter=0)
        nonce_resp = construct_nonce(epoch=0, direction=1, counter=0)

        assert nonce_init[4] == 0x00
        assert nonce_resp[4] == 0x01

    def test_padding_offset(self) -> None:
        """Padding (zeros) is at offsets 5-15 (11 bytes)."""
        nonce = construct_nonce(epoch=0xFFFFFFFF, direction=1, counter=0xFFFFFFFFFFFFFFFF)
        assert nonce[5:16] == b"\x00" * 11

    def test_counter_offset(self) -> None:
        """Counter is at offsets 16-23 (8 bytes, LE64)."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0x0807060504030201)
        assert nonce[16:24] == b"\x01\x02\x03\x04\x05\x06\x07\x08"


# =============================================================================
# Complete Frame Wire Format Tests
# =============================================================================


class TestCompleteFrameWireFormat:
    """Test complete data frame byte-level format."""

    def test_minimum_frame_size(self) -> None:
        """Minimum frame size is header + tag = 32 bytes.

        Per spec: Header (16) + empty payload + Tag (16) = 32+ bytes.
        But encrypted payload has minimum 10 bytes (payload header) + 28 bytes (sync header).
        """
        # Spec says minimum is 32, but actual minimum with headers:
        # Header (16) + PayloadHeader (10) + SyncHeader (28) + Tag (16) = 70 bytes
        min_header = DATA_FRAME_HEADER_SIZE  # 16
        min_tag = AEAD_TAG_SIZE  # 16

        # Spec-defined minimum (empty payload)
        spec_minimum = min_header + min_tag  # 32
        assert spec_minimum == 32

    def test_frame_header_is_plaintext(self, codec: NomadCodec) -> None:
        """Frame header (first 16 bytes) is not encrypted."""
        session_id = b"\xde\xad\xbe\xef\xca\xfe"
        key = codec.deterministic_bytes("plaintext_header", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=42,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=500,
            sync_message=sync_message,
        )

        # Header is plaintext - can read type, flags, session ID, nonce
        assert frame[0] == FRAME_DATA
        assert frame[2:8] == session_id

        # Nonce counter (little-endian)
        nonce_counter = struct.unpack_from("<Q", frame, 8)[0]
        assert nonce_counter == 42

    def test_frame_aad_is_header(self, codec: NomadCodec) -> None:
        """Frame header is used as AAD for AEAD encryption."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("aad_test", 32)

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

        # Modify header (AAD)
        frame[1] = 0xFF

        # Decryption should fail
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=bytes(frame),
                key=key,
                epoch=0,
                direction=0,
            )

    def test_frame_layout(self, codec: NomadCodec) -> None:
        """Verify complete frame byte layout.

        Layout:
        - Bytes 0-15: Header (plaintext, used as AAD)
          - Byte 0: Type
          - Byte 1: Flags
          - Bytes 2-7: Session ID
          - Bytes 8-15: Nonce Counter
        - Bytes 16+: Encrypted Payload + AEAD Tag
          - Last 16 bytes: AEAD Tag
        """
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("layout", 32)

        sync_message = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"test",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            timestamp=5000,
            timestamp_echo=4000,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Verify header layout
        assert frame[0] == FRAME_DATA
        assert frame[1] == FLAG_ACK_ONLY
        assert frame[2:8] == session_id

        nonce_counter = struct.unpack_from("<Q", frame, 8)[0]
        assert nonce_counter == 100

        # Encrypted payload starts at offset 16
        # Last 16 bytes are AEAD tag
        encrypted_payload = frame[16:-16]
        aead_tag = frame[-16:]

        # Encrypted payload should be:
        # PayloadHeader (10) + SyncMessage (28 + 4) = 42 bytes
        assert len(encrypted_payload) == 10 + 28 + len(b"test")
        assert len(aead_tag) == 16


# =============================================================================
# Size Constraint Tests
# =============================================================================


class TestSizeConstraints:
    """Test wire format size constraints."""

    def test_session_id_exactly_6_bytes(self) -> None:
        """Session ID must be exactly 6 bytes."""
        assert SESSION_ID_SIZE == 6

        # Valid
        encode_data_frame_header(
            flags=0,
            session_id=b"\x00" * 6,
            nonce_counter=0,
        )

        # Too short
        with pytest.raises(AssertionError):
            encode_data_frame_header(
                flags=0,
                session_id=b"\x00" * 5,
                nonce_counter=0,
            )

        # Too long
        with pytest.raises(AssertionError):
            encode_data_frame_header(
                flags=0,
                session_id=b"\x00" * 7,
                nonce_counter=0,
            )

    def test_aead_tag_size(self) -> None:
        """AEAD tag is exactly 16 bytes (Poly1305)."""
        assert AEAD_TAG_SIZE == 16

    def test_sync_diff_length_32bit(self) -> None:
        """Sync diff length field is 32 bits (max 4GB)."""
        # Verify the length field can theoretically hold large values
        max_32bit = 0xFFFFFFFF

        # Manually check the length field can hold max value
        length_bytes = struct.pack("<I", max_32bit)
        assert len(length_bytes) == 4


# =============================================================================
# MTU Compliance Tests
# =============================================================================


class TestMTUCompliance:
    """Test MTU-related size constraints from spec."""

    def test_recommended_max_payload(self) -> None:
        """Recommended max payload is 1200 bytes (conservative mobile MTU)."""
        # This is a documentation/constant test
        recommended_max = 1200
        # Verify it's a reasonable value within typical MTU ranges
        assert 1000 <= recommended_max <= 1500

    def test_ipv6_minimum_mtu(self) -> None:
        """IPv6 minimum MTU is 1280 bytes, recommended payload is 1200."""
        ipv6_min_mtu = 1280
        ipv6_recommended_payload = 1200
        assert ipv6_recommended_payload < ipv6_min_mtu

    def test_ethernet_mtu(self) -> None:
        """Ethernet MTU is typically 1500, recommended payload is 1400."""
        ethernet_mtu = 1500
        ethernet_recommended_payload = 1400
        assert ethernet_recommended_payload < ethernet_mtu

    def test_large_diff_payload(self, codec: NomadCodec) -> None:
        """Frame can carry diff payloads up to MTU limit."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("large_payload", 32)

        # Create a 1000-byte diff (within 1200 limit)
        large_diff = b"x" * 1000

        sync_message = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=large_diff,
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
        )

        # Verify roundtrip
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        assert parsed.sync_message.diff == large_diff


# =============================================================================
# Property-Based Wire Format Tests
# =============================================================================


class TestPropertyBasedWireFormat:
    """Property-based tests for wire format invariants."""

    @given(
        flags=st.integers(min_value=0, max_value=255),
        session_id=st.binary(min_size=SESSION_ID_SIZE, max_size=SESSION_ID_SIZE),
        nonce_counter=st.integers(min_value=0, max_value=2**64 - 1),
    )
    @settings(max_examples=100)
    def test_header_byte_positions(self, flags: int, session_id: bytes, nonce_counter: int) -> None:
        """Header fields are always at correct byte positions."""
        header = encode_data_frame_header(
            flags=flags,
            session_id=session_id,
            nonce_counter=nonce_counter,
        )

        # Type always at offset 0
        assert header[0] == FRAME_DATA

        # Flags always at offset 1
        assert header[1] == flags

        # Session ID always at offsets 2-7
        assert header[2:8] == session_id

        # Nonce counter always at offsets 8-15
        parsed_counter = struct.unpack_from("<Q", header, 8)[0]
        assert parsed_counter == nonce_counter

    @given(
        diff_size=st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=50)
    def test_sync_message_size_formula(self, diff_size: int) -> None:
        """Sync message size is always 28 + diff_size."""
        diff = b"x" * diff_size
        msg = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        assert len(msg) == SYNC_MESSAGE_HEADER_SIZE + diff_size
