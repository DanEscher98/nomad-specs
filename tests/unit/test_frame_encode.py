"""
Frame Encoding Tests

Tests frame encoding against test vectors from frame_vectors.json5.
Validates that the reference codec produces correct wire format.

Spec reference: specs/2-TRANSPORT.md
"""

from __future__ import annotations

from pathlib import Path

import json5
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    DATA_FRAME_HEADER_SIZE,
    FLAG_ACK_ONLY,
    FLAG_HAS_EXTENSION,
    FRAME_DATA,
    SESSION_ID_SIZE,
    NomadCodec,
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
# Data Frame Header Encoding Tests
# =============================================================================


class TestDataFrameHeaderEncode:
    """Test data frame header encoding."""

    def test_basic_data_frame_header(self, frame_vectors: dict) -> None:
        """Encode basic data frame header and verify against vector."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "basic_data_frame"
        )

        session_id = bytes.fromhex(vector["session_id"])
        encoded = encode_data_frame_header(
            flags=vector["flags"],
            session_id=session_id,
            nonce_counter=vector["nonce_counter"],
        )

        assert encoded == bytes.fromhex(vector["encoded"])
        assert len(encoded) == vector["encoded_length"]
        assert len(encoded) == DATA_FRAME_HEADER_SIZE

    def test_ack_only_frame_header(self, frame_vectors: dict) -> None:
        """Encode ack-only data frame header."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "ack_only_frame"
        )

        session_id = bytes.fromhex(vector["session_id"])
        encoded = encode_data_frame_header(
            flags=vector["flags"],
            session_id=session_id,
            nonce_counter=vector["nonce_counter"],
        )

        assert encoded == bytes.fromhex(vector["encoded"])
        assert encoded[0] == FRAME_DATA  # Type byte
        assert encoded[1] == FLAG_ACK_ONLY  # Flags byte

    def test_extension_flag_header(self, frame_vectors: dict) -> None:
        """Encode data frame header with extension flag."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "with_extension_flag"
        )

        session_id = bytes.fromhex(vector["session_id"])
        encoded = encode_data_frame_header(
            flags=vector["flags"],
            session_id=session_id,
            nonce_counter=vector["nonce_counter"],
        )

        assert encoded == bytes.fromhex(vector["encoded"])
        assert encoded[1] == FLAG_HAS_EXTENSION

    def test_header_structure(self) -> None:
        """Verify header byte layout matches spec.

        Layout:
        - Byte 0: Type (0x03 for Data)
        - Byte 1: Flags
        - Bytes 2-7: Session ID (6 bytes)
        - Bytes 8-15: Nonce Counter (LE64)
        """
        session_id = b"\x01\x02\x03\x04\x05\x06"
        nonce_counter = 0x0807060504030201  # Test endianness

        encoded = encode_data_frame_header(
            flags=0x00,
            session_id=session_id,
            nonce_counter=nonce_counter,
        )

        assert encoded[0] == 0x03  # Type
        assert encoded[1] == 0x00  # Flags
        assert encoded[2:8] == session_id  # Session ID
        # Nonce counter in little-endian
        assert encoded[8:16] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_nonce_counter_little_endian(self) -> None:
        """Verify nonce counter uses little-endian encoding."""
        session_id = b"\x00" * SESSION_ID_SIZE

        # Test with value that shows byte order
        encoded = encode_data_frame_header(
            flags=0,
            session_id=session_id,
            nonce_counter=1,  # Should be 0x01 in first byte
        )

        # Little-endian: LSB first
        assert encoded[8] == 0x01
        assert encoded[9:16] == b"\x00" * 7

    def test_invalid_session_id_length(self) -> None:
        """Reject session IDs that aren't exactly 6 bytes."""
        with pytest.raises(AssertionError):
            encode_data_frame_header(
                flags=0,
                session_id=b"\x00" * 5,  # Too short
                nonce_counter=0,
            )

        with pytest.raises(AssertionError):
            encode_data_frame_header(
                flags=0,
                session_id=b"\x00" * 7,  # Too long
                nonce_counter=0,
            )


# =============================================================================
# Payload Header Encoding Tests
# =============================================================================


class TestPayloadHeaderEncode:
    """Test encrypted payload header encoding."""

    def test_payload_header_structure(self) -> None:
        """Verify payload header byte layout.

        Layout:
        - Bytes 0-3: Timestamp (LE32)
        - Bytes 4-7: Timestamp Echo (LE32)
        - Bytes 8-9: Payload Length (LE16)
        """
        encoded = encode_payload_header(
            timestamp=0x04030201,
            timestamp_echo=0x08070605,
            payload_length=0x0A09,
        )

        # Little-endian: LSB first
        assert encoded[0:4] == b"\x01\x02\x03\x04"  # Timestamp
        assert encoded[4:8] == b"\x05\x06\x07\x08"  # Timestamp Echo
        assert encoded[8:10] == b"\x09\x0a"  # Payload Length

    def test_payload_header_length(self) -> None:
        """Payload header is exactly 10 bytes."""
        encoded = encode_payload_header(
            timestamp=0,
            timestamp_echo=0,
            payload_length=0,
        )
        assert len(encoded) == 10

    def test_timestamp_range(self) -> None:
        """Test timestamp at maximum uint32 value."""
        max_timestamp = 0xFFFFFFFF

        encoded = encode_payload_header(
            timestamp=max_timestamp,
            timestamp_echo=0,
            payload_length=0,
        )

        assert encoded[0:4] == b"\xff\xff\xff\xff"


# =============================================================================
# Sync Message Encoding Tests
# =============================================================================


class TestSyncMessageEncode:
    """Test sync message encoding."""

    def test_basic_sync_message(self, frame_vectors: dict) -> None:
        """Encode basic sync message and verify against vector."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "basic_sync"
        )

        diff = bytes.fromhex(vector["diff"])
        encoded = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        assert encoded == bytes.fromhex(vector["encoded"])
        assert len(encoded) == vector["encoded_length"]

    def test_ack_only_sync_message(self, frame_vectors: dict) -> None:
        """Encode ack-only sync message (empty diff)."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "ack_only_sync"
        )

        encoded = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=b"",  # Empty diff
        )

        assert encoded == bytes.fromhex(vector["encoded"])
        assert len(encoded) == 28  # Header only, no diff payload

    def test_initial_sync_message(self, frame_vectors: dict) -> None:
        """Encode initial sync message."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "initial_sync"
        )

        diff = bytes.fromhex(vector["diff"])
        encoded = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        assert encoded == bytes.fromhex(vector["encoded"])

    def test_sync_message_structure(self) -> None:
        """Verify sync message byte layout.

        Layout:
        - Bytes 0-7: Sender State Num (LE64)
        - Bytes 8-15: Acked State Num (LE64)
        - Bytes 16-23: Base State Num (LE64)
        - Bytes 24-27: Diff Length (LE32)
        - Bytes 28+: Diff Payload
        """
        diff = b"test"
        encoded = encode_sync_message(
            sender_state_num=1,
            acked_state_num=2,
            base_state_num=3,
            diff=diff,
        )

        import struct

        # Verify structure
        sender = struct.unpack_from("<Q", encoded, 0)[0]
        acked = struct.unpack_from("<Q", encoded, 8)[0]
        base = struct.unpack_from("<Q", encoded, 16)[0]
        diff_len = struct.unpack_from("<I", encoded, 24)[0]

        assert sender == 1
        assert acked == 2
        assert base == 3
        assert diff_len == len(diff)
        assert encoded[28:] == diff


# =============================================================================
# Complete Data Frame Encoding Tests
# =============================================================================


class TestCompleteDataFrameEncode:
    """Test complete data frame encoding (header + encrypted payload)."""

    def test_create_data_frame(self, codec: NomadCodec) -> None:
        """Create a complete encrypted data frame."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("test_key", 32)

        sync_message = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"hello",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,  # initiator -> responder
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Frame = Header (16) + Encrypted(Payload Header (10) + Sync Message) + Tag (16)
        expected_min_size = 16 + 10 + len(sync_message) + 16
        assert len(frame) == expected_min_size

        # Header should be plaintext
        assert frame[0] == FRAME_DATA
        assert frame[2:8] == session_id

    def test_data_frame_roundtrip(self, codec: NomadCodec) -> None:
        """Encode and decode a data frame."""
        session_id = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        key = codec.deterministic_bytes("roundtrip_key", 32)

        sync_message = encode_sync_message(
            sender_state_num=42,
            acked_state_num=41,
            base_state_num=40,
            diff=b"roundtrip test",
        )

        # Encode
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            timestamp=5000,
            timestamp_echo=4500,
            sync_message=sync_message,
        )

        # Decode
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        # Verify
        assert parsed.header.session_id == session_id
        assert parsed.header.nonce_counter == 100
        assert parsed.payload_header.timestamp == 5000
        assert parsed.payload_header.timestamp_echo == 4500
        assert parsed.sync_message.sender_state_num == 42
        assert parsed.sync_message.acked_state_num == 41
        assert parsed.sync_message.base_state_num == 40
        assert parsed.sync_message.diff == b"roundtrip test"

    def test_ack_only_data_frame(self, codec: NomadCodec) -> None:
        """Create ack-only data frame (keepalive)."""
        session_id = b"\x11\x22\x33\x44\x55\x66"
        key = codec.deterministic_bytes("keepalive_key", 32)

        # Ack-only: empty sync message
        sync_message = encode_sync_message(
            sender_state_num=10,
            acked_state_num=10,
            base_state_num=0,
            diff=b"",  # Empty diff
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=50,
            key=key,
            epoch=0,
            direction=1,  # responder -> initiator
            timestamp=10000,
            timestamp_echo=9500,
            sync_message=sync_message,
            flags=FLAG_ACK_ONLY,
        )

        # Verify ACK_ONLY flag is set
        assert frame[1] == FLAG_ACK_ONLY

        # Roundtrip
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=1,
        )

        assert parsed.header.flags == FLAG_ACK_ONLY
        assert parsed.sync_message.diff == b""


# =============================================================================
# Property-Based Tests (Hypothesis)
# =============================================================================


class TestPropertyBasedEncoding:
    """Property-based tests for encoding invariants."""

    @given(
        flags=st.integers(min_value=0, max_value=255),
        session_id=st.binary(min_size=SESSION_ID_SIZE, max_size=SESSION_ID_SIZE),
        nonce_counter=st.integers(min_value=0, max_value=2**64 - 1),
    )
    @settings(max_examples=100)
    def test_header_encode_length_invariant(
        self, flags: int, session_id: bytes, nonce_counter: int
    ) -> None:
        """Header is always exactly 16 bytes."""
        encoded = encode_data_frame_header(
            flags=flags,
            session_id=session_id,
            nonce_counter=nonce_counter,
        )
        assert len(encoded) == DATA_FRAME_HEADER_SIZE

    @given(
        timestamp=st.integers(min_value=0, max_value=2**32 - 1),
        timestamp_echo=st.integers(min_value=0, max_value=2**32 - 1),
        payload_length=st.integers(min_value=0, max_value=2**16 - 1),
    )
    @settings(max_examples=100)
    def test_payload_header_length_invariant(
        self, timestamp: int, timestamp_echo: int, payload_length: int
    ) -> None:
        """Payload header is always exactly 10 bytes."""
        encoded = encode_payload_header(
            timestamp=timestamp,
            timestamp_echo=timestamp_echo,
            payload_length=payload_length,
        )
        assert len(encoded) == 10

    @given(
        sender_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        acked_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        base_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        diff=st.binary(min_size=0, max_size=1024),
    )
    @settings(max_examples=50)
    def test_sync_message_length_invariant(
        self,
        sender_state_num: int,
        acked_state_num: int,
        base_state_num: int,
        diff: bytes,
    ) -> None:
        """Sync message is exactly 28 + len(diff) bytes."""
        encoded = encode_sync_message(
            sender_state_num=sender_state_num,
            acked_state_num=acked_state_num,
            base_state_num=base_state_num,
            diff=diff,
        )
        assert len(encoded) == 28 + len(diff)

    @given(
        session_id=st.binary(min_size=SESSION_ID_SIZE, max_size=SESSION_ID_SIZE),
        nonce_counter=st.integers(min_value=0, max_value=2**64 - 1),
        diff=st.binary(min_size=0, max_size=100),
    )
    @settings(max_examples=25)
    def test_data_frame_roundtrip_property(
        self, session_id: bytes, nonce_counter: int, diff: bytes
    ) -> None:
        """Any valid data frame can be round-tripped."""
        codec = NomadCodec()
        key = codec.deterministic_bytes("property_test", 32)

        sync_message = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=nonce_counter,
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

        assert parsed.header.session_id == session_id
        assert parsed.header.nonce_counter == nonce_counter
        assert parsed.sync_message.diff == diff
