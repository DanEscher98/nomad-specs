"""
Frame Decoding Tests

Tests frame decoding/parsing against test vectors and validates error handling
for malformed inputs.

Spec reference: specs/2-TRANSPORT.md
"""

from __future__ import annotations

from pathlib import Path

import json5
import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    FLAG_ACK_ONLY,
    FRAME_DATA,
    SESSION_ID_SIZE,
    SYNC_MESSAGE_HEADER_SIZE,
    DataFrameHeader,
    NomadCodec,
    PayloadHeader,
    SyncMessage,
    encode_data_frame_header,
    encode_payload_header,
    encode_sync_message,
    parse_data_frame_header,
    parse_payload_header,
    parse_sync_message,
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
# Data Frame Header Parsing Tests
# =============================================================================


class TestDataFrameHeaderParse:
    """Test data frame header parsing."""

    def test_parse_basic_header(self, frame_vectors: dict) -> None:
        """Parse basic data frame header from vector."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "basic_data_frame"
        )

        encoded = bytes.fromhex(vector["encoded"])
        header = parse_data_frame_header(encoded)

        assert header.frame_type == vector["frame_type"]
        assert header.flags == vector["flags"]
        assert header.session_id == bytes.fromhex(vector["session_id"])
        assert header.nonce_counter == vector["nonce_counter"]

    def test_parse_ack_only_header(self, frame_vectors: dict) -> None:
        """Parse ack-only data frame header."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "ack_only_frame"
        )

        encoded = bytes.fromhex(vector["encoded"])
        header = parse_data_frame_header(encoded)

        assert header.frame_type == FRAME_DATA
        assert header.flags == FLAG_ACK_ONLY
        assert header.nonce_counter == 42

    def test_parse_extension_flag_header(self, frame_vectors: dict) -> None:
        """Parse header with extension flag."""
        vector = next(
            v for v in frame_vectors["data_frame_headers"] if v["name"] == "with_extension_flag"
        )

        encoded = bytes.fromhex(vector["encoded"])
        header = parse_data_frame_header(encoded)

        assert header.flags == 2  # HAS_EXTENSION
        assert header.nonce_counter == 1000

    def test_header_returns_dataclass(self, frame_vectors: dict) -> None:
        """Parsed header is a DataFrameHeader dataclass."""
        vector = frame_vectors["data_frame_headers"][0]
        encoded = bytes.fromhex(vector["encoded"])

        header = parse_data_frame_header(encoded)

        assert isinstance(header, DataFrameHeader)
        assert hasattr(header, "frame_type")
        assert hasattr(header, "flags")
        assert hasattr(header, "session_id")
        assert hasattr(header, "nonce_counter")

    def test_parse_header_with_extra_data(self) -> None:
        """Parse header when buffer contains extra data (full frame)."""
        # Header + some extra data simulating rest of frame
        header_data = bytes.fromhex("03000102030405060000000000000000")
        extra_data = b"\xAA\xBB\xCC\xDD"  # Extra bytes (encrypted payload start)

        full_buffer = header_data + extra_data
        header = parse_data_frame_header(full_buffer)

        # Should parse only the first 16 bytes
        assert header.session_id == b"\x01\x02\x03\x04\x05\x06"

    def test_parse_header_too_short(self) -> None:
        """Reject headers shorter than 16 bytes."""
        with pytest.raises(ValueError, match="too short"):
            parse_data_frame_header(b"\x03\x00" + b"\x00" * 10)  # 12 bytes

    def test_parse_header_wrong_type(self) -> None:
        """Reject non-data frame types."""
        # Type 0x01 (Handshake Init) instead of 0x03 (Data)
        invalid_type = b"\x01\x00" + b"\x00" * 14
        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(invalid_type)


# =============================================================================
# Payload Header Parsing Tests
# =============================================================================


class TestPayloadHeaderParse:
    """Test encrypted payload header parsing."""

    def test_parse_payload_header(self) -> None:
        """Parse payload header."""
        # timestamp=1000, timestamp_echo=500, payload_length=100
        # Little-endian encoded
        data = bytes([
            0xE8, 0x03, 0x00, 0x00,  # timestamp = 1000
            0xF4, 0x01, 0x00, 0x00,  # timestamp_echo = 500
            0x64, 0x00,              # payload_length = 100
        ])

        header = parse_payload_header(data)

        assert header.timestamp == 1000
        assert header.timestamp_echo == 500
        assert header.payload_length == 100

    def test_parse_payload_header_returns_dataclass(self) -> None:
        """Parsed payload header is a PayloadHeader dataclass."""
        data = b"\x00" * 10

        header = parse_payload_header(data)

        assert isinstance(header, PayloadHeader)
        assert hasattr(header, "timestamp")
        assert hasattr(header, "timestamp_echo")
        assert hasattr(header, "payload_length")

    def test_parse_payload_header_too_short(self) -> None:
        """Reject payload headers shorter than 10 bytes."""
        with pytest.raises(ValueError, match="too short"):
            parse_payload_header(b"\x00" * 9)

    def test_parse_payload_header_with_extra_data(self) -> None:
        """Parse payload header when buffer contains sync message."""
        header_data = b"\x00" * 10
        sync_data = b"sync message data..."

        full_buffer = header_data + sync_data
        header = parse_payload_header(full_buffer)

        # Should parse only the first 10 bytes
        assert header.timestamp == 0


# =============================================================================
# Sync Message Parsing Tests
# =============================================================================


class TestSyncMessageParse:
    """Test sync message parsing."""

    def test_parse_basic_sync(self, frame_vectors: dict) -> None:
        """Parse basic sync message from vector."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "basic_sync"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == vector["sender_state_num"]
        assert msg.acked_state_num == vector["acked_state_num"]
        assert msg.base_state_num == vector["base_state_num"]
        assert msg.diff == bytes.fromhex(vector["diff"])

    def test_parse_ack_only_sync(self, frame_vectors: dict) -> None:
        """Parse ack-only sync message (empty diff)."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "ack_only_sync"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.diff == b""
        assert len(msg.diff) == vector["diff_length"]

    def test_parse_initial_sync(self, frame_vectors: dict) -> None:
        """Parse initial sync message."""
        vector = next(
            v for v in frame_vectors["sync_messages"] if v["name"] == "initial_sync"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == 1
        assert msg.acked_state_num == 0
        assert msg.base_state_num == 0
        assert msg.diff == b"initial"

    def test_sync_message_returns_dataclass(self, frame_vectors: dict) -> None:
        """Parsed sync message is a SyncMessage dataclass."""
        vector = frame_vectors["sync_messages"][0]
        encoded = bytes.fromhex(vector["encoded"])

        msg = parse_sync_message(encoded)

        assert isinstance(msg, SyncMessage)
        assert hasattr(msg, "sender_state_num")
        assert hasattr(msg, "acked_state_num")
        assert hasattr(msg, "base_state_num")
        assert hasattr(msg, "diff")

    def test_parse_sync_message_too_short(self) -> None:
        """Reject sync messages shorter than header."""
        with pytest.raises(ValueError, match="too short"):
            parse_sync_message(b"\x00" * (SYNC_MESSAGE_HEADER_SIZE - 1))

    def test_parse_sync_message_truncated_diff(self) -> None:
        """Reject sync messages with truncated diff payload."""
        # Header says diff is 100 bytes, but only 5 are present
        header = b"\x01\x00\x00\x00\x00\x00\x00\x00"  # sender_state_num = 1
        header += b"\x00" * 8  # acked_state_num = 0
        header += b"\x00" * 8  # base_state_num = 0
        header += b"\x64\x00\x00\x00"  # diff_length = 100
        header += b"short"  # Only 5 bytes of diff

        with pytest.raises(ValueError, match="truncated"):
            parse_sync_message(header)


# =============================================================================
# Complete Data Frame Parsing Tests
# =============================================================================


class TestCompleteDataFrameParse:
    """Test complete data frame parsing (decryption + parsing)."""

    def test_parse_valid_frame(self, codec: NomadCodec) -> None:
        """Parse a valid encrypted data frame."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("test_key", 32)

        sync_message = encode_sync_message(
            sender_state_num=5,
            acked_state_num=4,
            base_state_num=4,
            diff=b"hello",
        )

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=500,
            sync_message=sync_message,
        )

        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        assert parsed.header.session_id == session_id
        assert parsed.header.nonce_counter == 0
        assert parsed.payload_header.timestamp == 1000
        assert parsed.payload_header.timestamp_echo == 500
        assert parsed.sync_message.sender_state_num == 5
        assert parsed.sync_message.diff == b"hello"

    def test_parse_frame_wrong_key(self, codec: NomadCodec) -> None:
        """Reject frame encrypted with different key."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        encrypt_key = codec.deterministic_bytes("encrypt_key", 32)
        wrong_key = codec.deterministic_bytes("wrong_key", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=encrypt_key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=frame,
                key=wrong_key,
                epoch=0,
                direction=0,
            )

    def test_parse_frame_wrong_epoch(self, codec: NomadCodec) -> None:
        """Reject frame with wrong epoch in nonce."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("epoch_key", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,  # Encrypted with epoch 0
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=frame,
                key=key,
                epoch=1,  # Try to decrypt with epoch 1
                direction=0,
            )

    def test_parse_frame_wrong_direction(self, codec: NomadCodec) -> None:
        """Reject frame with wrong direction in nonce."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("direction_key", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,  # initiator -> responder
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=frame,
                key=key,
                epoch=0,
                direction=1,  # Try with responder -> initiator
            )

    def test_parse_frame_too_short(self, codec: NomadCodec) -> None:
        """Reject frames shorter than minimum size."""
        # Minimum: 16 (header) + 16 (tag) = 32 bytes
        short_frame = b"\x03\x00" + b"\x00" * 28  # 30 bytes

        key = codec.deterministic_bytes("short_key", 32)

        with pytest.raises(ValueError, match="too short"):
            codec.parse_data_frame(
                data=short_frame,
                key=key,
                epoch=0,
                direction=0,
            )

    def test_parse_frame_tampered_header(self, codec: NomadCodec) -> None:
        """Reject frame with tampered header (AAD verification fails)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("tamper_key", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        ))

        # Tamper with session ID in header
        frame[2] = 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=bytes(frame),
                key=key,
                epoch=0,
                direction=0,
            )

    def test_parse_frame_tampered_ciphertext(self, codec: NomadCodec) -> None:
        """Reject frame with tampered ciphertext."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("tamper2_key", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        ))

        # Tamper with encrypted payload (after header, before tag)
        frame[20] ^= 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=bytes(frame),
                key=key,
                epoch=0,
                direction=0,
            )


# =============================================================================
# Property-Based Tests (Hypothesis)
# =============================================================================


class TestPropertyBasedParsing:
    """Property-based tests for parsing invariants."""

    @given(
        flags=st.integers(min_value=0, max_value=255),
        session_id=st.binary(min_size=SESSION_ID_SIZE, max_size=SESSION_ID_SIZE),
        nonce_counter=st.integers(min_value=0, max_value=2**64 - 1),
    )
    @settings(max_examples=100)
    def test_header_roundtrip(
        self, flags: int, session_id: bytes, nonce_counter: int
    ) -> None:
        """Encode -> Parse preserves all header fields."""
        encoded = encode_data_frame_header(
            flags=flags,
            session_id=session_id,
            nonce_counter=nonce_counter,
        )

        parsed = parse_data_frame_header(encoded)

        assert parsed.frame_type == FRAME_DATA
        assert parsed.flags == flags
        assert parsed.session_id == session_id
        assert parsed.nonce_counter == nonce_counter

    @given(
        timestamp=st.integers(min_value=0, max_value=2**32 - 1),
        timestamp_echo=st.integers(min_value=0, max_value=2**32 - 1),
        payload_length=st.integers(min_value=0, max_value=2**16 - 1),
    )
    @settings(max_examples=100)
    def test_payload_header_roundtrip(
        self, timestamp: int, timestamp_echo: int, payload_length: int
    ) -> None:
        """Encode -> Parse preserves all payload header fields."""
        encoded = encode_payload_header(
            timestamp=timestamp,
            timestamp_echo=timestamp_echo,
            payload_length=payload_length,
        )

        parsed = parse_payload_header(encoded)

        assert parsed.timestamp == timestamp
        assert parsed.timestamp_echo == timestamp_echo
        assert parsed.payload_length == payload_length

    @given(
        sender_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        acked_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        base_state_num=st.integers(min_value=0, max_value=2**64 - 1),
        diff=st.binary(min_size=0, max_size=500),
    )
    @settings(max_examples=50)
    def test_sync_message_roundtrip(
        self,
        sender_state_num: int,
        acked_state_num: int,
        base_state_num: int,
        diff: bytes,
    ) -> None:
        """Encode -> Parse preserves all sync message fields."""
        encoded = encode_sync_message(
            sender_state_num=sender_state_num,
            acked_state_num=acked_state_num,
            base_state_num=base_state_num,
            diff=diff,
        )

        parsed = parse_sync_message(encoded)

        assert parsed.sender_state_num == sender_state_num
        assert parsed.acked_state_num == acked_state_num
        assert parsed.base_state_num == base_state_num
        assert parsed.diff == diff

    @given(data=st.binary(min_size=0, max_size=15))
    def test_short_header_rejected(self, data: bytes) -> None:
        """Any data shorter than 16 bytes is rejected as header."""
        with pytest.raises(ValueError):
            parse_data_frame_header(data)

    @given(data=st.binary(min_size=0, max_size=9))
    def test_short_payload_header_rejected(self, data: bytes) -> None:
        """Any data shorter than 10 bytes is rejected as payload header."""
        with pytest.raises(ValueError):
            parse_payload_header(data)

    @given(data=st.binary(min_size=0, max_size=27))
    def test_short_sync_message_rejected(self, data: bytes) -> None:
        """Any data shorter than 28 bytes is rejected as sync message."""
        with pytest.raises(ValueError):
            parse_sync_message(data)
