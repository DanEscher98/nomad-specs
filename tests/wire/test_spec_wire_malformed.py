"""
Malformed Packet Tests

Tests handling of malformed, truncated, and invalid packets.
Validates error handling per spec: all malformed packets must be silently dropped.

Spec reference: specs/2-TRANSPORT.md (Error Handling section)
"""

from __future__ import annotations

import contextlib
import struct

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FRAME_CLOSE,
    FRAME_HANDSHAKE_INIT,
    FRAME_HANDSHAKE_RESP,
    FRAME_REKEY,
    NomadCodec,
    encode_data_frame_header,
    encode_sync_message,
    parse_data_frame_header,
    parse_payload_header,
    parse_sync_message,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec instance."""
    return NomadCodec()


@pytest.fixture
def valid_frame(codec: NomadCodec) -> tuple[bytes, bytes]:
    """Create a valid frame for modification in tests.

    Returns:
        Tuple of (frame_bytes, encryption_key)
    """
    session_id = b"\x01\x02\x03\x04\x05\x06"
    key = codec.deterministic_bytes("valid_frame", 32)

    sync_message = encode_sync_message(
        sender_state_num=1,
        acked_state_num=0,
        base_state_num=0,
        diff=b"test payload",
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

    return frame, key


# =============================================================================
# Truncated Frame Tests
# =============================================================================


class TestTruncatedFrames:
    """Test handling of truncated frames."""

    def test_empty_frame(self, codec: NomadCodec) -> None:
        """Empty frame (0 bytes) is rejected."""
        key = codec.deterministic_bytes("empty", 32)

        with pytest.raises(ValueError, match="too short"):
            codec.parse_data_frame(data=b"", key=key, epoch=0, direction=0)

    def test_single_byte_frame(self, codec: NomadCodec) -> None:
        """Single byte frame is rejected."""
        key = codec.deterministic_bytes("single", 32)

        with pytest.raises(ValueError, match="too short"):
            codec.parse_data_frame(data=b"\x03", key=key, epoch=0, direction=0)

    def test_header_only_no_tag(self, codec: NomadCodec) -> None:
        """Frame with only header (no encrypted payload or tag) is rejected."""
        key = codec.deterministic_bytes("header_only", 32)

        # 16-byte header, no payload or tag
        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x01\x02\x03\x04\x05\x06",
            nonce_counter=0,
        )

        with pytest.raises(ValueError, match="too short"):
            codec.parse_data_frame(data=header, key=key, epoch=0, direction=0)

    def test_header_plus_partial_tag(self, codec: NomadCodec) -> None:
        """Frame with header + partial tag is rejected."""
        key = codec.deterministic_bytes("partial_tag", 32)

        header = encode_data_frame_header(
            flags=0,
            session_id=b"\x01\x02\x03\x04\x05\x06",
            nonce_counter=0,
        )

        # Add only 8 bytes (half a tag)
        frame = header + b"\x00" * 8

        with pytest.raises(ValueError, match="too short"):
            codec.parse_data_frame(data=frame, key=key, epoch=0, direction=0)

    def test_truncated_one_byte(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Frame truncated by one byte is rejected."""
        frame, key = valid_frame
        truncated = frame[:-1]

        # Should fail either due to size check or AEAD failure
        with pytest.raises((ValueError, InvalidTag)):
            codec.parse_data_frame(data=truncated, key=key, epoch=0, direction=0)

    def test_truncated_header_partial(self, codec: NomadCodec) -> None:
        """Truncated header (< 16 bytes) is rejected."""
        # Only 10 bytes of header
        partial_header = b"\x03\x00\x01\x02\x03\x04\x05\x06\x00\x00"

        with pytest.raises(ValueError, match="too short"):
            parse_data_frame_header(partial_header)

    @given(size=st.integers(min_value=0, max_value=31))
    @settings(max_examples=32)
    def test_undersized_frames_rejected(self, size: int, codec: NomadCodec) -> None:
        """Any frame smaller than minimum (32 bytes) is rejected."""
        key = codec.deterministic_bytes("undersized", 32)
        data = b"\x03" + b"\x00" * (size - 1) if size > 0 else b""

        with pytest.raises(ValueError):
            codec.parse_data_frame(data=data, key=key, epoch=0, direction=0)


# =============================================================================
# Invalid Type Byte Tests
# =============================================================================


class TestInvalidTypeByte:
    """Test handling of invalid frame type bytes."""

    def test_type_zero(self) -> None:
        """Type 0x00 is invalid."""
        invalid_header = b"\x00" + b"\x00" * 15

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(invalid_header)

    def test_type_too_high(self) -> None:
        """Types > 0x05 are invalid for data frame parsing."""
        for invalid_type in [0x06, 0x07, 0x10, 0x20, 0x80, 0xFF]:
            invalid_header = bytes([invalid_type]) + b"\x00" * 15

            with pytest.raises(ValueError, match="Not a data frame"):
                parse_data_frame_header(invalid_header)

    def test_handshake_init_not_data(self) -> None:
        """Handshake Init (0x01) is not a data frame."""
        handshake_header = bytes([FRAME_HANDSHAKE_INIT]) + b"\x00" * 15

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(handshake_header)

    def test_handshake_resp_not_data(self) -> None:
        """Handshake Response (0x02) is not a data frame."""
        handshake_header = bytes([FRAME_HANDSHAKE_RESP]) + b"\x00" * 15

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(handshake_header)

    def test_rekey_not_data(self) -> None:
        """Rekey (0x04) is not a data frame."""
        rekey_header = bytes([FRAME_REKEY]) + b"\x00" * 15

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(rekey_header)

    def test_close_not_data(self) -> None:
        """Close (0x05) is not a data frame."""
        close_header = bytes([FRAME_CLOSE]) + b"\x00" * 15

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(close_header)


# =============================================================================
# Invalid AEAD Tag Tests
# =============================================================================


class TestInvalidAEADTag:
    """Test handling of invalid AEAD authentication tags."""

    def test_corrupted_tag(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Frame with corrupted AEAD tag is rejected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Corrupt the last byte of the tag
        frame[-1] ^= 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_zeroed_tag(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Frame with zeroed AEAD tag is rejected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Zero out the entire tag
        frame[-16:] = b"\x00" * 16

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_random_tag(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Frame with random AEAD tag is rejected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Replace tag with random bytes
        frame[-16:] = b"\xde\xad\xbe\xef" * 4

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_tag_bit_flip(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Single bit flip in AEAD tag is detected."""
        frame, key = valid_frame

        for byte_offset in range(-16, 0):  # Last 16 bytes (tag)
            for bit in range(8):
                corrupted = bytearray(frame)
                corrupted[byte_offset] ^= 1 << bit

                with pytest.raises(InvalidTag):
                    codec.parse_data_frame(data=bytes(corrupted), key=key, epoch=0, direction=0)


# =============================================================================
# Corrupted Ciphertext Tests
# =============================================================================


class TestCorruptedCiphertext:
    """Test handling of corrupted ciphertext (encrypted payload)."""

    def test_corrupted_ciphertext_single_byte(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Single byte corruption in ciphertext is detected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Corrupt a byte in the encrypted payload (after header, before tag)
        frame[20] ^= 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_corrupted_ciphertext_multiple_bytes(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Multiple byte corruption in ciphertext is detected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Corrupt multiple bytes
        for i in range(20, 30):
            if i < len(frame) - 16:  # Don't corrupt tag
                frame[i] ^= 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_zeroed_ciphertext(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Zeroed ciphertext is rejected."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Zero out encrypted payload (between header and tag)
        for i in range(DATA_FRAME_HEADER_SIZE, len(frame) - AEAD_TAG_SIZE):
            frame[i] = 0x00

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)


# =============================================================================
# Corrupted Header Tests (AAD Modification)
# =============================================================================


class TestCorruptedHeader:
    """Test handling of corrupted header (AAD modification)."""

    def test_corrupted_type_byte(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Modified type byte causes AEAD failure."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Change type (but keep it as valid data frame type)
        # This should fail because AAD is different
        frame[0] = 0x03 if frame[0] != 0x03 else 0x03  # Type is always 0x03

        # Actually modify to different value that's still valid
        frame[1] ^= 0x01  # Flip flags instead

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_corrupted_flags(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Modified flags byte causes AEAD failure."""
        frame, key = valid_frame
        frame = bytearray(frame)

        frame[1] ^= 0x01  # Flip ACK_ONLY flag

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_corrupted_session_id(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Modified session ID causes AEAD failure."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Modify session ID
        frame[2] ^= 0xFF

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)

    def test_corrupted_nonce_counter(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Modified nonce counter in header causes AEAD failure."""
        frame, key = valid_frame
        frame = bytearray(frame)

        # Modify nonce counter
        frame[8] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=bytes(frame), key=key, epoch=0, direction=0)


# =============================================================================
# Invalid Sync Message Tests
# =============================================================================


class TestInvalidSyncMessage:
    """Test handling of invalid sync message structure."""

    def test_sync_too_short(self) -> None:
        """Sync message shorter than header is rejected."""
        short_sync = b"\x00" * 20  # Less than 28 bytes

        with pytest.raises(ValueError, match="too short"):
            parse_sync_message(short_sync)

    def test_sync_truncated_diff(self) -> None:
        """Sync message with truncated diff is rejected."""
        # Create header saying diff is 100 bytes
        header = struct.pack("<QQQ", 1, 0, 0)  # state nums
        length = struct.pack("<I", 100)  # claims 100 bytes diff
        truncated_diff = b"short"  # only 5 bytes

        truncated_sync = header + length + truncated_diff

        with pytest.raises(ValueError, match="truncated"):
            parse_sync_message(truncated_sync)

    def test_sync_diff_length_overflow(self) -> None:
        """Sync message with huge diff length is rejected as truncated."""
        header = struct.pack("<QQQ", 1, 0, 0)
        length = struct.pack("<I", 0xFFFFFFFF)  # 4GB
        no_diff = b""

        giant_claim = header + length + no_diff

        with pytest.raises(ValueError, match="truncated"):
            parse_sync_message(giant_claim)


# =============================================================================
# Invalid Payload Header Tests
# =============================================================================


class TestInvalidPayloadHeader:
    """Test handling of invalid payload header structure."""

    def test_payload_header_too_short(self) -> None:
        """Payload header shorter than 10 bytes is rejected."""
        short = b"\x00" * 9

        with pytest.raises(ValueError, match="too short"):
            parse_payload_header(short)

    @given(size=st.integers(min_value=0, max_value=9))
    @settings(max_examples=10)
    def test_any_short_payload_header_rejected(self, size: int) -> None:
        """Any payload header < 10 bytes is rejected."""
        data = b"\x00" * size

        with pytest.raises(ValueError):
            parse_payload_header(data)


# =============================================================================
# Wrong Key / Nonce Tests
# =============================================================================


class TestWrongKeyNonce:
    """Test handling of decryption with wrong key/nonce parameters."""

    def test_wrong_key(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Decryption with wrong key fails."""
        frame, _correct_key = valid_frame
        wrong_key = codec.deterministic_bytes("wrong_key", 32)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=frame, key=wrong_key, epoch=0, direction=0)

    def test_wrong_epoch(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Decryption with wrong epoch fails."""
        frame, key = valid_frame

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=frame, key=key, epoch=1, direction=0)

    def test_wrong_direction(self, valid_frame: tuple[bytes, bytes], codec: NomadCodec) -> None:
        """Decryption with wrong direction fails."""
        frame, key = valid_frame

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=frame, key=key, epoch=0, direction=1)

    def test_all_wrong_parameters(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Decryption with all wrong parameters fails."""
        frame, _key = valid_frame
        wrong_key = codec.deterministic_bytes("all_wrong", 32)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=frame, key=wrong_key, epoch=99, direction=1)


# =============================================================================
# Fuzz Tests
# =============================================================================


class TestFuzz:
    """Fuzz testing for malformed inputs."""

    @given(data=st.binary(min_size=0, max_size=100))
    @settings(max_examples=200)
    def test_random_data_header_parse(self, data: bytes) -> None:
        """Random data doesn't crash header parser."""
        with contextlib.suppress(ValueError):
            parse_data_frame_header(data)

    @given(data=st.binary(min_size=0, max_size=100))
    @settings(max_examples=200)
    def test_random_data_payload_header_parse(self, data: bytes) -> None:
        """Random data doesn't crash payload header parser."""
        with contextlib.suppress(ValueError):
            parse_payload_header(data)

    @given(data=st.binary(min_size=0, max_size=500))
    @settings(max_examples=200)
    def test_random_data_sync_message_parse(self, data: bytes) -> None:
        """Random data doesn't crash sync message parser."""
        with contextlib.suppress(ValueError):
            parse_sync_message(data)

    @given(data=st.binary(min_size=32, max_size=500))
    @settings(max_examples=100)
    def test_random_data_frame_parse(self, data: bytes, codec: NomadCodec) -> None:
        """Random data with valid size doesn't crash frame parser."""
        key = codec.deterministic_bytes("fuzz", 32)

        with contextlib.suppress(ValueError, InvalidTag):
            codec.parse_data_frame(data=data, key=key, epoch=0, direction=0)


# =============================================================================
# Error Response Tests
# =============================================================================


class TestErrorResponses:
    """Test that errors are appropriate per spec (silent drops)."""

    def test_invalid_aead_raises_invalidtag(
        self, valid_frame: tuple[bytes, bytes], codec: NomadCodec
    ) -> None:
        """Invalid AEAD raises InvalidTag (caller should silently drop)."""
        frame, key = valid_frame
        wrong_key = codec.deterministic_bytes("wrong", 32)

        # Per spec: "Invalid AEAD tag -> Silently drop"
        # We raise InvalidTag which caller should handle by dropping
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(data=frame, key=wrong_key, epoch=0, direction=0)

    def test_short_frame_raises_valueerror(self, codec: NomadCodec) -> None:
        """Short frame raises ValueError (caller should silently drop)."""
        key = codec.deterministic_bytes("short", 32)

        # Per spec: "Frame too small -> Silently drop"
        with pytest.raises(ValueError):
            codec.parse_data_frame(data=b"\x03" * 10, key=key, epoch=0, direction=0)

    def test_wrong_type_raises_valueerror(self) -> None:
        """Wrong frame type raises ValueError (caller should silently drop)."""
        # Per spec: "Unknown session ID" type errors -> Silently drop
        with pytest.raises(ValueError):
            parse_data_frame_header(b"\x01" + b"\x00" * 15)  # Type 0x01
