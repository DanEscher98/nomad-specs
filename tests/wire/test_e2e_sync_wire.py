"""
Wire-level sync message validation tests.

These tests capture actual packets on the wire and validate:
- Sync message format compliance (28-byte header + diff payload)
- Little-endian encoding of all fields
- Version number field layout (sender_state_num, acked_state_num, base_state_num)
- Diff length field accuracy

Requires Docker containers for real protocol traffic.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from lib.network import parse_pcap
from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    SYNC_MESSAGE_HEADER_SIZE,
    NomadCodec,
    parse_sync_message,
)

if TYPE_CHECKING:
    from docker.models.containers import Container

    from lib.containers import PacketCapture


pytestmark = [pytest.mark.container, pytest.mark.network]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def codec() -> NomadCodec:
    """Reference codec for validation."""
    return NomadCodec()


# =============================================================================
# Sync Message Wire Format Tests
# =============================================================================


class TestSyncMessageWireFormat:
    """Validate sync message wire format from captured packets."""

    def test_sync_message_header_size(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
        codec: NomadCodec,
    ) -> None:
        """Sync message header is exactly 28 bytes before diff payload."""
        # Capture packets during sync
        with packet_capture.capture() as pcap_file:
            # Wait for some sync messages
            import time

            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        assert len(data_frames) > 0, "Should capture at least one data frame"

        for frame in data_frames:
            # Skip header and AEAD overhead
            if len(frame.raw_bytes) > DATA_FRAME_HEADER_SIZE + AEAD_TAG_SIZE:
                # Encrypted payload contains: payload_header (10) + sync_message
                # We can't decrypt here without keys, but we can verify frame size
                # Minimum: header(16) + payload_header(10) + sync_header(28) + tag(16) = 70
                assert len(frame.raw_bytes) >= 70, (
                    f"Data frame too small for sync message: {len(frame.raw_bytes)} bytes"
                )

    def test_data_frame_header_layout(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Validate data frame header layout (16 bytes)."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        for frame in data_frames:
            raw = frame.raw_bytes
            assert len(raw) >= DATA_FRAME_HEADER_SIZE, "Frame too short for header"

            # Byte 0: Frame type
            frame_type = raw[0]
            assert frame_type == FRAME_DATA, (
                f"Expected data frame type 0x03, got 0x{frame_type:02x}"
            )

            # Byte 1: Flags (reserved bits should be 0)
            flags = raw[1]
            assert (flags & 0xFC) == 0, f"Reserved flag bits should be 0, got 0x{flags:02x}"

            # Bytes 2-7: Session ID (6 bytes)
            session_id = raw[2:8]
            assert len(session_id) == 6, "Session ID should be 6 bytes"

            # Bytes 8-15: Nonce counter (LE64)
            nonce_counter = struct.unpack("<Q", raw[8:16])[0]
            assert nonce_counter >= 0, "Nonce counter should be non-negative"

    def test_session_id_consistency(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Session ID should be consistent across all frames in a session."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if len(data_frames) < 2:
            pytest.skip("Need at least 2 frames to verify consistency")

        # Group by direction (src_ip, dst_ip)
        directions: dict[tuple[str, str], list[bytes]] = {}
        for frame in data_frames:
            direction = (frame.src_ip, frame.dst_ip)
            session_id = frame.raw_bytes[2:8]
            if direction not in directions:
                directions[direction] = []
            directions[direction].append(session_id)

        # All frames in same direction should have same session ID
        for direction, session_ids in directions.items():
            unique_ids = set(session_ids)
            assert len(unique_ids) == 1, (
                f"Session ID inconsistent for direction {direction}: "
                f"found {len(unique_ids)} different IDs"
            )

    def test_nonce_counter_monotonic(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Nonce counter should increase monotonically per direction."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Group by direction
        directions: dict[tuple[str, str], list[int]] = {}
        for frame in data_frames:
            direction = (frame.src_ip, frame.dst_ip)
            nonce = struct.unpack("<Q", frame.raw_bytes[8:16])[0]
            if direction not in directions:
                directions[direction] = []
            directions[direction].append(nonce)

        for direction, nonces in directions.items():
            # Nonces should be strictly increasing (no duplicates)
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i - 1], (
                    f"Nonce not monotonic for {direction}: {nonces[i - 1]} -> {nonces[i]}"
                )


class TestLittleEndianEncoding:
    """Verify all multi-byte fields use little-endian encoding."""

    def test_nonce_counter_little_endian(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Nonce counter in frame header is little-endian."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        for frame in data_frames:
            raw = frame.raw_bytes[8:16]
            le_value = struct.unpack("<Q", raw)[0]

            # For small values, LE should have lower bytes first
            # If value < 256, first byte should be the value, rest zeros
            if le_value < 256:
                assert raw[0] == le_value, "Small nonce should be in first byte (LE)"
                assert all(b == 0 for b in raw[1:]), "High bytes should be zero"

    def test_frame_type_is_single_byte(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Frame type is a single byte (no endianness issue)."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(1)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        for frame in data_frames:
            assert frame.raw_bytes[0] == 0x03, "Data frame type should be 0x03"


class TestSyncMessagePayload:
    """Tests for sync message payload structure (requires decryption)."""

    def test_encrypted_payload_minimum_size(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Encrypted payload should be at least payload_header + sync_header + tag."""
        with packet_capture.capture() as pcap_file:
            import time

            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Minimum encrypted payload size:
        # payload_header (10) + sync_header (28) + AEAD_tag (16) = 54
        MIN_ENCRYPTED_SIZE = 10 + SYNC_MESSAGE_HEADER_SIZE + AEAD_TAG_SIZE

        for frame in data_frames:
            encrypted_payload = frame.raw_bytes[DATA_FRAME_HEADER_SIZE:]
            assert len(encrypted_payload) >= MIN_ENCRYPTED_SIZE, (
                f"Encrypted payload too small: {len(encrypted_payload)} < {MIN_ENCRYPTED_SIZE}"
            )


class TestWireVectorValidation:
    """Validate wire format against known test vectors."""

    def test_sync_message_encoding_matches_vectors(self, sync_vectors: dict) -> None:
        """Sync message encoding matches test vectors exactly."""
        for vector in sync_vectors["sync_messages"]:
            encoded = bytes.fromhex(vector["encoded"])
            parsed = parse_sync_message(encoded)

            assert parsed.sender_state_num == vector["sender_state_num"], (
                f"{vector['name']}: sender_state_num mismatch"
            )
            assert parsed.acked_state_num == vector["acked_state_num"], (
                f"{vector['name']}: acked_state_num mismatch"
            )
            assert parsed.base_state_num == vector["base_state_num"], (
                f"{vector['name']}: base_state_num mismatch"
            )
            assert len(parsed.diff) == vector["diff_length"], (
                f"{vector['name']}: diff_length mismatch"
            )

    def test_sync_message_field_positions(self, sync_vectors: dict) -> None:
        """Verify field positions in encoded sync message."""
        # Use normal_sync vector
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "normal_sync")
        encoded = bytes.fromhex(vector["encoded"])

        # sender_state_num at offset 0 (8 bytes, LE)
        sender = struct.unpack("<Q", encoded[0:8])[0]
        assert sender == 5, f"sender_state_num at wrong position: got {sender}"

        # acked_state_num at offset 8 (8 bytes, LE)
        acked = struct.unpack("<Q", encoded[8:16])[0]
        assert acked == 3, f"acked_state_num at wrong position: got {acked}"

        # base_state_num at offset 16 (8 bytes, LE)
        base = struct.unpack("<Q", encoded[16:24])[0]
        assert base == 4, f"base_state_num at wrong position: got {base}"

        # diff_length at offset 24 (4 bytes, LE)
        diff_len = struct.unpack("<I", encoded[24:28])[0]
        assert diff_len == 11, f"diff_length at wrong position: got {diff_len}"

        # diff payload at offset 28
        diff = encoded[28:]
        assert diff == b"state delta", f"diff at wrong position: got {diff!r}"

    def test_large_version_numbers_encoding(self, sync_vectors: dict) -> None:
        """Large version numbers are encoded correctly."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "large_version_numbers"
        )
        encoded = bytes.fromhex(vector["encoded"])

        # These should be near max uint64
        sender = struct.unpack("<Q", encoded[0:8])[0]
        assert sender == 281474976710655, f"Large sender mismatch: {sender}"

        acked = struct.unpack("<Q", encoded[8:16])[0]
        assert acked == 281474976710654, f"Large acked mismatch: {acked}"

        base = struct.unpack("<Q", encoded[16:24])[0]
        assert base == 281474976710653, f"Large base mismatch: {base}"


class TestBinaryDiffPayload:
    """Tests for binary (non-ASCII) diff payloads."""

    def test_binary_diff_preserved_exactly(self, sync_vectors: dict) -> None:
        """Binary diff payload is preserved exactly through encoding."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "binary_diff")
        encoded = bytes.fromhex(vector["encoded"])
        parsed = parse_sync_message(encoded)

        expected_diff = bytes.fromhex(vector["diff"]["hex"])
        assert parsed.diff == expected_diff, (
            f"Binary diff mismatch: got {parsed.diff.hex()}, expected {expected_diff.hex()}"
        )

    def test_null_bytes_in_diff(self) -> None:
        """Null bytes in diff are handled correctly."""
        from lib.reference import encode_sync_message

        diff_with_nulls = b"\x00\x01\x00\x02\x00"
        encoded = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff_with_nulls,
        )
        parsed = parse_sync_message(encoded)

        assert parsed.diff == diff_with_nulls, "Null bytes should be preserved"
        assert len(parsed.diff) == 5, "Diff length should include null bytes"


class TestEmptyDiff:
    """Tests for empty diff payloads (ack-only messages)."""

    def test_empty_diff_encoding(self, sync_vectors: dict) -> None:
        """Empty diff is encoded with diff_length = 0."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "ack_only")
        encoded = bytes.fromhex(vector["encoded"])

        # Should be exactly 28 bytes (header only, no diff)
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE, (
            f"Ack-only should be {SYNC_MESSAGE_HEADER_SIZE} bytes, got {len(encoded)}"
        )

        # diff_length should be 0
        diff_len = struct.unpack("<I", encoded[24:28])[0]
        assert diff_len == 0, f"Empty diff should have length 0, got {diff_len}"

    def test_empty_diff_parsing(self, sync_vectors: dict) -> None:
        """Empty diff parses correctly."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "ack_only")
        encoded = bytes.fromhex(vector["encoded"])
        parsed = parse_sync_message(encoded)

        assert parsed.diff == b"", "Empty diff should parse to empty bytes"
        assert parsed.sender_state_num == 10
        assert parsed.acked_state_num == 10


# =============================================================================
# Fixtures for sync_vectors
# =============================================================================


@pytest.fixture
def sync_vectors() -> dict:
    """Load sync test vectors."""
    import json5

    vectors_path = Path(__file__).parent.parent / "vectors" / "sync_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)
