"""
Unit tests for sync message diff encoding.

Tests the encoding of sync messages (diffs) against canonical test vectors.
These tests validate that implementations correctly serialize:
- Version numbers (sender, acked, base)
- Diff length
- Diff payload

Reference: specs/3-SYNC.md
"""

from __future__ import annotations

from pathlib import Path

import json5
import pytest

from lib.reference import (
    SYNC_MESSAGE_HEADER_SIZE,
    NomadCodec,
    encode_sync_message,
)

# Path to test vectors
VECTORS_DIR = Path(__file__).parent.parent / "vectors"


@pytest.fixture(scope="module")
def sync_vectors() -> dict:
    """Load sync test vectors."""
    with open(VECTORS_DIR / "sync_vectors.json5") as f:
        return json5.load(f)


# =============================================================================
# Basic Encoding Tests
# =============================================================================


class TestSyncMessageEncoding:
    """Tests for sync message encoding against test vectors."""

    def test_initial_state_encoding(self, sync_vectors: dict) -> None:
        """Test encoding of initial state message (first sync from initiator)."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "initial_state"
        )

        diff = bytes.fromhex(vector["diff"]["hex"])
        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected
        assert len(result) == vector["encoded_length"]

    def test_normal_sync_encoding(self, sync_vectors: dict) -> None:
        """Test encoding of normal sync message with ack and diff."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "normal_sync"
        )

        diff = bytes.fromhex(vector["diff"]["hex"])
        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected

    def test_ack_only_encoding(self, sync_vectors: dict) -> None:
        """Test encoding of ack-only message (no state change)."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "ack_only"
        )

        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=b"",
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected
        # Ack-only should be exactly header size (28 bytes)
        assert len(result) == SYNC_MESSAGE_HEADER_SIZE
        assert len(result) == vector["encoded_length"]

    def test_large_version_numbers_encoding(self, sync_vectors: dict) -> None:
        """Test encoding with large version numbers (near max uint64)."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "large_version_numbers"
        )

        diff = bytes.fromhex(vector["diff"]["hex"])
        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected

    def test_binary_diff_encoding(self, sync_vectors: dict) -> None:
        """Test encoding with binary (non-ASCII) diff payload."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "binary_diff"
        )

        diff = bytes.fromhex(vector["diff"]["hex"])
        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected

    def test_empty_initial_encoding(self, sync_vectors: dict) -> None:
        """Test encoding of empty initial state."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "empty_initial"
        )

        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=b"",
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected

    def test_retransmit_scenario_encoding(self, sync_vectors: dict) -> None:
        """Test encoding of retransmit message (ack moved forward)."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "retransmit_scenario"
        )

        diff = bytes.fromhex(vector["diff"]["hex"])
        result = encode_sync_message(
            sender_state_num=vector["sender_state_num"],
            acked_state_num=vector["acked_state_num"],
            base_state_num=vector["base_state_num"],
            diff=diff,
        )

        expected = bytes.fromhex(vector["encoded"])
        assert result == expected

    def test_all_sync_vectors(self, sync_vectors: dict) -> None:
        """Test encoding against all sync message vectors."""
        for vector in sync_vectors["sync_messages"]:
            diff_hex = vector["diff"]["hex"]
            diff = bytes.fromhex(diff_hex) if diff_hex else b""

            result = encode_sync_message(
                sender_state_num=vector["sender_state_num"],
                acked_state_num=vector["acked_state_num"],
                base_state_num=vector["base_state_num"],
                diff=diff,
            )

            expected = bytes.fromhex(vector["encoded"])
            assert result == expected, f"Failed for vector: {vector['name']}"
            assert len(result) == vector["encoded_length"], f"Wrong length for: {vector['name']}"


# =============================================================================
# Structure Tests
# =============================================================================


class TestSyncMessageStructure:
    """Tests for sync message wire format structure."""

    def test_header_size(self) -> None:
        """Test that sync message header is exactly 28 bytes."""
        # Header: 3 * uint64 (24 bytes) + uint32 (4 bytes) = 28 bytes
        assert SYNC_MESSAGE_HEADER_SIZE == 28

    def test_little_endian_encoding(self) -> None:
        """Test that version numbers are encoded in little-endian."""
        result = encode_sync_message(
            sender_state_num=0x0102030405060708,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )

        # First 8 bytes should be sender_state_num in little-endian
        # 0x0102030405060708 in LE = 08 07 06 05 04 03 02 01
        assert result[0:8] == bytes([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])

    def test_diff_length_field(self) -> None:
        """Test that diff length is correctly encoded."""
        diff = b"test payload"
        result = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        # Diff length is at bytes 24-27 (after 3 * uint64)
        # Length = 12 in LE32 = 0c 00 00 00
        import struct

        diff_len = struct.unpack_from("<I", result, 24)[0]
        assert diff_len == len(diff)

    def test_diff_payload_position(self) -> None:
        """Test that diff payload starts at correct offset."""
        diff = b"payload"
        result = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        # Diff starts at byte 28 (after header)
        assert result[SYNC_MESSAGE_HEADER_SIZE:] == diff

    def test_total_length(self) -> None:
        """Test total message length calculation."""
        diff = b"x" * 100
        result = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        assert len(result) == SYNC_MESSAGE_HEADER_SIZE + len(diff)


# =============================================================================
# Convergence Scenario Encoding Tests
# =============================================================================


class TestConvergenceScenarioEncoding:
    """Tests for convergence scenario message encoding."""

    def test_normal_convergence_messages(self, sync_vectors: dict) -> None:
        """Test encoding of messages in normal convergence scenario."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"]
            if s["name"] == "normal_convergence"
        )

        for msg in scenario["messages"]:
            diff = msg["diff_ascii"].encode("utf-8")
            result = encode_sync_message(
                sender_state_num=msg["sender_state_num"],
                acked_state_num=msg["acked_state_num"],
                base_state_num=msg["base_state_num"],
                diff=diff,
            )

            expected = bytes.fromhex(msg["encoded"])
            assert result == expected, f"Failed for direction {msg['direction']}"

    def test_packet_loss_recovery_messages(self, sync_vectors: dict) -> None:
        """Test encoding of messages in packet loss recovery scenario."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"]
            if s["name"] == "packet_loss_recovery"
        )

        for msg in scenario["messages"]:
            diff = msg["diff_ascii"].encode("utf-8")
            result = encode_sync_message(
                sender_state_num=msg["sender_state_num"],
                acked_state_num=msg["acked_state_num"],
                base_state_num=msg["base_state_num"],
                diff=diff,
            )

            expected = bytes.fromhex(msg["encoded"])
            assert result == expected, (
                f"Failed for {msg['direction']} (status: {msg.get('status', 'unknown')})"
            )


# =============================================================================
# Codec Class Encoding Tests
# =============================================================================


class TestCodecEncoding:
    """Tests for NomadCodec sync message encoding."""

    def test_codec_create_sync_message(self, sync_vectors: dict) -> None:
        """Test NomadCodec.create_sync_message() against vectors."""
        codec = NomadCodec()

        for vector in sync_vectors["sync_messages"]:
            diff_hex = vector["diff"]["hex"]
            diff = bytes.fromhex(diff_hex) if diff_hex else b""

            result = codec.create_sync_message(
                sender_state_num=vector["sender_state_num"],
                acked_state_num=vector["acked_state_num"],
                base_state_num=vector["base_state_num"],
                diff=diff,
            )

            expected = bytes.fromhex(vector["encoded"])
            assert result == expected, f"Codec failed for vector: {vector['name']}"

    def test_codec_vs_function(self) -> None:
        """Test that NomadCodec.create_sync_message matches encode_sync_message."""
        codec = NomadCodec()

        for sender in [1, 100, 281474976710655]:
            for acked in [0, 50, 100]:
                for base in [0, 99]:
                    for diff in [b"", b"test", b"\x00\xff\xde\xad"]:
                        func_result = encode_sync_message(sender, acked, base, diff)
                        codec_result = codec.create_sync_message(sender, acked, base, diff)
                        assert func_result == codec_result


# =============================================================================
# Edge Case Encoding Tests
# =============================================================================


class TestEncodingEdgeCases:
    """Tests for edge cases in sync message encoding."""

    def test_zero_version_numbers(self) -> None:
        """Test encoding with all zero version numbers."""
        result = encode_sync_message(
            sender_state_num=0,
            acked_state_num=0,
            base_state_num=0,
            diff=b"",
        )

        # All zeros except header structure
        assert result == b"\x00" * SYNC_MESSAGE_HEADER_SIZE

    def test_max_uint64_version(self) -> None:
        """Test encoding with maximum uint64 version number."""
        max_uint64 = (1 << 64) - 1
        result = encode_sync_message(
            sender_state_num=max_uint64,
            acked_state_num=max_uint64,
            base_state_num=max_uint64,
            diff=b"",
        )

        # All version fields should be 0xff * 8
        assert result[0:8] == b"\xff" * 8
        assert result[8:16] == b"\xff" * 8
        assert result[16:24] == b"\xff" * 8

    def test_large_diff_payload(self) -> None:
        """Test encoding with large diff payload."""
        large_diff = b"x" * 65536  # 64KB
        result = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=large_diff,
        )

        assert len(result) == SYNC_MESSAGE_HEADER_SIZE + 65536

        # Verify diff length field
        import struct

        diff_len = struct.unpack_from("<I", result, 24)[0]
        assert diff_len == 65536

    def test_null_bytes_in_diff(self) -> None:
        """Test encoding with null bytes in diff payload."""
        diff = b"\x00\x00\x00test\x00\x00"
        result = encode_sync_message(
            sender_state_num=1,
            acked_state_num=0,
            base_state_num=0,
            diff=diff,
        )

        assert result[SYNC_MESSAGE_HEADER_SIZE:] == diff
