"""
Unit tests for sync message diff decoding.

Tests the decoding (parsing) of sync messages from wire format.
These tests validate that implementations correctly deserialize:
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
    parse_sync_message,
)

# Path to test vectors
VECTORS_DIR = Path(__file__).parent.parent / "vectors"


@pytest.fixture(scope="module")
def sync_vectors() -> dict:
    """Load sync test vectors."""
    with open(VECTORS_DIR / "sync_vectors.json5") as f:
        return json5.load(f)


# =============================================================================
# Basic Decoding Tests
# =============================================================================


class TestSyncMessageDecoding:
    """Tests for sync message decoding against test vectors."""

    def test_initial_state_decoding(self, sync_vectors: dict) -> None:
        """Test decoding of initial state message."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "initial_state")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == vector["sender_state_num"]
        assert msg.acked_state_num == vector["acked_state_num"]
        assert msg.base_state_num == vector["base_state_num"]
        assert msg.diff == bytes.fromhex(vector["diff"]["hex"])

    def test_normal_sync_decoding(self, sync_vectors: dict) -> None:
        """Test decoding of normal sync message with ack and diff."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "normal_sync")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == vector["sender_state_num"]
        assert msg.acked_state_num == vector["acked_state_num"]
        assert msg.base_state_num == vector["base_state_num"]
        assert msg.diff == bytes.fromhex(vector["diff"]["hex"])

    def test_ack_only_decoding(self, sync_vectors: dict) -> None:
        """Test decoding of ack-only message (empty diff)."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "ack_only")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == vector["sender_state_num"]
        assert msg.acked_state_num == vector["acked_state_num"]
        assert msg.base_state_num == vector["base_state_num"]
        assert msg.diff == b""

    def test_large_version_numbers_decoding(self, sync_vectors: dict) -> None:
        """Test decoding with large version numbers."""
        vector = next(
            v for v in sync_vectors["sync_messages"] if v["name"] == "large_version_numbers"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == vector["sender_state_num"]
        assert msg.acked_state_num == vector["acked_state_num"]
        assert msg.base_state_num == vector["base_state_num"]

    def test_binary_diff_decoding(self, sync_vectors: dict) -> None:
        """Test decoding with binary (non-ASCII) diff payload."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "binary_diff")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.diff == bytes.fromhex(vector["diff"]["hex"])

    def test_all_sync_vectors(self, sync_vectors: dict) -> None:
        """Test decoding against all sync message vectors."""
        for vector in sync_vectors["sync_messages"]:
            encoded = bytes.fromhex(vector["encoded"])
            msg = parse_sync_message(encoded)

            assert msg.sender_state_num == vector["sender_state_num"], (
                f"sender mismatch for: {vector['name']}"
            )
            assert msg.acked_state_num == vector["acked_state_num"], (
                f"acked mismatch for: {vector['name']}"
            )
            assert msg.base_state_num == vector["base_state_num"], (
                f"base mismatch for: {vector['name']}"
            )

            expected_diff = bytes.fromhex(vector["diff"]["hex"]) if vector["diff"]["hex"] else b""
            assert msg.diff == expected_diff, f"diff mismatch for: {vector['name']}"


# =============================================================================
# Malformed Input Tests
# =============================================================================


class TestMalformedDecoding:
    """Tests for handling malformed sync messages."""

    def test_too_short_message(self) -> None:
        """Test that message shorter than header raises error."""
        with pytest.raises(ValueError, match="Sync message too short"):
            parse_sync_message(b"\x01\x02\x03")

    def test_exactly_header_size_minus_one(self) -> None:
        """Test that message one byte too short raises error."""
        with pytest.raises(ValueError, match="Sync message too short"):
            parse_sync_message(b"\x00" * (SYNC_MESSAGE_HEADER_SIZE - 1))

    def test_truncated_diff(self) -> None:
        """Test that truncated diff payload raises error."""
        # Header claims 100 bytes of diff, but only provides 5
        header = (
            b"\x01\x00\x00\x00\x00\x00\x00\x00"  # sender = 1
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # acked = 0
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # base = 0
            b"\x64\x00\x00\x00"  # diff_length = 100
        )
        bad_msg = header + b"short"  # only 5 bytes of payload

        with pytest.raises(ValueError, match="Sync message truncated"):
            parse_sync_message(bad_msg)

    def test_empty_message(self) -> None:
        """Test that empty message raises error."""
        with pytest.raises(ValueError, match="Sync message too short"):
            parse_sync_message(b"")

    def test_diff_length_larger_than_remaining(self) -> None:
        """Test diff length claiming more bytes than available."""
        # Valid header but diff length > remaining bytes
        header = (
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"  # diff_length = 10
        )
        bad_msg = header + b"12345"  # only 5 bytes

        with pytest.raises(ValueError, match="Sync message truncated"):
            parse_sync_message(bad_msg)

    def test_zero_diff_length_with_trailing_bytes(self) -> None:
        """Test that trailing bytes after declared length are ignored."""
        # This is valid - extra bytes are allowed (forward compatibility)
        header = (
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x05\x00\x00\x00"  # diff_length = 5
        )
        msg_with_extra = header + b"12345" + b"extra"  # 5 bytes + extra

        result = parse_sync_message(msg_with_extra)

        # Should only parse the first 5 bytes of diff
        assert result.diff == b"12345"


# =============================================================================
# Roundtrip Tests
# =============================================================================


class TestEncodingDecodingRoundtrip:
    """Tests for encode-decode roundtrip consistency."""

    def test_simple_roundtrip(self) -> None:
        """Test basic encode-decode roundtrip."""
        sender = 100
        acked = 95
        base = 99
        diff = b"test diff payload"

        encoded = encode_sync_message(sender, acked, base, diff)
        parsed = parse_sync_message(encoded)

        assert parsed.sender_state_num == sender
        assert parsed.acked_state_num == acked
        assert parsed.base_state_num == base
        assert parsed.diff == diff

    def test_empty_diff_roundtrip(self) -> None:
        """Test roundtrip with empty diff."""
        encoded = encode_sync_message(10, 10, 0, b"")
        parsed = parse_sync_message(encoded)

        assert parsed.diff == b""
        assert parsed.sender_state_num == 10
        assert parsed.acked_state_num == 10
        assert parsed.base_state_num == 0

    def test_large_version_roundtrip(self) -> None:
        """Test roundtrip with large version numbers."""
        large = 281474976710655  # from test vector
        encoded = encode_sync_message(large, large - 1, large - 2, b"big")
        parsed = parse_sync_message(encoded)

        assert parsed.sender_state_num == large
        assert parsed.acked_state_num == large - 1
        assert parsed.base_state_num == large - 2

    def test_max_uint64_roundtrip(self) -> None:
        """Test roundtrip with maximum uint64 values."""
        max_uint64 = (1 << 64) - 1
        encoded = encode_sync_message(max_uint64, max_uint64, max_uint64, b"")
        parsed = parse_sync_message(encoded)

        assert parsed.sender_state_num == max_uint64
        assert parsed.acked_state_num == max_uint64
        assert parsed.base_state_num == max_uint64

    def test_binary_diff_roundtrip(self) -> None:
        """Test roundtrip with binary diff payload."""
        diff = bytes(range(256))  # All possible byte values
        encoded = encode_sync_message(1, 0, 0, diff)
        parsed = parse_sync_message(encoded)

        assert parsed.diff == diff

    def test_large_diff_roundtrip(self) -> None:
        """Test roundtrip with large diff payload."""
        diff = b"x" * 65536
        encoded = encode_sync_message(1, 0, 0, diff)
        parsed = parse_sync_message(encoded)

        assert parsed.diff == diff


# =============================================================================
# Convergence Scenario Decoding Tests
# =============================================================================


class TestConvergenceScenarioDecoding:
    """Tests for decoding convergence scenario messages."""

    def test_normal_convergence_messages(self, sync_vectors: dict) -> None:
        """Test decoding of messages in normal convergence scenario."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "normal_convergence"
        )

        for msg_data in scenario["messages"]:
            encoded = bytes.fromhex(msg_data["encoded"])
            msg = parse_sync_message(encoded)

            assert msg.sender_state_num == msg_data["sender_state_num"]
            assert msg.acked_state_num == msg_data["acked_state_num"]
            assert msg.base_state_num == msg_data["base_state_num"]
            assert msg.diff == msg_data["diff_ascii"].encode("utf-8")

    def test_packet_loss_recovery_messages(self, sync_vectors: dict) -> None:
        """Test decoding of messages in packet loss recovery scenario."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "packet_loss_recovery"
        )

        for msg_data in scenario["messages"]:
            encoded = bytes.fromhex(msg_data["encoded"])
            msg = parse_sync_message(encoded)

            assert msg.sender_state_num == msg_data["sender_state_num"]
            assert msg.acked_state_num == msg_data["acked_state_num"]
            assert msg.diff == msg_data["diff_ascii"].encode("utf-8")


# =============================================================================
# Codec Class Decoding Tests
# =============================================================================


class TestCodecDecoding:
    """Tests for NomadCodec sync message decoding."""

    def test_codec_parse_sync_message(self, sync_vectors: dict) -> None:
        """Test NomadCodec.parse_sync_message() against vectors."""
        codec = NomadCodec()

        for vector in sync_vectors["sync_messages"]:
            encoded = bytes.fromhex(vector["encoded"])
            msg = codec.parse_sync_message(encoded)

            assert msg.sender_state_num == vector["sender_state_num"]
            assert msg.acked_state_num == vector["acked_state_num"]
            assert msg.base_state_num == vector["base_state_num"]

            expected_diff = bytes.fromhex(vector["diff"]["hex"]) if vector["diff"]["hex"] else b""
            assert msg.diff == expected_diff

    def test_codec_vs_function(self) -> None:
        """Test that NomadCodec.parse_sync_message matches parse_sync_message."""
        codec = NomadCodec()

        test_cases = [
            (1, 0, 0, b""),
            (100, 50, 99, b"test"),
            (1000, 999, 998, b"\x00\xff\xde\xad"),
            (281474976710655, 281474976710654, 281474976710653, b"big"),
        ]

        for sender, acked, base, diff in test_cases:
            encoded = encode_sync_message(sender, acked, base, diff)

            func_result = parse_sync_message(encoded)
            codec_result = codec.parse_sync_message(encoded)

            assert func_result.sender_state_num == codec_result.sender_state_num
            assert func_result.acked_state_num == codec_result.acked_state_num
            assert func_result.base_state_num == codec_result.base_state_num
            assert func_result.diff == codec_result.diff


# =============================================================================
# ASCII vs Binary Diff Tests
# =============================================================================


class TestDiffPayloadTypes:
    """Tests for different types of diff payloads."""

    def test_ascii_diff(self, sync_vectors: dict) -> None:
        """Test decoding ASCII diff from vector with ascii field."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "initial_state")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        # Verify ASCII representation matches
        assert msg.diff.decode("utf-8") == vector["diff"]["ascii"]

    def test_binary_only_diff(self, sync_vectors: dict) -> None:
        """Test decoding binary diff that has no ASCII representation."""
        vector = next(v for v in sync_vectors["sync_messages"] if v["name"] == "binary_diff")

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        # Binary diff should match hex encoding
        assert msg.diff == bytes.fromhex(vector["diff"]["hex"])

        # Should not have valid ASCII (contains null bytes)
        assert b"\x00" in msg.diff

    def test_unicode_in_diff(self) -> None:
        """Test roundtrip with UTF-8 encoded unicode in diff."""
        unicode_diff = "Hello 世界 🌍".encode()

        encoded = encode_sync_message(1, 0, 0, unicode_diff)
        msg = parse_sync_message(encoded)

        assert msg.diff == unicode_diff
        assert msg.diff.decode("utf-8") == "Hello 世界 🌍"
