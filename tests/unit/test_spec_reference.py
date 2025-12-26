"""
Unit tests for the NOMAD reference codec.

These tests validate the reference codec against the canonical test vectors.
The codec is the SOURCE OF TRUTH for wire format correctness.
"""

from __future__ import annotations

from pathlib import Path

import json5
import pytest
from cryptography.exceptions import InvalidTag

from lib.reference import (
    AEAD_NONCE_SIZE,
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FLAG_ACK_ONLY,
    FRAME_DATA,
    SESSION_ID_SIZE,
    SYNC_MESSAGE_HEADER_SIZE,
    NomadCodec,
    construct_nonce,
    encode_data_frame_header,
    encode_payload_header,
    encode_sync_message,
    parse_data_frame_header,
    parse_nonce,
    parse_payload_header,
    parse_sync_message,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

# Path to test vectors
VECTORS_DIR = Path(__file__).parent.parent / "vectors"


# =============================================================================
# Fixtures for loading test vectors
# =============================================================================


@pytest.fixture(scope="module")
def aead_vectors() -> dict:
    """Load AEAD test vectors."""
    with open(VECTORS_DIR / "aead_vectors.json5") as f:
        return json5.load(f)


@pytest.fixture(scope="module")
def nonce_vectors() -> dict:
    """Load nonce test vectors."""
    with open(VECTORS_DIR / "nonce_vectors.json5") as f:
        return json5.load(f)


@pytest.fixture(scope="module")
def frame_vectors() -> dict:
    """Load frame test vectors."""
    with open(VECTORS_DIR / "frame_vectors.json5") as f:
        return json5.load(f)


@pytest.fixture(scope="module")
def sync_vectors() -> dict:
    """Load sync test vectors."""
    with open(VECTORS_DIR / "sync_vectors.json5") as f:
        return json5.load(f)


# =============================================================================
# XChaCha20-Poly1305 AEAD Tests
# =============================================================================


class TestXChaCha20Poly1305:
    """Tests for XChaCha20-Poly1305 AEAD implementation."""

    def test_encrypt_basic(self, aead_vectors: dict) -> None:
        """Test basic encryption matches test vector."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected = bytes.fromhex(vector["ciphertext"])

        result = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert result == expected

    def test_decrypt_basic(self, aead_vectors: dict) -> None:
        """Test basic decryption matches test vector."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        aad = bytes.fromhex(vector["aad"])
        expected_plaintext = bytes.fromhex(vector["plaintext"])

        result = xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)
        assert result == expected_plaintext

    def test_encrypt_empty_plaintext(self, aead_vectors: dict) -> None:
        """Test encryption with empty plaintext (ack-only frame)."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "empty_plaintext_ack_only")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"]) if vector["plaintext"] else b""
        aad = bytes.fromhex(vector["aad"])
        expected = bytes.fromhex(vector["ciphertext"])

        result = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert result == expected
        # With empty plaintext, ciphertext should be just the tag
        assert len(result) == AEAD_TAG_SIZE

    def test_encrypt_responder_direction(self, aead_vectors: dict) -> None:
        """Test encryption with responder direction."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "responder_direction")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected = bytes.fromhex(vector["ciphertext"])

        result = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert result == expected

    def test_encrypt_after_rekey(self, aead_vectors: dict) -> None:
        """Test encryption after rekey (epoch > 0)."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "after_rekey_epoch_1")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected = bytes.fromhex(vector["ciphertext"])

        result = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert result == expected

    def test_decrypt_invalid_tag(self) -> None:
        """Test that invalid tag raises exception."""
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        ciphertext = b"\x00" * 32  # Invalid ciphertext with wrong tag
        aad = b""

        with pytest.raises(InvalidTag):
            xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)

    def test_decrypt_wrong_aad(self, aead_vectors: dict) -> None:
        """Test that wrong AAD causes authentication failure."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        wrong_aad = b"\x00" * 16  # Wrong AAD

        with pytest.raises(InvalidTag):
            xchacha20_poly1305_decrypt(key, nonce, ciphertext, wrong_aad)

    def test_roundtrip(self) -> None:
        """Test encrypt-decrypt roundtrip."""
        key = b"\x42" * 32
        nonce = b"\x13" * 24
        plaintext = b"Hello, NOMAD Protocol!"
        aad = b"additional data"

        ciphertext = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        decrypted = xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext


# =============================================================================
# Nonce Construction Tests
# =============================================================================


class TestNonceConstruction:
    """Tests for nonce construction and parsing."""

    def test_nonce_vectors(self, nonce_vectors: dict) -> None:
        """Test nonce construction matches all test vectors."""
        for vector in nonce_vectors["vectors"]:
            epoch = vector["epoch"]
            direction = vector["direction"]
            counter = vector["counter"]
            expected = bytes.fromhex(vector["nonce"])

            result = construct_nonce(epoch, direction, counter)
            assert result == expected, f"Failed for vector: {vector['name']}"
            assert len(result) == AEAD_NONCE_SIZE

    def test_nonce_parse_roundtrip(self, nonce_vectors: dict) -> None:
        """Test nonce parse matches construction."""
        for vector in nonce_vectors["vectors"]:
            nonce = bytes.fromhex(vector["nonce"])
            components = parse_nonce(nonce)

            assert components.epoch == vector["epoch"]
            assert components.direction == vector["direction"]
            assert components.counter == vector["counter"]

    def test_nonce_initial_initiator(self) -> None:
        """Test initial initiator nonce is all zeros except structure."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        assert nonce == b"\x00" * 24

    def test_nonce_direction_bit(self) -> None:
        """Test direction bit is at correct position."""
        nonce_initiator = construct_nonce(0, 0, 0)
        nonce_responder = construct_nonce(0, 1, 0)

        assert nonce_initiator[4] == 0
        assert nonce_responder[4] == 1
        # Rest should be identical
        assert nonce_initiator[:4] == nonce_responder[:4]
        assert nonce_initiator[5:] == nonce_responder[5:]


# =============================================================================
# Frame Header Tests
# =============================================================================


class TestFrameHeader:
    """Tests for data frame header encoding/parsing."""

    def test_frame_header_vectors(self, frame_vectors: dict) -> None:
        """Test frame header encoding matches test vectors."""
        for vector in frame_vectors["data_frame_headers"]:
            session_id = bytes.fromhex(vector["session_id"])
            flags = vector["flags"]
            nonce_counter = vector["nonce_counter"]
            expected = bytes.fromhex(vector["encoded"])

            result = encode_data_frame_header(flags, session_id, nonce_counter)
            assert result == expected, f"Failed for vector: {vector['name']}"
            assert len(result) == DATA_FRAME_HEADER_SIZE

    def test_frame_header_parse(self, frame_vectors: dict) -> None:
        """Test frame header parsing matches encoding."""
        for vector in frame_vectors["data_frame_headers"]:
            encoded = bytes.fromhex(vector["encoded"])
            header = parse_data_frame_header(encoded)

            assert header.frame_type == FRAME_DATA
            assert header.flags == vector["flags"]
            assert header.session_id == bytes.fromhex(vector["session_id"])
            assert header.nonce_counter == vector["nonce_counter"]

    def test_frame_header_roundtrip(self) -> None:
        """Test encode-parse roundtrip for frame headers."""
        session_id = b"\x12\x34\x56\x78\x9a\xbc"
        flags = 0x03
        nonce_counter = 12345678

        encoded = encode_data_frame_header(flags, session_id, nonce_counter)
        parsed = parse_data_frame_header(encoded)

        assert parsed.frame_type == FRAME_DATA
        assert parsed.flags == flags
        assert parsed.session_id == session_id
        assert parsed.nonce_counter == nonce_counter

    def test_frame_header_wrong_type(self) -> None:
        """Test parsing header with wrong frame type raises error."""
        # Create a header with wrong type (0x01 = handshake init)
        bad_header = b"\x01\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00"

        with pytest.raises(ValueError, match="Not a data frame"):
            parse_data_frame_header(bad_header)

    def test_frame_header_too_short(self) -> None:
        """Test parsing truncated header raises error."""
        with pytest.raises(ValueError, match="Header too short"):
            parse_data_frame_header(b"\x03\x00\x01\x02")


# =============================================================================
# Sync Message Tests
# =============================================================================


class TestSyncMessage:
    """Tests for sync message encoding/parsing."""

    def test_sync_message_vectors(self, sync_vectors: dict) -> None:
        """Test sync message encoding matches test vectors."""
        for vector in sync_vectors["sync_messages"]:
            sender = vector["sender_state_num"]
            acked = vector["acked_state_num"]
            base = vector["base_state_num"]
            diff = bytes.fromhex(vector["diff"]["hex"]) if vector["diff"]["hex"] else b""
            expected = bytes.fromhex(vector["encoded"])

            result = encode_sync_message(sender, acked, base, diff)
            assert result == expected, f"Failed for vector: {vector['name']}"

    def test_sync_message_parse(self, sync_vectors: dict) -> None:
        """Test sync message parsing matches encoding."""
        for vector in sync_vectors["sync_messages"]:
            encoded = bytes.fromhex(vector["encoded"])
            msg = parse_sync_message(encoded)

            assert msg.sender_state_num == vector["sender_state_num"]
            assert msg.acked_state_num == vector["acked_state_num"]
            assert msg.base_state_num == vector["base_state_num"]
            expected_diff = bytes.fromhex(vector["diff"]["hex"]) if vector["diff"]["hex"] else b""
            assert msg.diff == expected_diff

    def test_sync_message_roundtrip(self) -> None:
        """Test encode-parse roundtrip for sync messages."""
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

    def test_sync_message_empty_diff(self) -> None:
        """Test sync message with empty diff (ack-only)."""
        encoded = encode_sync_message(10, 10, 0, b"")
        parsed = parse_sync_message(encoded)

        assert parsed.diff == b""
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE

    def test_sync_message_too_short(self) -> None:
        """Test parsing truncated sync message raises error."""
        with pytest.raises(ValueError, match="Sync message too short"):
            parse_sync_message(b"\x01\x02\x03")  # Too short

    def test_sync_message_truncated_diff(self) -> None:
        """Test parsing sync message with truncated diff raises error."""
        # Header claims 100 bytes of diff, but only provides 5
        bad_msg = (
            b"\x01\x00\x00\x00\x00\x00\x00\x00"  # sender
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # acked
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # base
            b"\x64\x00\x00\x00"  # diff_length = 100
            b"short"  # only 5 bytes
        )

        with pytest.raises(ValueError, match="Sync message truncated"):
            parse_sync_message(bad_msg)


# =============================================================================
# Payload Header Tests
# =============================================================================


class TestPayloadHeader:
    """Tests for encrypted payload header encoding/parsing."""

    def test_payload_header_roundtrip(self) -> None:
        """Test encode-parse roundtrip for payload headers."""
        timestamp = 12345
        timestamp_echo = 12300
        payload_length = 500

        encoded = encode_payload_header(timestamp, timestamp_echo, payload_length)
        parsed = parse_payload_header(encoded)

        assert parsed.timestamp == timestamp
        assert parsed.timestamp_echo == timestamp_echo
        assert parsed.payload_length == payload_length
        assert len(encoded) == 10  # 4 + 4 + 2

    def test_payload_header_too_short(self) -> None:
        """Test parsing truncated payload header raises error."""
        with pytest.raises(ValueError, match="Payload header too short"):
            parse_payload_header(b"\x00\x01\x02")


# =============================================================================
# NomadCodec Class Tests
# =============================================================================


class TestNomadCodec:
    """Tests for the NomadCodec class interface."""

    def test_codec_encrypt_decrypt(self, aead_vectors: dict) -> None:
        """Test codec encrypt/decrypt methods."""
        codec = NomadCodec()
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_codec_nonce_construction(self, nonce_vectors: dict) -> None:
        """Test codec nonce methods."""
        codec = NomadCodec()

        for vector in nonce_vectors["vectors"]:
            nonce = codec.construct_nonce(vector["epoch"], vector["direction"], vector["counter"])
            assert nonce == bytes.fromhex(vector["nonce"])

            components = codec.parse_nonce(nonce)
            assert components.epoch == vector["epoch"]
            assert components.direction == vector["direction"]
            assert components.counter == vector["counter"]

    def test_codec_sync_message(self, sync_vectors: dict) -> None:
        """Test codec sync message methods."""
        codec = NomadCodec()

        for vector in sync_vectors["sync_messages"]:
            diff = bytes.fromhex(vector["diff"]["hex"]) if vector["diff"]["hex"] else b""
            encoded = codec.create_sync_message(
                vector["sender_state_num"],
                vector["acked_state_num"],
                vector["base_state_num"],
                diff,
            )
            assert encoded == bytes.fromhex(vector["encoded"])

            parsed = codec.parse_sync_message(encoded)
            assert parsed.sender_state_num == vector["sender_state_num"]
            assert parsed.acked_state_num == vector["acked_state_num"]
            assert parsed.base_state_num == vector["base_state_num"]
            assert parsed.diff == diff

    def test_codec_data_frame_roundtrip(self) -> None:
        """Test codec create/parse data frame roundtrip."""
        codec = NomadCodec()

        session_id = b"\x01\x02\x03\x04\x05\x06"
        nonce_counter = 42
        key = b"\xaa" * 32
        epoch = 0
        direction = 0
        timestamp = 1000
        timestamp_echo = 500
        sync_message = codec.create_sync_message(5, 3, 4, b"test diff")

        # Create frame
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=nonce_counter,
            key=key,
            epoch=epoch,
            direction=direction,
            timestamp=timestamp,
            timestamp_echo=timestamp_echo,
            sync_message=sync_message,
        )

        # Parse frame
        parsed = codec.parse_data_frame(frame, key, epoch, direction)

        assert parsed.header.session_id == session_id
        assert parsed.header.nonce_counter == nonce_counter
        assert parsed.payload_header.timestamp == timestamp
        assert parsed.payload_header.timestamp_echo == timestamp_echo
        assert parsed.sync_message.sender_state_num == 5
        assert parsed.sync_message.acked_state_num == 3
        assert parsed.sync_message.base_state_num == 4
        assert parsed.sync_message.diff == b"test diff"

    def test_codec_constants(self) -> None:
        """Test codec exposes correct constants."""
        assert NomadCodec.FRAME_DATA == FRAME_DATA
        assert NomadCodec.FLAG_ACK_ONLY == FLAG_ACK_ONLY
        assert NomadCodec.SESSION_ID_SIZE == SESSION_ID_SIZE
        assert NomadCodec.AEAD_TAG_SIZE == AEAD_TAG_SIZE
        assert NomadCodec.AEAD_NONCE_SIZE == AEAD_NONCE_SIZE


# =============================================================================
# Convergence Scenario Tests
# =============================================================================


class TestConvergenceScenarios:
    """Tests for sync convergence scenarios from test vectors."""

    def test_normal_convergence(self, sync_vectors: dict) -> None:
        """Test normal convergence scenario encoding."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "normal_convergence"
        )

        for msg in scenario["messages"]:
            diff = msg["diff_ascii"].encode("utf-8")
            encoded = encode_sync_message(
                msg["sender_state_num"],
                msg["acked_state_num"],
                msg["base_state_num"],
                diff,
            )
            assert encoded == bytes.fromhex(msg["encoded"])

    def test_packet_loss_recovery(self, sync_vectors: dict) -> None:
        """Test packet loss recovery scenario encoding."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "packet_loss_recovery"
        )

        for msg in scenario["messages"]:
            diff = msg["diff_ascii"].encode("utf-8")
            encoded = encode_sync_message(
                msg["sender_state_num"],
                msg["acked_state_num"],
                msg["base_state_num"],
                diff,
            )
            assert encoded == bytes.fromhex(msg["encoded"])


# =============================================================================
# Deterministic Key Generation Tests
# =============================================================================


class TestDeterministicKeys:
    """Tests for deterministic key generation (reproducibility)."""

    def test_keypair_deterministic(self) -> None:
        """Test that keypair generation is deterministic."""
        priv1, pub1 = NomadCodec.deterministic_keypair("test-seed")
        priv2, pub2 = NomadCodec.deterministic_keypair("test-seed")

        assert priv1 == priv2
        assert pub1 == pub2

    def test_keypair_different_seeds(self) -> None:
        """Test that different seeds produce different keys."""
        priv1, pub1 = NomadCodec.deterministic_keypair("seed-1")
        priv2, pub2 = NomadCodec.deterministic_keypair("seed-2")

        assert priv1 != priv2
        assert pub1 != pub2

    def test_bytes_deterministic(self) -> None:
        """Test that byte generation is deterministic."""
        bytes1 = NomadCodec.deterministic_bytes("test-seed", 64)
        bytes2 = NomadCodec.deterministic_bytes("test-seed", 64)

        assert bytes1 == bytes2
        assert len(bytes1) == 64
