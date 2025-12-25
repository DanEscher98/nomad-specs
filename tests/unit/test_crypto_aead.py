"""
XChaCha20-Poly1305 AEAD encryption/decryption tests.

Tests the security layer's authenticated encryption against test vectors
and validates crypto properties with hypothesis.

Test mapping: specs/1-SECURITY.md § "AEAD Encryption"
"""

from __future__ import annotations

from pathlib import Path

import json5
import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_TAG_SIZE,
    NomadCodec,
    hchacha20,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def aead_vectors() -> dict:
    """Load AEAD test vectors."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "aead_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """NomadCodec instance for testing."""
    return NomadCodec()


# =============================================================================
# Test Vector Validation
# =============================================================================


class TestAEADVectors:
    """Test AEAD encryption against known test vectors."""

    def test_basic_encryption(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Basic AEAD encryption produces expected ciphertext."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)

        assert ciphertext == expected_ciphertext

    def test_basic_decryption(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Basic AEAD decryption recovers original plaintext."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "basic_encryption")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        aad = bytes.fromhex(vector["aad"])
        expected_plaintext = bytes.fromhex(vector["plaintext"])

        plaintext = codec.decrypt(key, nonce, ciphertext, aad)

        assert plaintext == expected_plaintext

    def test_empty_plaintext_ack_only(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """AEAD with empty plaintext (ack-only frame)."""
        vector = next(
            v for v in aead_vectors["vectors"] if v["name"] == "empty_plaintext_ack_only"
        )

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])  # Empty
        aad = bytes.fromhex(vector["aad"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        assert plaintext == b""
        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ciphertext

        # Decrypt should also work
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)
        assert decrypted == b""

    def test_responder_direction(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """AEAD with responder->initiator direction."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "responder_direction")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ciphertext

        # Verify nonce has direction=1
        assert nonce[4] == 1  # Direction byte

    def test_after_rekey_epoch_1(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """AEAD after first rekey (epoch=1)."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "after_rekey_epoch_1")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ciphertext

        # Verify nonce has epoch=1
        import struct

        epoch = struct.unpack_from("<I", nonce, 0)[0]
        assert epoch == 1

    def test_high_counter_value(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """AEAD with high counter value (4 billion)."""
        vector = next(v for v in aead_vectors["vectors"] if v["name"] == "high_counter_value")

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        plaintext = bytes.fromhex(vector["plaintext"])
        aad = bytes.fromhex(vector["aad"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ciphertext

    def test_all_vectors_roundtrip(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """All vectors roundtrip correctly."""
        for vector in aead_vectors["vectors"]:
            key = bytes.fromhex(vector["key"])
            nonce = bytes.fromhex(vector["nonce"])
            plaintext = bytes.fromhex(vector["plaintext"])
            aad = bytes.fromhex(vector["aad"])

            ciphertext = codec.encrypt(key, nonce, plaintext, aad)
            decrypted = codec.decrypt(key, nonce, ciphertext, aad)

            assert decrypted == plaintext, f"Roundtrip failed for vector: {vector['name']}"


# =============================================================================
# Authentication Tag Verification
# =============================================================================


class TestAEADAuthentication:
    """Test AEAD authentication tag verification."""

    def test_tampered_ciphertext_rejected(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Tampered ciphertext is rejected."""
        vector = aead_vectors["vectors"][0]

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytearray(bytes.fromhex(vector["ciphertext"]))
        aad = bytes.fromhex(vector["aad"])

        # Flip a bit in the ciphertext (not the tag)
        if len(ciphertext) > AEAD_TAG_SIZE:
            ciphertext[0] ^= 0x01
        else:
            # If ciphertext is only the tag (empty plaintext), flip a tag bit
            ciphertext[0] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.decrypt(key, nonce, bytes(ciphertext), aad)

    def test_tampered_tag_rejected(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Tampered authentication tag is rejected."""
        vector = aead_vectors["vectors"][0]

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytearray(bytes.fromhex(vector["ciphertext"]))
        aad = bytes.fromhex(vector["aad"])

        # Flip a bit in the tag (last 16 bytes)
        ciphertext[-1] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.decrypt(key, nonce, bytes(ciphertext), aad)

    def test_tampered_aad_rejected(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Tampered AAD is rejected."""
        vector = aead_vectors["vectors"][0]

        key = bytes.fromhex(vector["key"])
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        aad = bytearray(bytes.fromhex(vector["aad"]))

        # Flip a bit in AAD
        aad[0] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.decrypt(key, nonce, ciphertext, bytes(aad))

    def test_wrong_key_rejected(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Wrong decryption key is rejected."""
        vector = aead_vectors["vectors"][0]

        key = bytearray(bytes.fromhex(vector["key"]))
        nonce = bytes.fromhex(vector["nonce"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        aad = bytes.fromhex(vector["aad"])

        # Use different key
        key[0] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.decrypt(bytes(key), nonce, ciphertext, aad)

    def test_wrong_nonce_rejected(self, aead_vectors: dict, codec: NomadCodec) -> None:
        """Wrong nonce is rejected."""
        vector = aead_vectors["vectors"][0]

        key = bytes.fromhex(vector["key"])
        nonce = bytearray(bytes.fromhex(vector["nonce"]))
        ciphertext = bytes.fromhex(vector["ciphertext"])
        aad = bytes.fromhex(vector["aad"])

        # Use different nonce
        nonce[0] ^= 0x01

        with pytest.raises(InvalidTag):
            codec.decrypt(key, bytes(nonce), ciphertext, aad)


# =============================================================================
# HChaCha20 Subkey Derivation
# =============================================================================


class TestHChaCha20:
    """Test HChaCha20 subkey derivation (core of XChaCha20)."""

    def test_hchacha20_key_length(self) -> None:
        """HChaCha20 requires 32-byte key."""
        key = b"\x00" * 32
        nonce = b"\x00" * 16

        subkey = hchacha20(key, nonce)
        assert len(subkey) == 32

    def test_hchacha20_deterministic(self) -> None:
        """HChaCha20 is deterministic."""
        key = b"\x00" * 32
        nonce = b"\x00" * 16

        subkey1 = hchacha20(key, nonce)
        subkey2 = hchacha20(key, nonce)

        assert subkey1 == subkey2

    def test_hchacha20_different_nonce_different_subkey(self) -> None:
        """Different nonces produce different subkeys."""
        key = b"\x00" * 32
        nonce1 = b"\x00" * 16
        nonce2 = b"\x01" + b"\x00" * 15

        subkey1 = hchacha20(key, nonce1)
        subkey2 = hchacha20(key, nonce2)

        assert subkey1 != subkey2

    def test_hchacha20_different_key_different_subkey(self) -> None:
        """Different keys produce different subkeys."""
        key1 = b"\x00" * 32
        key2 = b"\x01" + b"\x00" * 31
        nonce = b"\x00" * 16

        subkey1 = hchacha20(key1, nonce)
        subkey2 = hchacha20(key2, nonce)

        assert subkey1 != subkey2


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestAEADProperties:
    """Property-based tests for AEAD."""

    @given(
        key=st.binary(min_size=32, max_size=32),
        nonce=st.binary(min_size=24, max_size=24),
        plaintext=st.binary(min_size=0, max_size=1024),
        aad=st.binary(min_size=0, max_size=256),
    )
    @settings(max_examples=100)
    def test_roundtrip_property(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> None:
        """Encrypt then decrypt always recovers original plaintext."""
        ciphertext = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        decrypted = xchacha20_poly1305_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    @given(
        key=st.binary(min_size=32, max_size=32),
        nonce=st.binary(min_size=24, max_size=24),
        plaintext=st.binary(min_size=0, max_size=1024),
        aad=st.binary(min_size=0, max_size=256),
    )
    @settings(max_examples=100)
    def test_ciphertext_length_property(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> None:
        """Ciphertext length is plaintext length + tag size."""
        ciphertext = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

        assert len(ciphertext) == len(plaintext) + AEAD_TAG_SIZE

    @given(
        key=st.binary(min_size=32, max_size=32),
        nonce=st.binary(min_size=24, max_size=24),
        plaintext=st.binary(min_size=0, max_size=1024),
        aad=st.binary(min_size=0, max_size=256),
    )
    @settings(max_examples=50)
    def test_different_nonce_different_ciphertext(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> None:
        """Same plaintext with different nonces produces different ciphertext."""
        # Create a different nonce by flipping a bit
        nonce2 = bytes([nonce[0] ^ 0x01]) + nonce[1:]

        assume(nonce != nonce2)  # Ensure nonces are different

        ciphertext1 = xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        ciphertext2 = xchacha20_poly1305_encrypt(key, nonce2, plaintext, aad)

        # Ciphertexts should be different (with overwhelming probability)
        if len(plaintext) > 0:
            assert ciphertext1 != ciphertext2

    @given(
        key=st.binary(min_size=32, max_size=32),
        nonce=st.binary(min_size=24, max_size=24),
        plaintext=st.binary(min_size=1, max_size=1024),
        aad=st.binary(min_size=0, max_size=256),
        bit_position=st.integers(min_value=0, max_value=7),
        byte_position=st.integers(min_value=0, max_value=100),
    )
    @settings(max_examples=50)
    def test_any_tampering_detected(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
        bit_position: int,
        byte_position: int,
    ) -> None:
        """Any bit flip in ciphertext is detected."""
        ciphertext = bytearray(xchacha20_poly1305_encrypt(key, nonce, plaintext, aad))

        # Flip a bit
        byte_position = byte_position % len(ciphertext)
        ciphertext[byte_position] ^= 1 << bit_position

        with pytest.raises(InvalidTag):
            xchacha20_poly1305_decrypt(key, nonce, bytes(ciphertext), aad)


# =============================================================================
# Edge Cases
# =============================================================================


class TestAEADEdgeCases:
    """Edge case tests for AEAD."""

    def test_empty_plaintext(self, codec: NomadCodec) -> None:
        """Empty plaintext produces tag-only ciphertext."""
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        plaintext = b""
        aad = b"\x00" * 16

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)

        assert len(ciphertext) == AEAD_TAG_SIZE
        assert codec.decrypt(key, nonce, ciphertext, aad) == b""

    def test_empty_aad(self, codec: NomadCodec) -> None:
        """Empty AAD is valid."""
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        plaintext = b"test"
        aad = b""

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_large_plaintext(self, codec: NomadCodec) -> None:
        """Large plaintext (64KB) works correctly."""
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        plaintext = b"\x00" * 65536
        aad = b"\x00" * 16

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_all_bits_set_key(self, codec: NomadCodec) -> None:
        """Key with all bits set works."""
        key = b"\xff" * 32
        nonce = b"\x00" * 24
        plaintext = b"test"
        aad = b"\x00" * 16

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_all_bits_set_nonce(self, codec: NomadCodec) -> None:
        """Nonce with all bits set works."""
        key = b"\x00" * 32
        nonce = b"\xff" * 24
        plaintext = b"test"
        aad = b"\x00" * 16

        ciphertext = codec.encrypt(key, nonce, plaintext, aad)
        decrypted = codec.decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext


# =============================================================================
# Input Validation
# =============================================================================


class TestAEADInputValidation:
    """Test AEAD input validation."""

    def test_key_too_short_rejected(self) -> None:
        """Key shorter than 32 bytes is rejected."""
        key = b"\x00" * 31
        nonce = b"\x00" * 24
        plaintext = b"test"
        aad = b""

        with pytest.raises(AssertionError):
            xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    def test_key_too_long_rejected(self) -> None:
        """Key longer than 32 bytes is rejected."""
        key = b"\x00" * 33
        nonce = b"\x00" * 24
        plaintext = b"test"
        aad = b""

        with pytest.raises(AssertionError):
            xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    def test_nonce_too_short_rejected(self) -> None:
        """Nonce shorter than 24 bytes is rejected."""
        key = b"\x00" * 32
        nonce = b"\x00" * 23
        plaintext = b"test"
        aad = b""

        with pytest.raises(AssertionError):
            xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    def test_nonce_too_long_rejected(self) -> None:
        """Nonce longer than 24 bytes is rejected."""
        key = b"\x00" * 32
        nonce = b"\x00" * 25
        plaintext = b"test"
        aad = b""

        with pytest.raises(AssertionError):
            xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    def test_truncated_ciphertext_rejected(self, codec: NomadCodec) -> None:
        """Ciphertext shorter than tag size is rejected."""
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        ciphertext = b"\x00" * (AEAD_TAG_SIZE - 1)  # Too short
        aad = b""

        with pytest.raises(InvalidTag):
            codec.decrypt(key, nonce, ciphertext, aad)
