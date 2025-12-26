"""
NOMAD Protocol - Rekey Key Derivation Tests (PCS Fix)

These tests verify the Post-Compromise Security fix:
- rekey_auth_key derivation from static DH
- Rekey key derivation mixing rekey_auth_key
- Test vectors from rekey_vectors.json5

The PCS fix ensures that an attacker who compromises a session key
cannot derive future session keys after a rekey, because they don't
have access to rekey_auth_key (derived from static DH during handshake).
"""

from __future__ import annotations

import struct
from pathlib import Path

import json5
import pytest

from lib.reference import (
    REKEY_AUTH_INFO,
    REKEY_AUTH_KEY_SIZE,
    REKEY_INFO_PREFIX,
    SESSION_KEY_INFO,
    SYMMETRIC_KEY_SIZE,
    NomadCodec,
    compute_ephemeral_dh,
    compute_static_dh,
    derive_rekey_auth_key,
    derive_rekey_keys,
    derive_session_keys,
    hkdf_expand,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def rekey_vectors() -> dict:
    """Load rekey test vectors."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "rekey_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)


@pytest.fixture
def handshake_vectors() -> dict:
    """Load handshake test vectors."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "handshake_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)


@pytest.fixture
def codec() -> NomadCodec:
    """Create a NomadCodec instance."""
    return NomadCodec()


# =============================================================================
# HKDF-Expand Tests
# =============================================================================


class TestHkdfExpand:
    """Tests for HKDF-Expand functionality."""

    def test_hkdf_expand_32_bytes(self) -> None:
        """HKDF-Expand produces 32 bytes of key material."""
        prk = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")
        info = b"test info"

        result = hkdf_expand(prk, info, 32)

        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_hkdf_expand_64_bytes(self) -> None:
        """HKDF-Expand produces 64 bytes of key material."""
        prk = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")
        info = b"test info"

        result = hkdf_expand(prk, info, 64)

        assert len(result) == 64
        assert isinstance(result, bytes)

    def test_hkdf_expand_deterministic(self) -> None:
        """HKDF-Expand is deterministic - same inputs produce same output."""
        prk = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")
        info = b"test info"

        result1 = hkdf_expand(prk, info, 32)
        result2 = hkdf_expand(prk, info, 32)

        assert result1 == result2

    def test_hkdf_expand_different_info_different_output(self) -> None:
        """Different info produces different output."""
        prk = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")

        result1 = hkdf_expand(prk, b"info1", 32)
        result2 = hkdf_expand(prk, b"info2", 32)

        assert result1 != result2


# =============================================================================
# Rekey Auth Key Derivation Tests
# =============================================================================


class TestRekeyAuthKeyDerivation:
    """Tests for rekey_auth_key derivation from static DH."""

    def test_derive_rekey_auth_key_length(self) -> None:
        """rekey_auth_key is 32 bytes."""
        static_dh = bytes(32)

        result = derive_rekey_auth_key(static_dh)

        assert len(result) == REKEY_AUTH_KEY_SIZE
        assert len(result) == 32

    def test_derive_rekey_auth_key_deterministic(self) -> None:
        """rekey_auth_key derivation is deterministic."""
        static_dh = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )

        result1 = derive_rekey_auth_key(static_dh)
        result2 = derive_rekey_auth_key(static_dh)

        assert result1 == result2

    def test_derive_rekey_auth_key_uses_correct_info(self) -> None:
        """rekey_auth_key uses 'nomad v1 rekey auth' as info."""
        assert REKEY_AUTH_INFO == b"nomad v1 rekey auth"

    def test_derive_rekey_auth_key_from_vectors(self, rekey_vectors: dict) -> None:
        """rekey_auth_key matches test vector."""
        intermediate = rekey_vectors["intermediate_values"]
        static_dh = bytes.fromhex(intermediate["static_dh"])
        expected = bytes.fromhex(intermediate["rekey_auth_key"]["output"])

        result = derive_rekey_auth_key(static_dh)

        assert result == expected

    def test_compute_static_dh_from_vectors(self, rekey_vectors: dict) -> None:
        """Static DH computation matches test vector."""
        intermediate = rekey_vectors["intermediate_values"]
        static_keys = intermediate["static_keys"]

        initiator_static_priv = bytes.fromhex(static_keys["initiator_static_private"])
        responder_static_pub = bytes.fromhex(static_keys["responder_static_public"])
        expected_dh = bytes.fromhex(intermediate["static_dh"])

        result = compute_static_dh(initiator_static_priv, responder_static_pub)

        assert result == expected_dh


# =============================================================================
# Session Key Derivation Tests
# =============================================================================


class TestSessionKeyDerivation:
    """Tests for session key derivation (epoch 0)."""

    def test_derive_session_keys_length(self) -> None:
        """Session keys are each 32 bytes."""
        handshake_hash = bytes(32)

        initiator_key, responder_key = derive_session_keys(handshake_hash)

        assert len(initiator_key) == SYMMETRIC_KEY_SIZE
        assert len(responder_key) == SYMMETRIC_KEY_SIZE

    def test_derive_session_keys_different(self) -> None:
        """Initiator and responder keys are different."""
        handshake_hash = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )

        initiator_key, responder_key = derive_session_keys(handshake_hash)

        assert initiator_key != responder_key

    def test_derive_session_keys_deterministic(self) -> None:
        """Session key derivation is deterministic."""
        handshake_hash = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )

        i1, r1 = derive_session_keys(handshake_hash)
        i2, r2 = derive_session_keys(handshake_hash)

        assert i1 == i2
        assert r1 == r2

    def test_derive_session_keys_uses_correct_info(self) -> None:
        """Session key derivation uses 'nomad v1 session keys' as info."""
        assert SESSION_KEY_INFO == b"nomad v1 session keys"

    def test_derive_session_keys_from_vectors(self, handshake_vectors: dict) -> None:
        """Session keys match test vector."""
        kd = handshake_vectors["key_derivation"]["session_keys"]
        handshake_hash = bytes.fromhex(kd["handshake_hash"])
        expected_initiator = bytes.fromhex(kd["initiator_key"])
        expected_responder = bytes.fromhex(kd["responder_key"])

        initiator_key, responder_key = derive_session_keys(handshake_hash)

        assert initiator_key == expected_initiator
        assert responder_key == expected_responder


# =============================================================================
# Rekey Key Derivation Tests (PCS Fix)
# =============================================================================


class TestRekeyKeyDerivation:
    """Tests for rekey key derivation with PCS fix."""

    def test_derive_rekey_keys_length(self) -> None:
        """Rekey keys are each 32 bytes."""
        ephemeral_dh = bytes(32)
        rekey_auth_key = bytes(32)

        initiator_key, responder_key = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)

        assert len(initiator_key) == SYMMETRIC_KEY_SIZE
        assert len(responder_key) == SYMMETRIC_KEY_SIZE

    def test_derive_rekey_keys_different(self) -> None:
        """Initiator and responder rekey keys are different."""
        ephemeral_dh = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )
        rekey_auth_key = bytes.fromhex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )

        initiator_key, responder_key = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)

        assert initiator_key != responder_key

    def test_derive_rekey_keys_deterministic(self) -> None:
        """Rekey key derivation is deterministic."""
        ephemeral_dh = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )
        rekey_auth_key = bytes.fromhex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )

        i1, r1 = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)
        i2, r2 = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)

        assert i1 == i2
        assert r1 == r2

    def test_derive_rekey_keys_different_epochs(self) -> None:
        """Different epochs produce different keys."""
        ephemeral_dh = bytes.fromhex(
            "0102030405060708091011121314151617181920212223242526272829303132"
        )
        rekey_auth_key = bytes.fromhex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )

        i1, r1 = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)
        i2, r2 = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=2)

        assert i1 != i2
        assert r1 != r2

    def test_derive_rekey_keys_rejects_epoch_zero(self) -> None:
        """Rekey key derivation rejects epoch 0."""
        ephemeral_dh = bytes(32)
        rekey_auth_key = bytes(32)

        with pytest.raises(ValueError, match="epoch must be >= 1"):
            derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=0)

    def test_derive_rekey_keys_uses_correct_info_format(self) -> None:
        """Rekey uses 'nomad v1 rekey' || LE32(epoch) as info."""
        assert REKEY_INFO_PREFIX == b"nomad v1 rekey"

        # Verify epoch encoding
        epoch1_info = REKEY_INFO_PREFIX + struct.pack("<I", 1)
        assert epoch1_info == b"nomad v1 rekey\x01\x00\x00\x00"

        epoch2_info = REKEY_INFO_PREFIX + struct.pack("<I", 2)
        assert epoch2_info == b"nomad v1 rekey\x02\x00\x00\x00"


# =============================================================================
# Test Vector Validation
# =============================================================================


class TestRekeyVectors:
    """Tests validating against rekey_vectors.json5."""

    def test_epoch_0_to_1_vector(self, rekey_vectors: dict) -> None:
        """Epoch 0→1 rekey matches test vector."""
        vector = next(v for v in rekey_vectors["rekey_vectors"] if v["name"] == "epoch_0_to_1")

        ephemeral_dh = bytes.fromhex(vector["ephemeral_dh"])
        rekey_auth_key = bytes.fromhex(vector["rekey_auth_key"])
        expected_init = bytes.fromhex(vector["new_initiator_key"])
        expected_resp = bytes.fromhex(vector["new_responder_key"])

        initiator_key, responder_key = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)

        assert initiator_key == expected_init
        assert responder_key == expected_resp

    def test_epoch_1_to_2_pcs_vector(self, rekey_vectors: dict) -> None:
        """Epoch 1→2 rekey (PCS case) matches test vector."""
        vector = next(
            v for v in rekey_vectors["rekey_vectors"] if v["name"] == "epoch_1_to_2_pcs_case"
        )

        ephemeral_dh = bytes.fromhex(vector["ephemeral_dh"])
        rekey_auth_key = bytes.fromhex(vector["rekey_auth_key"])
        expected_init = bytes.fromhex(vector["new_initiator_key"])
        expected_resp = bytes.fromhex(vector["new_responder_key"])

        initiator_key, responder_key = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=2)

        assert initiator_key == expected_init
        assert responder_key == expected_resp

    def test_epoch_high_number_vector(self, rekey_vectors: dict) -> None:
        """High epoch number (100) matches test vector."""
        vector = next(v for v in rekey_vectors["rekey_vectors"] if v["name"] == "epoch_high_number")

        ephemeral_dh = bytes.fromhex(vector["ephemeral_dh"])
        rekey_auth_key = bytes.fromhex(vector["rekey_auth_key"])
        expected_init = bytes.fromhex(vector["new_initiator_key"])
        expected_resp = bytes.fromhex(vector["new_responder_key"])

        initiator_key, responder_key = derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=100)

        assert initiator_key == expected_init
        assert responder_key == expected_resp

    def test_ephemeral_dh_computation(self, rekey_vectors: dict) -> None:
        """Ephemeral DH computation matches test vectors."""
        for vector in rekey_vectors["rekey_vectors"]:
            init_priv = bytes.fromhex(vector["initiator_ephemeral"]["private_key"])
            resp_pub = bytes.fromhex(vector["responder_ephemeral"]["public_key"])
            expected_dh = bytes.fromhex(vector["ephemeral_dh"])

            result = compute_ephemeral_dh(init_priv, resp_pub)

            assert result == expected_dh, f"Failed for {vector['name']}"

    def test_info_encoding(self, rekey_vectors: dict) -> None:
        """Info parameter encoding matches test vectors."""
        for vector in rekey_vectors["rekey_vectors"]:
            epoch = vector["epoch"]
            expected_info = bytes.fromhex(vector["info"])

            computed_info = REKEY_INFO_PREFIX + struct.pack("<I", epoch)

            assert computed_info == expected_info, f"Failed for epoch {epoch}"


# =============================================================================
# Post-Compromise Security Tests
# =============================================================================


class TestPostCompromiseSecurity:
    """Tests demonstrating PCS property.

    The PCS fix ensures that an attacker who has compromised a session key
    cannot derive future session keys, because they don't have rekey_auth_key.
    """

    def test_pcs_without_auth_key_produces_different_keys(self, rekey_vectors: dict) -> None:
        """Without rekey_auth_key, attacker cannot derive correct keys.

        This test demonstrates that if an attacker only has the ephemeral DH
        (which they could compute if they inject their own ephemeral) but does
        NOT have rekey_auth_key, they get different (wrong) keys.
        """
        vector = next(
            v for v in rekey_vectors["rekey_vectors"] if v["name"] == "epoch_1_to_2_pcs_case"
        )

        ephemeral_dh = bytes.fromhex(vector["ephemeral_dh"])
        correct_auth_key = bytes.fromhex(vector["rekey_auth_key"])
        expected_init = bytes.fromhex(vector["new_initiator_key"])
        expected_resp = bytes.fromhex(vector["new_responder_key"])

        # Correct derivation with rekey_auth_key
        correct_init, correct_resp = derive_rekey_keys(ephemeral_dh, correct_auth_key, epoch=2)
        assert correct_init == expected_init
        assert correct_resp == expected_resp

        # Attacker's attempt without rekey_auth_key (using wrong/zero auth key)
        fake_auth_key = bytes(32)  # Attacker doesn't know the real rekey_auth_key
        attacker_init, attacker_resp = derive_rekey_keys(ephemeral_dh, fake_auth_key, epoch=2)

        # Attacker gets different keys - they cannot maintain access!
        assert attacker_init != expected_init
        assert attacker_resp != expected_resp

    def test_rekey_auth_key_requires_static_dh(self, rekey_vectors: dict) -> None:
        """rekey_auth_key can only be computed with static keys.

        An attacker who only has session keys (from compromise) cannot
        compute rekey_auth_key because they don't have the static private keys.
        """
        intermediate = rekey_vectors["intermediate_values"]
        static_keys = intermediate["static_keys"]

        # Correct derivation (requires static private key)
        initiator_static_priv = bytes.fromhex(static_keys["initiator_static_private"])
        responder_static_pub = bytes.fromhex(static_keys["responder_static_public"])
        static_dh = compute_static_dh(initiator_static_priv, responder_static_pub)
        correct_auth_key = derive_rekey_auth_key(static_dh)

        expected_auth_key = bytes.fromhex(intermediate["rekey_auth_key"]["output"])
        assert correct_auth_key == expected_auth_key

        # Attacker cannot compute static DH without private keys
        # (they only have session keys from the compromise)
        # This is the fundamental security property:
        # DH requires the private key, which never leaves the endpoint


# =============================================================================
# NomadCodec Integration Tests
# =============================================================================


class TestNomadCodecRekeyMethods:
    """Tests for NomadCodec rekey-related methods."""

    def test_codec_derive_rekey_auth_key(self, codec: NomadCodec, rekey_vectors: dict) -> None:
        """NomadCodec.derive_rekey_auth_key works correctly."""
        intermediate = rekey_vectors["intermediate_values"]
        static_dh = bytes.fromhex(intermediate["static_dh"])
        expected = bytes.fromhex(intermediate["rekey_auth_key"]["output"])

        result = codec.derive_rekey_auth_key(static_dh)

        assert result == expected

    def test_codec_derive_rekey_keys(self, codec: NomadCodec, rekey_vectors: dict) -> None:
        """NomadCodec.derive_rekey_keys works correctly."""
        vector = next(v for v in rekey_vectors["rekey_vectors"] if v["name"] == "epoch_0_to_1")

        ephemeral_dh = bytes.fromhex(vector["ephemeral_dh"])
        rekey_auth_key = bytes.fromhex(vector["rekey_auth_key"])
        expected_init = bytes.fromhex(vector["new_initiator_key"])
        expected_resp = bytes.fromhex(vector["new_responder_key"])

        init_key, resp_key = codec.derive_rekey_keys(ephemeral_dh, rekey_auth_key, epoch=1)

        assert init_key == expected_init
        assert resp_key == expected_resp

    def test_codec_compute_static_dh(self, codec: NomadCodec, rekey_vectors: dict) -> None:
        """NomadCodec.compute_static_dh works correctly."""
        intermediate = rekey_vectors["intermediate_values"]
        static_keys = intermediate["static_keys"]

        initiator_priv = bytes.fromhex(static_keys["initiator_static_private"])
        responder_pub = bytes.fromhex(static_keys["responder_static_public"])
        expected = bytes.fromhex(intermediate["static_dh"])

        result = codec.compute_static_dh(initiator_priv, responder_pub)

        assert result == expected

    def test_codec_hkdf_expand(self, codec: NomadCodec) -> None:
        """NomadCodec.hkdf_expand works correctly."""
        prk = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")
        info = b"test"

        result = codec.hkdf_expand(prk, info, 32)

        assert len(result) == 32
        assert result == hkdf_expand(prk, info, 32)

    def test_codec_exposes_constants(self, codec: NomadCodec) -> None:
        """NomadCodec exposes key derivation constants."""
        assert codec.SESSION_KEY_INFO == b"nomad v1 session keys"
        assert codec.REKEY_AUTH_INFO == b"nomad v1 rekey auth"
        assert codec.REKEY_INFO_PREFIX == b"nomad v1 rekey"
        assert codec.SYMMETRIC_KEY_SIZE == 32
        assert codec.REKEY_AUTH_KEY_SIZE == 32
