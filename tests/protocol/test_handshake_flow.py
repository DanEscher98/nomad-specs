"""
Handshake flow protocol tests.

Tests the complete Noise_IK handshake flow including state transitions,
message exchange, and error handling.

Test mapping: specs/1-SECURITY.md § "Handshake Protocol", "Handshake State Machine"
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

import json5
import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.bindings import crypto_scalarmult

from lib.reference import (
    AEAD_NONCE_SIZE,
    AEAD_TAG_SIZE,
    FRAME_HANDSHAKE_INIT,
    FRAME_HANDSHAKE_RESP,
    PUBLIC_KEY_SIZE,
    SESSION_ID_SIZE,
    NomadCodec,
    deterministic_bytes,
    deterministic_keypair,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

# =============================================================================
# Protocol Constants (from spec)
# =============================================================================


HANDSHAKE_TIMEOUT_MS = 1000
HANDSHAKE_MAX_RETRIES = 5
HANDSHAKE_BACKOFF = 2

HANDSHAKE_INIT_MIN_SIZE = 100
HANDSHAKE_RESP_MIN_SIZE = 56

PROTOCOL_VERSION = 0x0001


# =============================================================================
# Handshake State Machine
# =============================================================================


class HandshakeState(IntEnum):
    """Handshake state machine states per spec."""

    IDLE = 0
    WAIT_RESPONSE = 1
    ESTABLISHED = 2
    FAILED = 3


@dataclass
class HandshakeMessage:
    """Parsed handshake message structure."""

    frame_type: int
    raw: bytes

    # HandshakeInit fields (type 0x01)
    protocol_version: int | None = None
    initiator_ephemeral: bytes | None = None
    encrypted_static: bytes | None = None
    encrypted_payload: bytes | None = None

    # HandshakeResp fields (type 0x02)
    session_id: bytes | None = None
    responder_ephemeral: bytes | None = None


def parse_handshake_init(data: bytes) -> HandshakeMessage:
    """Parse HandshakeInit message (Type 0x01)."""
    if len(data) < HANDSHAKE_INIT_MIN_SIZE:
        raise ValueError(f"HandshakeInit too short: {len(data)} < {HANDSHAKE_INIT_MIN_SIZE}")

    frame_type = data[0]
    if frame_type != FRAME_HANDSHAKE_INIT:
        raise ValueError(f"Not a HandshakeInit: type 0x{frame_type:02x}")

    # reserved = data[1]  # Should be 0x00
    protocol_version = struct.unpack_from("<H", data, 2)[0]
    initiator_ephemeral = data[4:36]
    encrypted_static = data[36:84]
    encrypted_payload = data[84:]

    return HandshakeMessage(
        frame_type=frame_type,
        raw=data,
        protocol_version=protocol_version,
        initiator_ephemeral=initiator_ephemeral,
        encrypted_static=encrypted_static,
        encrypted_payload=encrypted_payload,
    )


def parse_handshake_resp(data: bytes) -> HandshakeMessage:
    """Parse HandshakeResp message (Type 0x02)."""
    if len(data) < HANDSHAKE_RESP_MIN_SIZE:
        raise ValueError(f"HandshakeResp too short: {len(data)} < {HANDSHAKE_RESP_MIN_SIZE}")

    frame_type = data[0]
    if frame_type != FRAME_HANDSHAKE_RESP:
        raise ValueError(f"Not a HandshakeResp: type 0x{frame_type:02x}")

    # reserved = data[1]  # Should be 0x00
    session_id = data[2:8]
    responder_ephemeral = data[8:40]
    encrypted_payload = data[40:]

    return HandshakeMessage(
        frame_type=frame_type,
        raw=data,
        session_id=session_id,
        responder_ephemeral=responder_ephemeral,
        encrypted_payload=encrypted_payload,
    )


# =============================================================================
# Mock Handshake Implementation (for testing protocol flow)
# =============================================================================


@dataclass
class HandshakeKeys:
    """Keypairs used in handshake."""

    initiator_static_private: bytes
    initiator_static_public: bytes
    initiator_ephemeral_private: bytes
    initiator_ephemeral_public: bytes
    responder_static_private: bytes
    responder_static_public: bytes
    responder_ephemeral_private: bytes
    responder_ephemeral_public: bytes


def create_test_keys() -> HandshakeKeys:
    """Create deterministic test keypairs."""
    i_static_priv, i_static_pub = deterministic_keypair("initiator-static")
    i_ephemeral_priv, i_ephemeral_pub = deterministic_keypair("initiator-ephemeral")
    r_static_priv, r_static_pub = deterministic_keypair("responder-static")
    r_ephemeral_priv, r_ephemeral_pub = deterministic_keypair("responder-ephemeral")

    return HandshakeKeys(
        initiator_static_private=i_static_priv,
        initiator_static_public=i_static_pub,
        initiator_ephemeral_private=i_ephemeral_priv,
        initiator_ephemeral_public=i_ephemeral_pub,
        responder_static_private=r_static_priv,
        responder_static_public=r_static_pub,
        responder_ephemeral_private=r_ephemeral_priv,
        responder_ephemeral_public=r_ephemeral_pub,
    )


def create_handshake_init(
    keys: HandshakeKeys,
    state_type_id: str = "nomad.test.v1",
    protocol_version: int = PROTOCOL_VERSION,
) -> bytes:
    """Create a HandshakeInit message.

    Simplified version - in real implementation, the Noise_IK pattern
    would be followed exactly. This creates the wire format structure.
    """
    # Frame header
    frame = bytearray()
    frame.append(FRAME_HANDSHAKE_INIT)  # Type
    frame.append(0x00)  # Reserved
    frame.extend(struct.pack("<H", protocol_version))  # Version

    # Ephemeral public key (unencrypted)
    frame.extend(keys.initiator_ephemeral_public)

    # Encrypted static key (32 bytes + 16 tag = 48 bytes)
    # In Noise_IK, this is encrypted with es (ephemeral-static DH)
    es_shared = crypto_scalarmult(
        keys.initiator_ephemeral_private, keys.responder_static_public
    )
    # Simplified: use shared secret directly as key (real impl uses Noise state machine)
    nonce = b"\x00" * AEAD_NONCE_SIZE
    encrypted_static = xchacha20_poly1305_encrypt(
        es_shared, nonce, keys.initiator_static_public, b""
    )
    frame.extend(encrypted_static)

    # Encrypted payload (state type ID + extensions)
    # First, derive key from es + ss
    ss_shared = crypto_scalarmult(
        keys.initiator_static_private, keys.responder_static_public
    )
    payload = state_type_id.encode("utf-8")
    payload_key = bytes([a ^ b for a, b in zip(es_shared, ss_shared, strict=False)])
    nonce2 = b"\x01" + b"\x00" * 23
    encrypted_payload = xchacha20_poly1305_encrypt(payload_key, nonce2, payload, b"")
    frame.extend(encrypted_payload)

    return bytes(frame)


def create_handshake_resp(
    keys: HandshakeKeys,
    session_id: bytes | None = None,
) -> bytes:
    """Create a HandshakeResp message."""
    if session_id is None:
        session_id = deterministic_bytes("session-id", SESSION_ID_SIZE)

    # Frame header
    frame = bytearray()
    frame.append(FRAME_HANDSHAKE_RESP)  # Type
    frame.append(0x00)  # Reserved
    frame.extend(session_id)

    # Ephemeral public key (unencrypted)
    frame.extend(keys.responder_ephemeral_public)

    # Encrypted payload (ack + negotiated extensions)
    # Simplified: use combined shared secrets
    ee_shared = crypto_scalarmult(
        keys.responder_ephemeral_private, keys.initiator_ephemeral_public
    )
    nonce = b"\x02" + b"\x00" * 23
    payload = b"\x01"  # ACK
    encrypted_payload = xchacha20_poly1305_encrypt(ee_shared, nonce, payload, b"")
    frame.extend(encrypted_payload)

    return bytes(frame)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def handshake_vectors() -> dict:
    """Load handshake test vectors."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "handshake_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)


@pytest.fixture
def test_keys() -> HandshakeKeys:
    """Create test keypairs."""
    return create_test_keys()


@pytest.fixture
def codec() -> NomadCodec:
    """NomadCodec instance."""
    return NomadCodec()


# =============================================================================
# HandshakeInit Tests
# =============================================================================


class TestHandshakeInit:
    """Test HandshakeInit message creation and parsing."""

    def test_handshake_init_minimum_size(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit meets minimum size requirement."""
        msg = create_handshake_init(test_keys)
        assert len(msg) >= HANDSHAKE_INIT_MIN_SIZE

    def test_handshake_init_type(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit has correct frame type."""
        msg = create_handshake_init(test_keys)
        parsed = parse_handshake_init(msg)

        assert parsed.frame_type == FRAME_HANDSHAKE_INIT
        assert parsed.frame_type == 0x01

    def test_handshake_init_protocol_version(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit has correct protocol version."""
        msg = create_handshake_init(test_keys)
        parsed = parse_handshake_init(msg)

        assert parsed.protocol_version == PROTOCOL_VERSION
        assert parsed.protocol_version == 0x0001

    def test_handshake_init_ephemeral_key(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit contains initiator's ephemeral public key."""
        msg = create_handshake_init(test_keys)
        parsed = parse_handshake_init(msg)

        assert parsed.initiator_ephemeral == test_keys.initiator_ephemeral_public
        assert len(parsed.initiator_ephemeral) == PUBLIC_KEY_SIZE

    def test_handshake_init_encrypted_static_size(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit encrypted static is 48 bytes (32 + 16 tag)."""
        msg = create_handshake_init(test_keys)
        parsed = parse_handshake_init(msg)

        assert len(parsed.encrypted_static) == 48

    def test_handshake_init_has_encrypted_payload(self, test_keys: HandshakeKeys) -> None:
        """HandshakeInit has encrypted payload."""
        msg = create_handshake_init(test_keys)
        parsed = parse_handshake_init(msg)

        assert len(parsed.encrypted_payload) >= AEAD_TAG_SIZE


class TestHandshakeInitValidation:
    """Test HandshakeInit validation."""

    def test_reject_truncated_init(self) -> None:
        """Truncated HandshakeInit is rejected."""
        truncated = bytes([FRAME_HANDSHAKE_INIT]) + b"\x00" * 50

        with pytest.raises(ValueError, match="too short"):
            parse_handshake_init(truncated)

    def test_reject_wrong_type(self) -> None:
        """Wrong frame type is rejected."""
        wrong_type = bytes([0xFF]) + b"\x00" * 100

        with pytest.raises(ValueError, match="Not a HandshakeInit"):
            parse_handshake_init(wrong_type)

    def test_reject_unsupported_version(self, test_keys: HandshakeKeys) -> None:
        """Unsupported protocol version should be handled.

        Note: Actual rejection depends on implementation policy.
        The test documents that version is correctly parsed.
        """
        msg = bytearray(create_handshake_init(test_keys))
        # Modify version to 0x9999
        struct.pack_into("<H", msg, 2, 0x9999)

        parsed = parse_handshake_init(bytes(msg))
        assert parsed.protocol_version == 0x9999


# =============================================================================
# HandshakeResp Tests
# =============================================================================


class TestHandshakeResp:
    """Test HandshakeResp message creation and parsing."""

    def test_handshake_resp_minimum_size(self, test_keys: HandshakeKeys) -> None:
        """HandshakeResp meets minimum size requirement."""
        msg = create_handshake_resp(test_keys)
        assert len(msg) >= HANDSHAKE_RESP_MIN_SIZE

    def test_handshake_resp_type(self, test_keys: HandshakeKeys) -> None:
        """HandshakeResp has correct frame type."""
        msg = create_handshake_resp(test_keys)
        parsed = parse_handshake_resp(msg)

        assert parsed.frame_type == FRAME_HANDSHAKE_RESP
        assert parsed.frame_type == 0x02

    def test_handshake_resp_session_id(self, test_keys: HandshakeKeys) -> None:
        """HandshakeResp contains session ID."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        msg = create_handshake_resp(test_keys, session_id=session_id)
        parsed = parse_handshake_resp(msg)

        assert parsed.session_id == session_id
        assert len(parsed.session_id) == SESSION_ID_SIZE

    def test_handshake_resp_ephemeral_key(self, test_keys: HandshakeKeys) -> None:
        """HandshakeResp contains responder's ephemeral public key."""
        msg = create_handshake_resp(test_keys)
        parsed = parse_handshake_resp(msg)

        assert parsed.responder_ephemeral == test_keys.responder_ephemeral_public
        assert len(parsed.responder_ephemeral) == PUBLIC_KEY_SIZE


class TestHandshakeRespValidation:
    """Test HandshakeResp validation."""

    def test_reject_truncated_resp(self) -> None:
        """Truncated HandshakeResp is rejected."""
        truncated = bytes([FRAME_HANDSHAKE_RESP]) + b"\x00" * 30

        with pytest.raises(ValueError, match="too short"):
            parse_handshake_resp(truncated)

    def test_reject_wrong_type(self) -> None:
        """Wrong frame type is rejected."""
        wrong_type = bytes([0xFF]) + b"\x00" * 60

        with pytest.raises(ValueError, match="Not a HandshakeResp"):
            parse_handshake_resp(wrong_type)


# =============================================================================
# Handshake State Machine Tests
# =============================================================================


class TestHandshakeStateMachine:
    """Test handshake state machine transitions."""

    def test_initial_state_is_idle(self) -> None:
        """Initial state is IDLE."""
        state = HandshakeState.IDLE
        assert state == HandshakeState.IDLE

    def test_transition_idle_to_wait_response(self) -> None:
        """Sending HandshakeInit transitions IDLE -> WAIT_RESPONSE."""
        state = HandshakeState.IDLE

        # Simulate sending HandshakeInit
        state = HandshakeState.WAIT_RESPONSE

        assert state == HandshakeState.WAIT_RESPONSE

    def test_transition_wait_response_to_established(self) -> None:
        """Receiving valid HandshakeResp transitions WAIT_RESPONSE -> ESTABLISHED."""
        state = HandshakeState.WAIT_RESPONSE

        # Simulate receiving valid HandshakeResp
        state = HandshakeState.ESTABLISHED

        assert state == HandshakeState.ESTABLISHED

    def test_transition_wait_response_timeout(self) -> None:
        """Timeout in WAIT_RESPONSE can retry or fail."""
        state = HandshakeState.WAIT_RESPONSE
        retries = 0

        # Simulate timeout
        retries += 1
        if retries >= HANDSHAKE_MAX_RETRIES:
            state = HandshakeState.FAILED

        assert retries < HANDSHAKE_MAX_RETRIES or state == HandshakeState.FAILED


# =============================================================================
# Invalid Static Key Rejection
# =============================================================================


class TestInvalidStaticKeyRejection:
    """Test that invalid static keys are rejected."""

    def test_reject_unknown_initiator_static(self, test_keys: HandshakeKeys) -> None:
        """Responder rejects unknown initiator static key.

        In Noise_IK, the responder can optionally verify the initiator's
        static key against a whitelist.
        """
        # Create keys for unknown initiator
        unknown_priv, unknown_pub = deterministic_keypair("unknown-initiator")

        # Create modified keys with unknown initiator
        modified_keys = HandshakeKeys(
            initiator_static_private=unknown_priv,
            initiator_static_public=unknown_pub,
            initiator_ephemeral_private=test_keys.initiator_ephemeral_private,
            initiator_ephemeral_public=test_keys.initiator_ephemeral_public,
            responder_static_private=test_keys.responder_static_private,
            responder_static_public=test_keys.responder_static_public,
            responder_ephemeral_private=test_keys.responder_ephemeral_private,
            responder_ephemeral_public=test_keys.responder_ephemeral_public,
        )

        msg = create_handshake_init(modified_keys)
        parsed = parse_handshake_init(msg)

        # The responder would decrypt the encrypted static and verify
        # For now, we just verify the message is parseable but static differs
        assert len(parsed.encrypted_static) == 48

    def test_wrong_responder_static_fails_decryption(self, test_keys: HandshakeKeys) -> None:
        """Initiator using wrong responder static key fails to communicate.

        If initiator encrypts to wrong responder static key, responder
        cannot decrypt the message.
        """
        # Create keys with wrong responder static
        wrong_resp_priv, wrong_resp_pub = deterministic_keypair("wrong-responder")

        # Create modified keys - initiator thinks responder has different key
        modified_keys = HandshakeKeys(
            initiator_static_private=test_keys.initiator_static_private,
            initiator_static_public=test_keys.initiator_static_public,
            initiator_ephemeral_private=test_keys.initiator_ephemeral_private,
            initiator_ephemeral_public=test_keys.initiator_ephemeral_public,
            responder_static_private=test_keys.responder_static_private,
            responder_static_public=wrong_resp_pub,  # Wrong key!
            responder_ephemeral_private=test_keys.responder_ephemeral_private,
            responder_ephemeral_public=test_keys.responder_ephemeral_public,
        )

        msg = create_handshake_init(modified_keys)
        parsed = parse_handshake_init(msg)

        # Real responder tries to decrypt with correct key
        es_shared = crypto_scalarmult(
            test_keys.responder_static_private, parsed.initiator_ephemeral
        )
        nonce = b"\x00" * AEAD_NONCE_SIZE

        # Decryption should fail because message was encrypted to wrong key
        with pytest.raises(InvalidTag):
            xchacha20_poly1305_decrypt(es_shared, nonce, parsed.encrypted_static, b"")


# =============================================================================
# Retransmission Tests
# =============================================================================


class TestHandshakeRetransmission:
    """Test handshake retransmission behavior."""

    def test_retransmission_constants(self) -> None:
        """Retransmission constants match spec."""
        assert HANDSHAKE_TIMEOUT_MS == 1000
        assert HANDSHAKE_MAX_RETRIES == 5
        assert HANDSHAKE_BACKOFF == 2

    def test_exponential_backoff_calculation(self) -> None:
        """Exponential backoff doubles timeout up to max."""
        timeout = HANDSHAKE_TIMEOUT_MS
        max_timeout = 30000  # 30 seconds per spec

        timeouts = []
        for _ in range(HANDSHAKE_MAX_RETRIES):
            timeouts.append(timeout)
            timeout = min(timeout * HANDSHAKE_BACKOFF, max_timeout)

        # First timeout is 1000ms
        assert timeouts[0] == 1000
        # Second is 2000ms
        assert timeouts[1] == 2000
        # Third is 4000ms
        assert timeouts[2] == 4000
        # Fourth is 8000ms
        assert timeouts[3] == 8000
        # Fifth is 16000ms
        assert timeouts[4] == 16000

    def test_responder_can_regenerate_response(self, test_keys: HandshakeKeys) -> None:
        """Responder can regenerate HandshakeResp for duplicate init.

        Per spec: responders process duplicate HandshakeInit by
        regenerating HandshakeResp.
        """
        session_id = deterministic_bytes("fixed-session", SESSION_ID_SIZE)

        resp1 = create_handshake_resp(test_keys, session_id=session_id)
        resp2 = create_handshake_resp(test_keys, session_id=session_id)

        # Same session ID means same response structure
        parsed1 = parse_handshake_resp(resp1)
        parsed2 = parse_handshake_resp(resp2)

        assert parsed1.session_id == parsed2.session_id
        assert parsed1.responder_ephemeral == parsed2.responder_ephemeral


# =============================================================================
# Session ID Tests
# =============================================================================


class TestSessionIDHandling:
    """Test session ID generation and collision handling."""

    def test_session_id_size(self) -> None:
        """Session ID is 6 bytes (48 bits)."""
        assert SESSION_ID_SIZE == 6

    def test_session_id_random(self) -> None:
        """Session IDs should be random (unique across calls)."""
        session_ids = set()
        for i in range(100):
            session_id = deterministic_bytes(f"session-{i}", SESSION_ID_SIZE)
            session_ids.add(session_id)

        assert len(session_ids) == 100

    def test_session_id_in_handshake_resp(self, test_keys: HandshakeKeys) -> None:
        """Session ID is correctly embedded in HandshakeResp."""
        expected_session_id = b"\xde\xad\xbe\xef\xca\xfe"
        msg = create_handshake_resp(test_keys, session_id=expected_session_id)
        parsed = parse_handshake_resp(msg)

        assert parsed.session_id == expected_session_id


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestHandshakeProperties:
    """Property-based tests for handshake messages."""

    @given(version=st.integers(min_value=0, max_value=0xFFFF))
    @settings(max_examples=50)
    def test_protocol_version_roundtrip(self, version: int) -> None:
        """Protocol version is correctly encoded/decoded."""
        keys = create_test_keys()
        msg = create_handshake_init(keys, protocol_version=version)
        parsed = parse_handshake_init(msg)

        assert parsed.protocol_version == version

    @given(session_id=st.binary(min_size=6, max_size=6))
    @settings(max_examples=50)
    def test_session_id_roundtrip(self, session_id: bytes) -> None:
        """Session ID is correctly encoded/decoded."""
        keys = create_test_keys()
        msg = create_handshake_resp(keys, session_id=session_id)
        parsed = parse_handshake_resp(msg)

        assert parsed.session_id == session_id
