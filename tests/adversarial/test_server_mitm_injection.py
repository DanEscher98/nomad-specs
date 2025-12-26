"""
MITM Injection Tests for NOMAD Protocol.

These tests verify that implementations correctly reject injected (forged) frames
that lack valid AEAD authentication.

Per spec (1-SECURITY.md, 2-TRANSPORT.md):
- All frames require valid AEAD authentication
- Invalid frames are silently dropped (no error response)
- Silent drops prevent confirmation of session existence to attackers

Security property: Authentication prevents attackers from injecting arbitrary
frames into existing sessions.
"""

from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lib.reference import (
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    NomadCodec,
)

if TYPE_CHECKING:
    from lib.attacker import MITMAttacker


# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


class TestForgedFrameInjection:
    """Tests for injection of forged frames with invalid authentication."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    @pytest.fixture
    def session_context(self, codec: NomadCodec) -> dict:
        """Create session context for testing."""
        key = codec.deterministic_bytes("injection-test-key", 32)
        session_id = codec.deterministic_bytes("injection-session", 6)
        return {
            "key": key,
            "session_id": session_id,
            "epoch": 0,
            "direction": 0,
        }

    def test_inject_forged_frame_random_tag_dropped(
        self, codec: NomadCodec, session_context: dict
    ) -> None:
        """Forged frame with random tag MUST be dropped.

        Spec: 2-TRANSPORT.md §Error Handling
        "Invalid AEAD tag: Silently drop"

        Attack scenario:
        1. Attacker knows session ID (e.g., from observing traffic)
        2. Attacker creates frame with correct header but random tag
        3. Implementation MUST drop frame silently
        """
        # Create forged frame with correct session ID but random payload/tag
        session_id = session_context["session_id"]

        # Build header
        header = bytearray(DATA_FRAME_HEADER_SIZE)
        header[0] = FRAME_DATA
        header[1] = 0x00  # No flags
        header[2:8] = session_id
        struct.pack_into("<Q", header, 8, 1000)  # Some nonce

        # Random "encrypted" payload with random tag
        fake_payload = os.urandom(50)

        forged_frame = bytes(header) + fake_payload

        # Should fail AEAD verification
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                forged_frame,
                session_context["key"],
                session_context["epoch"],
                session_context["direction"],
            )

    def test_inject_frame_wrong_session_id_dropped(
        self, codec: NomadCodec, session_context: dict
    ) -> None:
        """Frame with wrong session ID MUST be dropped.

        Spec: 2-TRANSPORT.md §Error Handling
        "Unknown session ID: Silently drop"

        Attack scenario:
        1. Attacker captures valid frame from one session
        2. Attacker modifies session ID to target different session
        3. Both sessions should reject (AAD mismatch or unknown session)
        """
        # Create valid frame
        sync = codec.create_sync_message(1, 0, 0, b"test payload")
        valid_frame = codec.create_data_frame(
            session_id=session_context["session_id"],
            nonce_counter=100,
            key=session_context["key"],
            epoch=session_context["epoch"],
            direction=session_context["direction"],
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Modify session ID to a different (wrong) one
        wrong_session_id = os.urandom(6)
        modified = bytearray(valid_frame)
        modified[2:8] = wrong_session_id
        modified = bytes(modified)

        # Should fail because session ID is in AAD
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                modified,
                session_context["key"],
                session_context["epoch"],
                session_context["direction"],
            )

    def test_inject_valid_looking_unsigned_frame_dropped(
        self, codec: NomadCodec, session_context: dict
    ) -> None:
        """Valid-looking but unauthenticated frame MUST be dropped.

        Attack scenario:
        1. Attacker constructs frame that looks structurally valid
        2. Frame has valid header, valid-looking payload structure
        3. But no valid AEAD tag (attacker doesn't have key)
        4. MUST be rejected
        """
        session_id = session_context["session_id"]

        # Build structurally valid header
        header = codec.create_data_frame_header(
            flags=0x00,
            session_id=session_id,
            nonce_counter=500,
        )

        # Build structurally valid (but unsigned) payload
        # Payload header: timestamp (4) + timestamp_echo (4) + length (2)
        payload_header = struct.pack("<IIH", 1000, 0, 28)

        # Sync message: sender(8) + acked(8) + base(8) + len(4) + diff
        sync_header = struct.pack("<QQQI", 1, 0, 0, 4)
        diff = b"test"

        plaintext = payload_header + sync_header + diff

        # "Encrypt" with wrong key (simulates attacker not having real key)
        wrong_key = os.urandom(32)
        nonce = codec.construct_nonce(0, 0, 500)
        fake_ciphertext = codec.encrypt(wrong_key, nonce, plaintext, header)

        forged_frame = header + fake_ciphertext

        # Should fail with real session key
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                forged_frame,
                session_context["key"],
                session_context["epoch"],
                session_context["direction"],
            )


@pytest.mark.scapy_attack
class TestInjectionWithAttacker:
    """Tests using the MITMAttacker injection functionality.

    Requires: test-runner container with NET_RAW capability.
    Run with: just docker-test-runner -m scapy_attack adversarial/
    """

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_attacker_forge_frame_produces_invalid_frame(
        self, codec: NomadCodec, attacker: MITMAttacker
    ) -> None:
        """Verify attacker.forge_frame produces frames that fail AEAD."""
        key = codec.deterministic_bytes("forge-test-key", 32)
        session_id = codec.deterministic_bytes("forge-session", 6)

        # Use attacker's forge function
        forged = attacker.forge_frame(
            session_id=session_id,
            nonce_counter=42,
            payload=None,  # Random payload
        )

        # Should fail AEAD (attacker doesn't know the key)
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(forged, key, 0, 0)

    @given(nonce=st.integers(min_value=0, max_value=2**63 - 1))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_forged_frame_any_nonce_rejected(
        self, codec: NomadCodec, attacker: MITMAttacker, nonce: int
    ) -> None:
        """Forged frames are rejected regardless of nonce value."""
        key = codec.deterministic_bytes("forge-nonce-key", 32)
        session_id = codec.deterministic_bytes("forge-nonce-session", 6)

        forged = attacker.forge_frame(
            session_id=session_id,
            nonce_counter=nonce,
        )

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(forged, key, 0, 0)


class TestKeyGuessingAttack:
    """Tests for attacks that attempt to guess the session key."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_wrong_key_always_fails(self, codec: NomadCodec) -> None:
        """Decryption with wrong key always fails.

        XChaCha20-Poly1305 key space is 256 bits.
        Probability of guessing: 1/2^256 (computationally infeasible).
        """
        real_key = codec.deterministic_bytes("real-key", 32)
        session_id = codec.deterministic_bytes("key-guess-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"secret data")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=real_key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Try 10 random wrong keys (symbolically represents key space)
        for _ in range(10):
            wrong_key = os.urandom(32)
            if wrong_key == real_key:
                continue  # Astronomically unlikely

            with pytest.raises(InvalidTag):
                codec.parse_data_frame(frame, wrong_key, 0, 0)

    def test_partial_key_knowledge_useless(self, codec: NomadCodec) -> None:
        """Even knowing part of the key doesn't help.

        If attacker knows 31 of 32 bytes, they still can't authenticate.
        """
        real_key = codec.deterministic_bytes("partial-key-real", 32)
        session_id = codec.deterministic_bytes("partial-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"test")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=real_key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Attacker knows 31 bytes, guesses the last byte
        for guess in range(256):
            partial_key = real_key[:31] + bytes([guess])
            if partial_key == real_key:
                continue

            with pytest.raises(InvalidTag):
                codec.parse_data_frame(frame, partial_key, 0, 0)


class TestSilentDropBehavior:
    """Tests verifying silent drop behavior (no error oracle)."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_invalid_tag_raises_same_exception(self, codec: NomadCodec) -> None:
        """All invalid frames should raise the same exception type.

        Spec: 2-TRANSPORT.md §Error Handling
        "Invalid AEAD tag: Silently drop"
        "Reject frames with invalid AEAD tags without timing differences"

        Different error types could create an oracle.
        """
        key = codec.deterministic_bytes("oracle-key", 32)
        session_id = codec.deterministic_bytes("oracle-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"test")
        valid = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Different types of invalid frames should all raise InvalidTag
        invalid_frames = [
            # Bit flip in ciphertext
            valid[:20] + bytes([valid[20] ^ 0x01]) + valid[21:],
            # Random tag
            valid[:-16] + os.urandom(16),
            # Wrong key (create new frame)
            codec.create_data_frame(
                session_id=session_id,
                nonce_counter=2,
                key=os.urandom(32),  # Wrong key
                epoch=0,
                direction=0,
                timestamp=1000,
                timestamp_echo=0,
                sync_message=sync,
            ),
        ]

        for invalid in invalid_frames:
            with pytest.raises(InvalidTag):
                codec.parse_data_frame(invalid, key, 0, 0)


class TestFrameTypeManipulation:
    """Tests for frame type manipulation attacks."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_cannot_change_frame_type(self, codec: NomadCodec) -> None:
        """Attacker cannot change frame type without detection.

        Frame type is in AAD, so changing it invalidates the tag.
        """
        key = codec.deterministic_bytes("frame-type-key", 32)
        session_id = codec.deterministic_bytes("frame-type-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"test")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Try to change to each other frame type
        for frame_type in [0x01, 0x02, 0x04, 0x05]:  # Init, Resp, Rekey, Close
            modified = bytes([frame_type]) + frame[1:]
            with pytest.raises((InvalidTag, ValueError)):
                codec.parse_data_frame(modified, key, 0, 0)


class TestInjectionIntegration:
    """Integration tests for injection attacks with containers."""

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_inject_forged_frame_integration(
        self,
        attacker: MITMAttacker,
        server_container,
    ) -> None:
        """Integration test: inject forged frame.

        This test:
        1. Forges a frame for a guessed session ID
        2. Injects it toward the server
        3. Server should silently drop (no response)
        """
        # Forge frame with guessed session ID
        forged = attacker.forge_frame(
            session_id=os.urandom(6),
            nonce_counter=1,
        )

        # Inject toward server
        attacker.inject_frame(
            forged,
            dst_ip="172.31.0.10",  # Server IP
            dst_port=19999,
        )

        # Should be silently dropped (no way to verify without logs)
        assert attacker.stats.frames_injected >= 1
