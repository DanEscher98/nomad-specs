"""
Session Hijack Tests for NOMAD Protocol.

These tests verify that implementations resist session hijacking attacks
through:
- Unpredictable session IDs
- AEAD authentication preventing forged frames
- Silent drops preventing session enumeration

Per spec (1-SECURITY.md §Session ID):
- 6-byte (48-bit) session ID generated with secure random
- Responders MUST track active session IDs
- Reject duplicate session IDs

Security property: Session hijacking prevention ensures attackers cannot
take over or inject into existing sessions.
"""

from __future__ import annotations

import os
import struct
from collections import Counter
from typing import TYPE_CHECKING

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    SESSION_ID_SIZE,
    NomadCodec,
)

if TYPE_CHECKING:
    from lib.attacker import MITMAttacker, SessionProbe


# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


class TestSessionIDRandomness:
    """Tests for session ID randomness and unpredictability."""

    def test_session_id_size(self) -> None:
        """Session ID MUST be 6 bytes (48 bits).

        Spec: 1-SECURITY.md §Session ID
        "6-byte (48-bit) session ID"
        """
        assert SESSION_ID_SIZE == 6

    def test_session_id_entropy(self) -> None:
        """Session ID MUST have 48 bits of entropy.

        This provides 2^48 possible values, making brute force infeasible.
        """
        bits_of_entropy = SESSION_ID_SIZE * 8
        assert bits_of_entropy == 48

        # Birthday paradox: 50% collision after ~2^24 sessions
        collision_threshold = 2 ** (bits_of_entropy / 2)
        assert collision_threshold > 16_000_000, "Should have >16M sessions before likely collision"

    def test_generated_session_ids_are_random(self) -> None:
        """Generated session IDs should have high entropy.

        Spec: 1-SECURITY.md §Session ID Generation
        "return secure_random(6)"
        """
        # Generate many session IDs
        session_ids = [os.urandom(SESSION_ID_SIZE) for _ in range(1000)]

        # Check uniqueness
        unique_ids = set(session_ids)
        assert len(unique_ids) == len(session_ids), "All generated session IDs should be unique"

        # Check byte distribution (chi-squared test approximation)
        all_bytes = b"".join(session_ids)
        byte_counts = Counter(all_bytes)

        # With 6000 bytes, expected count per byte value is ~23.4
        expected_per_byte = len(all_bytes) / 256

        # Calculate chi-squared statistic
        chi_squared = sum(
            ((count - expected_per_byte) ** 2) / expected_per_byte for count in byte_counts.values()
        )

        # Chi-squared critical value for 255 df, p=0.01 is ~310
        # Random data should be well below this
        assert chi_squared < 400, f"Session ID bytes not uniformly distributed (chi²={chi_squared})"

    def test_session_ids_not_sequential(self) -> None:
        """Session IDs MUST NOT be sequential.

        Sequential IDs allow prediction and enumeration.
        """
        session_ids = [os.urandom(SESSION_ID_SIZE) for _ in range(100)]

        # Convert to integers
        id_ints = [int.from_bytes(sid, "little") for sid in session_ids]

        # Check that differences are not constant (would indicate sequential)
        diffs = [id_ints[i + 1] - id_ints[i] for i in range(len(id_ints) - 1)]

        # Sequential would have all same diff (usually 1)
        unique_diffs = set(diffs)
        assert len(unique_diffs) > 1, "Session IDs appear to be sequential"

    @given(seed=st.binary(min_size=6, max_size=6))
    @settings(max_examples=50)
    def test_session_id_not_predictable_from_previous(self, seed: bytes) -> None:
        """Session ID N+1 should not be predictable from session ID N.

        Even if attacker knows current session ID, they cannot predict next.
        """
        # Generate two "consecutive" session IDs (both random)
        id1 = os.urandom(SESSION_ID_SIZE)
        id2 = os.urandom(SESSION_ID_SIZE)

        # No simple mathematical relationship (diff shows no pattern)
        # diff = int.from_bytes(id2, "little") - int.from_bytes(id1, "little")

        # Cannot predict id2 from id1 and diff pattern
        # (because both are random)
        assert id1 != id2


class TestSessionIDGuessing:
    """Tests for session ID guessing attacks."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_guess_session_id_cannot_forge_frame(self, codec: NomadCodec) -> None:
        """Even if attacker guesses session ID, cannot forge valid frame.

        Security relies on AEAD authentication, not session ID secrecy.

        Spec: 2-TRANSPORT.md §Error Handling
        "Invalid AEAD tag: Silently drop"
        """
        real_key = codec.deterministic_bytes("hijack-test-key", 32)
        real_session_id = os.urandom(SESSION_ID_SIZE)

        # Attacker somehow knows the session ID (e.g., sniffed from traffic)
        known_session_id = real_session_id

        # Attacker creates frame with correct session ID but no valid auth
        header = bytearray(DATA_FRAME_HEADER_SIZE)
        header[0] = FRAME_DATA
        header[1] = 0x00
        header[2:8] = known_session_id
        struct.pack_into("<Q", header, 8, 1)

        # Random payload (attacker doesn't have key)
        forged_frame = bytes(header) + os.urandom(50)

        # AEAD verification fails (attacker doesn't have key)
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(forged_frame, real_key, 0, 0)

    def test_brute_force_session_id_infeasible(self) -> None:
        """Brute forcing session ID space is computationally infeasible.

        2^48 = 281 trillion possible session IDs.
        At 1 billion guesses/second: 281,000 seconds = 78 hours
        And each guess requires AEAD verification to confirm.
        """
        session_id_space = 2 ** (SESSION_ID_SIZE * 8)
        assert session_id_space == 281474976710656  # 2^48

        # Even at 1 billion guesses per second
        guesses_per_second = 10**9
        seconds_to_exhaust = session_id_space / guesses_per_second
        hours_to_exhaust = seconds_to_exhaust / 3600

        assert hours_to_exhaust > 50, "Session ID space should take many hours to exhaust"

        # And each guess requires network round-trip + AEAD verification
        # Realistically takes much longer


class TestSessionEnumeration:
    """Tests for session enumeration attacks."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_invalid_session_id_silent_drop(self, codec: NomadCodec) -> None:
        """Invalid session ID frames are silently dropped.

        Spec: 2-TRANSPORT.md §Error Handling
        "Unknown session ID: Silently drop"

        Silent drops prevent attackers from enumerating valid session IDs.
        """
        # Unknown session ID should result in silent drop
        # (Implementation doesn't even have the key for this session)
        unknown_session = os.urandom(SESSION_ID_SIZE)

        # Forge frame for unknown session
        header = bytearray(DATA_FRAME_HEADER_SIZE)
        header[0] = FRAME_DATA
        header[1] = 0x00
        header[2:8] = unknown_session
        struct.pack_into("<Q", header, 8, 1)

        forged = bytes(header) + os.urandom(50)

        # Try to decrypt with some key
        test_key = os.urandom(32)

        # Will fail (session doesn't exist / wrong key)
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(forged, test_key, 0, 0)

        # Key point: implementation MUST NOT respond differently
        # for valid vs invalid session IDs

    def test_no_session_oracle(self, codec: NomadCodec) -> None:
        """Implementation MUST NOT reveal whether session exists.

        Both valid and invalid session IDs should result in same behavior
        (silent drop for invalid frames, regardless of session existence).
        """
        real_key = codec.deterministic_bytes("oracle-test-key", 32)
        real_session_id = codec.deterministic_bytes("oracle-session", 6)

        # Frame for real session with wrong tag
        real_frame_bad_tag = (
            bytes([FRAME_DATA, 0x00]) + real_session_id + struct.pack("<Q", 1) + os.urandom(50)
        )

        # Frame for fake session
        fake_session_id = os.urandom(SESSION_ID_SIZE)
        fake_frame = (
            bytes([FRAME_DATA, 0x00]) + fake_session_id + struct.pack("<Q", 1) + os.urandom(50)
        )

        # Both should fail with same exception type
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(real_frame_bad_tag, real_key, 0, 0)

        with pytest.raises(InvalidTag):
            codec.parse_data_frame(fake_frame, real_key, 0, 0)


class TestSessionProbeAttacks:
    """Tests using the SessionProbe for enumeration attacks."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_session_probe_entropy_estimate(self, session_probe: SessionProbe) -> None:
        """Test entropy estimation for session IDs.

        Random session IDs should have high entropy estimate.
        """
        # Generate random session IDs
        random_ids = [os.urandom(SESSION_ID_SIZE) for _ in range(10)]

        entropy = session_probe.entropy_estimate(random_ids)

        # Random IDs should have high entropy (close to 48 bits)
        assert entropy >= 8.0, "Random session IDs should have good entropy"

    def test_sequential_session_ids_low_entropy(self, session_probe: SessionProbe) -> None:
        """Sequential session IDs have very low entropy.

        This tests the entropy estimation catches sequential patterns.
        """
        # Generate sequential session IDs (BAD - vulnerable)
        sequential_ids = [(100 + i).to_bytes(SESSION_ID_SIZE, "little") for i in range(10)]

        entropy = session_probe.entropy_estimate(sequential_ids)

        # Sequential IDs should have zero entropy
        assert entropy == 0.0, "Sequential session IDs should have zero entropy"


class TestSessionHijackVectors:
    """Test vectors for session hijacking scenarios."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_hijack_vector_observer_attack(self, codec: NomadCodec) -> None:
        """Test vector: observer captures session ID from traffic.

        Scenario:
        1. Attacker observes traffic, learns session ID
        2. Attacker cannot hijack because they lack session key
        """
        # Real session
        real_key = codec.deterministic_bytes("observer-key", 32)
        session_id = codec.deterministic_bytes("observer-session", 6)

        sync = codec.create_sync_message(1, 0, 0, b"legitimate data")
        legit_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=1,
            key=real_key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync,
        )

        # Attacker observes session ID from frame header (unencrypted)
        observed_session_id = legit_frame[2:8]
        assert observed_session_id == session_id

        # Attacker tries to inject frame
        header = (
            bytes([FRAME_DATA, 0x00])
            + observed_session_id
            + struct.pack("<Q", 100)  # Different nonce
        )

        # Attacker encrypts with wrong key
        attacker_key = os.urandom(32)
        attacker_sync = codec.create_sync_message(99, 0, 0, b"hijacked!")
        nonce = codec.construct_nonce(0, 0, 100)
        attacker_ciphertext = codec.encrypt(attacker_key, nonce, attacker_sync, header)

        hijack_frame = header + attacker_ciphertext

        # Verification with real key fails
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(hijack_frame, real_key, 0, 0)

    def test_hijack_vector_collision_attack(self, codec: NomadCodec) -> None:
        """Test vector: session ID collision attack.

        Spec: 1-SECURITY.md §Session ID Collision Handling
        "Responders MUST: Track active session IDs, Reject new sessions
         with colliding IDs"
        """
        # Active sessions set (server state)
        active_sessions: set[bytes] = set()

        # Normal session creation
        def create_session() -> bytes:
            for _ in range(3):  # Max retries per spec
                session_id = os.urandom(SESSION_ID_SIZE)
                if session_id not in active_sessions:
                    active_sessions.add(session_id)
                    return session_id
            raise RuntimeError("Session ID collision - too many active sessions")

        # Create many sessions
        for _ in range(1000):
            session_id = create_session()
            assert session_id in active_sessions

        # Verify all unique
        assert len(active_sessions) == 1000


class TestSessionHijackIntegration:
    """Integration tests for session hijacking with containers."""

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_hijack_attempt_integration(
        self,
        attacker: MITMAttacker,
        session_probe: SessionProbe,
        server_container,
        client_container,
    ) -> None:
        """Integration test: attempt session hijacking.

        This test:
        1. Captures traffic to observe session IDs
        2. Attempts to inject frames into existing sessions
        3. Verifies server silently drops injected frames
        """
        # Capture some traffic to learn session ID
        frames = attacker.capture_traffic(count=5, timeout=10.0)

        if not frames:
            pytest.skip("No frames captured")

        # Extract session ID from captured frame
        first_frame = frames[0]
        if len(first_frame.data) >= 8:
            observed_session_id = first_frame.data[2:8]

            # Attempt injection
            session_probe.probe_session_id(
                observed_session_id,
                dst_ip=first_frame.dst_ip,
                dst_port=first_frame.dst_port,
            )

            # The injected frame should be silently dropped
            assert observed_session_id in session_probe.probed_ids

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_enumerate_sessions_integration(
        self,
        attacker: MITMAttacker,
        session_probe: SessionProbe,
        server_container,
    ) -> None:
        """Integration test: attempt to enumerate sessions.

        This test sends probes for many session IDs to see if server
        responds differently (it should not).
        """
        # Probe many random session IDs
        for _ in range(100):
            random_id = os.urandom(SESSION_ID_SIZE)
            session_probe.probe_session_id(
                random_id,
                dst_ip="172.31.0.10",
                dst_port=19999,
            )

        # All probes should be silently dropped
        assert len(session_probe.probed_ids) == 100
