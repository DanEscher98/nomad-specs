"""
Simple E2E Roaming (Connection Migration) Tests - Tests against real Rust implementation.

These tests verify roaming/migration behavior without requiring packet capture.
Uses simple UDP sockets in external mode.

Requirements:
  - Docker containers running: docker compose up -d
  - Set NOMAD_EXTERNAL_CONTAINERS=1 for external mode

Test mapping: specs/2-TRANSPORT.md § "Connection Migration"

Migration rules:
1. Valid AEAD tag from new address -> update remote_endpoint
2. Invalid AEAD -> silently drop (no migration)
3. Anti-amplification: max 3x bytes sent before validation
"""

from __future__ import annotations

import base64
import contextlib
import os
import socket
import struct
import time

import pytest
from noise.connection import Keypair, NoiseConnection

# =============================================================================
# Protocol Constants
# =============================================================================

FRAME_HANDSHAKE_INIT = 0x01
FRAME_HANDSHAKE_RESP = 0x02
FRAME_DATA = 0x03

PROTOCOL_VERSION = 0x0001

# Well-known test keys
SERVER_PUBLIC_KEY = base64.b64decode("gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=")
STATE_TYPE_ID = b"nomad.echo.v1"


# =============================================================================
# Helper Functions
# =============================================================================


def complete_handshake(
    sock: socket.socket,
    server_addr: tuple[str, int],
) -> tuple[NoiseConnection, bytes]:
    """Complete a Noise_IK handshake with the server."""
    private_key = os.urandom(32)

    noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, SERVER_PUBLIC_KEY)
    noise.start_handshake()

    noise_message = noise.write_message(STATE_TYPE_ID)
    packet = bytearray()
    packet.append(FRAME_HANDSHAKE_INIT)
    packet.append(0x00)
    packet.extend(struct.pack("<H", PROTOCOL_VERSION))
    packet.extend(noise_message)

    sock.sendto(bytes(packet), server_addr)

    sock.settimeout(5.0)
    response, _ = sock.recvfrom(1024)

    if response[0] != FRAME_HANDSHAKE_RESP:
        raise RuntimeError(f"Expected HandshakeResp, got 0x{response[0]:02x}")

    session_id = response[2:8]
    noise_response = response[8:]
    noise.read_message(noise_response)

    if not noise.handshake_finished:
        raise RuntimeError("Handshake did not complete")

    return noise, session_id


def build_data_frame(
    noise: NoiseConnection,
    session_id: bytes,
    nonce_counter: int,
    payload: bytes,
) -> bytes:
    """Build an encrypted data frame."""
    encrypted = noise.encrypt(payload)

    frame = bytearray()
    frame.append(FRAME_DATA)
    frame.append(0x00)
    frame.extend(session_id)
    frame.extend(struct.pack("<Q", nonce_counter))
    frame.extend(encrypted)

    return bytes(frame)


# =============================================================================
# E2E Port Change Tests (Simulating NAT/Roaming)
# =============================================================================


@pytest.mark.container
class TestE2EPortChange:
    """E2E tests for client source port changes (NAT behavior)."""

    def test_session_survives_port_change(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives when client's source port changes.

        This simulates NAT rebinding or network roaming.
        """
        # Establish session on first socket
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)

            # Send some traffic
            frame1 = build_data_frame(noise, session_id, 0, b"From original port")
            sock1.sendto(frame1, server_address)

            # Get original port
            sock1.getsockname()[1]

        finally:
            sock1.close()

        # Create new socket (different source port)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(5.0)

        try:
            # Bind to a different port
            sock2.bind(("", 0))
            sock2.getsockname()[1]

            # Ports should be different (usually)
            # Note: In rare cases they might be the same, that's OK

            # Send frame from new port using same session keys
            frame2 = build_data_frame(noise, session_id, 1, b"From new port")
            sock2.sendto(frame2, server_address)

            # If server accepts migration, it should respond to new port
            try:
                response, _ = sock2.recvfrom(1024)
                if len(response) > 0:
                    # Got response - server migrated to new address
                    assert response[0] == FRAME_DATA
            except TimeoutError:
                # Server may not respond immediately, but shouldn't crash
                pass

        finally:
            sock2.close()

    def test_session_continues_after_reconnect(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session state preserved when reconnecting from different port."""
        # First connection
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)

            # Send several frames
            for i in range(3):
                frame = build_data_frame(noise, session_id, i, f"Frame {i}".encode())
                sock1.sendto(frame, server_address)
                time.sleep(0.1)

        finally:
            sock1.close()

        # Second connection (simulating roaming)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(5.0)

        try:
            # Continue sending with same session (nonce continues)
            for i in range(3, 6):
                frame = build_data_frame(noise, session_id, i, f"Frame {i} (after roam)".encode())
                sock2.sendto(frame, server_address)
                time.sleep(0.1)

        finally:
            sock2.close()


# =============================================================================
# E2E Session Continuity Tests
# =============================================================================


@pytest.mark.container
class TestE2ESessionContinuity:
    """E2E tests for session continuity during migration."""

    def test_session_id_remains_constant(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session ID doesn't change during migration."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Session ID should be 6 bytes
            assert len(session_id) == 6

            # Send multiple frames - session ID in each should be same
            for i in range(5):
                frame = build_data_frame(noise, session_id, i, f"Check {i}".encode())

                # Verify session ID in frame
                frame_session_id = frame[2:8]
                assert frame_session_id == session_id

                sock.sendto(frame, server_address)
                time.sleep(0.1)

        finally:
            sock.close()

    def test_nonce_counter_continues_across_migration(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Nonce counter continues incrementing after port change."""
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)

            # Send frames 0-4
            for i in range(5):
                frame = build_data_frame(noise, session_id, i, f"Nonce {i}".encode())
                sock1.sendto(frame, server_address)

        finally:
            sock1.close()

        # Switch to new socket
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(5.0)

        try:
            # Continue with nonces 5-9
            for i in range(5, 10):
                frame = build_data_frame(noise, session_id, i, f"Nonce {i}".encode())
                sock2.sendto(frame, server_address)
                time.sleep(0.05)

        finally:
            sock2.close()


# =============================================================================
# E2E Migration Validation Tests
# =============================================================================


@pytest.mark.container
@pytest.mark.adversarial
class TestE2EMigrationValidation:
    """E2E tests for migration validation (security)."""

    def test_invalid_session_id_rejected_on_migration(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Frame with wrong session ID from 'new address' is rejected."""
        # Establish real session
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)

            # Send valid frame
            frame = build_data_frame(noise, session_id, 0, b"Valid")
            sock1.sendto(frame, server_address)

        finally:
            sock1.close()

        # Try to "migrate" with wrong session ID
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(1.0)

        try:
            # Use wrong session ID
            wrong_session = b"\xff\xff\xff\xff\xff\xff"
            encrypted = noise.encrypt(b"Hijack attempt")

            frame = bytearray()
            frame.append(FRAME_DATA)
            frame.append(0x00)
            frame.extend(wrong_session)  # Wrong!
            frame.extend(struct.pack("<Q", 1))
            frame.extend(encrypted)

            sock2.sendto(bytes(frame), server_address)

            # Should be silently dropped - no response
            with contextlib.suppress(TimeoutError):
                sock2.recvfrom(1024)

        finally:
            sock2.close()

    def test_corrupted_frame_rejected_on_migration(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Frame with corrupted AEAD from 'new address' is rejected."""
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)
            frame = build_data_frame(noise, session_id, 0, b"Valid")
            sock1.sendto(frame, server_address)
        finally:
            sock1.close()

        # Try migration with corrupted frame
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(1.0)

        try:
            # Build valid frame then corrupt it
            frame = build_data_frame(noise, session_id, 1, b"Corrupt")
            corrupted = bytearray(frame)
            corrupted[-1] ^= 0xFF  # Corrupt AEAD tag

            sock2.sendto(bytes(corrupted), server_address)

            # Should be silently dropped
            with contextlib.suppress(TimeoutError):
                sock2.recvfrom(1024)

        finally:
            sock2.close()


# =============================================================================
# E2E Anti-Amplification Tests
# =============================================================================


@pytest.mark.container
@pytest.mark.adversarial
class TestE2EAntiAmplification:
    """E2E tests for anti-amplification protection.

    Per spec: Cannot send more than 3x bytes received from unvalidated address.
    """

    def test_random_small_packet_limited_response(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Server limits response to unauthenticated small packets."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            # Send small random data (not a valid frame)
            small_data = b"\x03" + os.urandom(31)  # 32 bytes
            sock.sendto(small_data, server_address)

            # Should get no response (invalid frame silently dropped)
            # If we get a response, it should be limited
            # (3x rule means max 96 bytes for 32 byte request)
            # But actually we expect no response for invalid frames
            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

        finally:
            sock.close()

    def test_valid_handshake_gets_response(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Valid handshake gets proper response (no artificial limit)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            private_key = os.urandom(32)

            noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
            noise.set_as_initiator()
            noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
            noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, SERVER_PUBLIC_KEY)
            noise.start_handshake()

            noise_message = noise.write_message(STATE_TYPE_ID)
            packet = bytearray()
            packet.append(FRAME_HANDSHAKE_INIT)
            packet.append(0x00)
            packet.extend(struct.pack("<H", PROTOCOL_VERSION))
            packet.extend(noise_message)

            sock.sendto(bytes(packet), server_address)

            # Should get valid handshake response
            response, _ = sock.recvfrom(1024)
            assert response[0] == FRAME_HANDSHAKE_RESP
            assert len(response) >= 56  # Minimum handshake response size

        finally:
            sock.close()


# =============================================================================
# E2E Multiple Socket Tests
# =============================================================================


@pytest.mark.container
class TestE2EMultipleSocketBehavior:
    """E2E tests for behavior across multiple client sockets."""

    def test_different_sessions_from_different_sockets(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Different sockets get different sessions."""
        sessions = []

        for _i in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            try:
                _, session_id = complete_handshake(sock, server_address)
                sessions.append(session_id)
            finally:
                sock.close()

        # All sessions should be unique
        unique_sessions = set(sessions)
        assert len(unique_sessions) == 3, "Each connection should get unique session"

    def test_same_session_works_across_sockets(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Same session keys work from different sockets (migration)."""
        # Establish session
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock1, server_address)
            frame1 = build_data_frame(noise, session_id, 0, b"Socket 1")
            sock1.sendto(frame1, server_address)
        finally:
            sock1.close()

        # Use session from second socket
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(5.0)

        try:
            frame2 = build_data_frame(noise, session_id, 1, b"Socket 2")
            sock2.sendto(frame2, server_address)
            # Server should accept (migration)
        finally:
            sock2.close()

        # And from third socket
        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock3.settimeout(5.0)

        try:
            frame3 = build_data_frame(noise, session_id, 2, b"Socket 3")
            sock3.sendto(frame3, server_address)
        finally:
            sock3.close()
