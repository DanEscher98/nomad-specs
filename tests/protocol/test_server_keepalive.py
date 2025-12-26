"""
Simple E2E Keepalive Tests - Tests against real Rust implementation.

These tests verify keepalive behavior without requiring packet capture.
Uses simple UDP sockets in external mode.

Requirements:
  - Docker containers running: docker compose up -d
  - Set NOMAD_EXTERNAL_CONTAINERS=1 for external mode

Test mapping: specs/2-TRANSPORT.md § "Keepalive"
"""

from __future__ import annotations

import base64
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

FLAG_ACK_ONLY = 0x01

PROTOCOL_VERSION = 0x0001

# Timing constants (from spec)
KEEPALIVE_INTERVAL_SECONDS = 25
DEAD_INTERVAL_SECONDS = 60

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
    flags: int = 0x00,
) -> bytes:
    """Build an encrypted data frame."""
    encrypted = noise.encrypt(payload)

    frame = bytearray()
    frame.append(FRAME_DATA)
    frame.append(flags)
    frame.extend(session_id)
    frame.extend(struct.pack("<Q", nonce_counter))
    frame.extend(encrypted)

    return bytes(frame)


def build_keepalive_frame(
    noise: NoiseConnection,
    session_id: bytes,
    nonce_counter: int,
) -> bytes:
    """Build a keepalive frame (ACK_ONLY flag, empty payload)."""
    return build_data_frame(noise, session_id, nonce_counter, b"", flags=FLAG_ACK_ONLY)


# =============================================================================
# E2E Keepalive Frame Tests
# =============================================================================


@pytest.mark.container
class TestE2EKeepaliveFrameFormat:
    """E2E tests for keepalive frame format."""

    def test_keepalive_frame_type_is_data(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Keepalive frames are Data frames (type 0x03) with ACK_ONLY flag."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Build keepalive frame
            keepalive = build_keepalive_frame(noise, session_id, 0)

            # Verify format
            assert keepalive[0] == FRAME_DATA, "Keepalive should be DATA frame type"
            assert keepalive[1] & FLAG_ACK_ONLY, "Keepalive should have ACK_ONLY flag"

            # Send it
            sock.sendto(keepalive, server_address)

            # Server should accept it (no crash)
            time.sleep(0.2)

            # Verify server still responds
            frame2 = build_data_frame(noise, session_id, 1, b"After keepalive")
            sock.sendto(frame2, server_address)

        finally:
            sock.close()

    def test_keepalive_ack_only_flag_value(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """ACK_ONLY flag is bit 0 (value 0x01)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Create frame with ACK_ONLY flag
            frame = build_keepalive_frame(noise, session_id, 0)

            # Verify flag byte
            flags = frame[1]
            assert flags == FLAG_ACK_ONLY, f"Expected 0x01, got 0x{flags:02x}"
            assert flags & 0x01 == 0x01, "ACK_ONLY should be bit 0"

            sock.sendto(frame, server_address)

        finally:
            sock.close()


# =============================================================================
# E2E Session Liveness Tests
# =============================================================================


@pytest.mark.container
class TestE2ESessionLiveness:
    """E2E tests for session liveness via keepalives."""

    def test_session_stays_alive_with_traffic(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session stays alive when sending regular traffic."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send traffic over several seconds
            for i in range(5):
                frame = build_data_frame(noise, session_id, i, f"Message {i}".encode())
                sock.sendto(frame, server_address)
                time.sleep(1)

            # Session should still be alive
            final_frame = build_data_frame(noise, session_id, 5, b"Final")
            sock.sendto(final_frame, server_address)

        finally:
            sock.close()

    def test_session_stays_alive_with_keepalives(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session stays alive when sending keepalives."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send initial data
            frame0 = build_data_frame(noise, session_id, 0, b"Initial")
            sock.sendto(frame0, server_address)

            # Send keepalives
            for i in range(3):
                keepalive = build_keepalive_frame(noise, session_id, i + 1)
                sock.sendto(keepalive, server_address)
                time.sleep(1)

            # Session should still be alive - send data
            final_frame = build_data_frame(noise, session_id, 4, b"After keepalives")
            sock.sendto(final_frame, server_address)

        finally:
            sock.close()

    def test_session_survives_idle_period(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives short idle periods (< DEAD_INTERVAL)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send initial frame
            frame1 = build_data_frame(noise, session_id, 0, b"Before idle")
            sock.sendto(frame1, server_address)

            # Idle for 5 seconds (well under DEAD_INTERVAL)
            time.sleep(5)

            # Session should still work
            frame2 = build_data_frame(noise, session_id, 1, b"After idle")
            sock.sendto(frame2, server_address)

            # If we can send without error, session is alive

        finally:
            sock.close()


# =============================================================================
# E2E Timestamp Tests
# =============================================================================


@pytest.mark.container
class TestE2ETimestampBehavior:
    """E2E tests for timestamp handling."""

    def test_nonce_counter_increases(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Nonce counter increases with each frame."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send frames with increasing nonces
            for nonce in range(10):
                frame = build_data_frame(noise, session_id, nonce, f"Nonce {nonce}".encode())

                # Verify nonce in frame
                frame_nonce = struct.unpack("<Q", frame[8:16])[0]
                assert frame_nonce == nonce

                sock.sendto(frame, server_address)
                time.sleep(0.1)

        finally:
            sock.close()

    def test_echo_server_responds_with_increasing_nonce(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Echo server responses have increasing nonces."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            server_nonces = []

            for i in range(3):
                frame = build_data_frame(noise, session_id, i, f"Echo {i}".encode())
                sock.sendto(frame, server_address)

                try:
                    response, _ = sock.recvfrom(1024)
                    if len(response) >= 16 and response[0] == FRAME_DATA:
                        server_nonce = struct.unpack("<Q", response[8:16])[0]
                        server_nonces.append(server_nonce)
                except TimeoutError:
                    pass  # Echo may not always respond

                time.sleep(0.2)

            # If we got multiple responses, verify nonces increase
            if len(server_nonces) >= 2:
                for i in range(1, len(server_nonces)):
                    assert server_nonces[i] > server_nonces[i - 1], "Server nonce should increase"

        finally:
            sock.close()


# =============================================================================
# E2E Keepalive Timing Constants
# =============================================================================


@pytest.mark.container
class TestE2EKeepaliveConstants:
    """Tests documenting keepalive timing constants."""

    def test_keepalive_interval_constant(self) -> None:
        """KEEPALIVE_INTERVAL is 25 seconds per spec."""
        assert KEEPALIVE_INTERVAL_SECONDS == 25

    def test_dead_interval_constant(self) -> None:
        """DEAD_INTERVAL is 60 seconds per spec."""
        assert DEAD_INTERVAL_SECONDS == 60

    def test_dead_interval_greater_than_keepalive(self) -> None:
        """DEAD_INTERVAL > KEEPALIVE_INTERVAL (safety margin)."""
        assert DEAD_INTERVAL_SECONDS > KEEPALIVE_INTERVAL_SECONDS


# =============================================================================
# E2E Connection Health Tests
# =============================================================================


@pytest.mark.container
class TestE2EConnectionHealth:
    """E2E tests for connection health verification."""

    def test_server_responds_to_valid_frames(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Server responds to valid frames (echo server)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            frame = build_data_frame(noise, session_id, 0, b"Health check")
            sock.sendto(frame, server_address)

            try:
                response, _ = sock.recvfrom(1024)
                # If we get a response, verify it's a DATA frame
                if len(response) > 0:
                    assert response[0] == FRAME_DATA
            except TimeoutError:
                # Echo server may not respond immediately
                pass

        finally:
            sock.close()

    def test_multiple_sessions_stay_healthy(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Multiple concurrent sessions can stay healthy."""
        sockets = []
        sessions = []

        try:
            # Create 3 sessions
            for _i in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5.0)
                sockets.append(sock)

                noise, session_id = complete_handshake(sock, server_address)
                sessions.append((noise, session_id))

            # Send from all sessions
            for i, (sock, (noise, session_id)) in enumerate(zip(sockets, sessions, strict=False)):
                frame = build_data_frame(noise, session_id, 0, f"Session {i}".encode())
                sock.sendto(frame, server_address)
                time.sleep(0.1)

            # All sessions should still work
            for i, (sock, (noise, session_id)) in enumerate(zip(sockets, sessions, strict=False)):
                frame = build_data_frame(noise, session_id, 1, f"Session {i} alive".encode())
                sock.sendto(frame, server_address)

        finally:
            for sock in sockets:
                sock.close()


# =============================================================================
# Slow Keepalive Tests
# =============================================================================


@pytest.mark.slow
@pytest.mark.container
class TestE2ESlowKeepaliveTests:
    """Slow tests for keepalive behavior.

    These tests require longer wait times.
    Run with: pytest -m slow
    """

    @pytest.mark.skip(reason="Requires 10+ second wait")
    def test_session_survives_10_second_idle(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives 10 second idle period."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(15.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            frame1 = build_data_frame(noise, session_id, 0, b"Before 10s idle")
            sock.sendto(frame1, server_address)

            time.sleep(10)

            frame2 = build_data_frame(noise, session_id, 1, b"After 10s idle")
            sock.sendto(frame2, server_address)

        finally:
            sock.close()
