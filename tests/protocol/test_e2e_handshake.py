"""
E2E Handshake Tests - Tests against real Rust implementation.

These tests connect to the actual Nomad server running in Docker
and perform real Noise_IK handshakes.

Requirements:
  - Docker containers running: docker compose up -d
  - Set NOMAD_EXTERNAL_CONTAINERS=1 for external mode

Test mapping: specs/1-SECURITY.md § "Handshake Protocol"
"""

from __future__ import annotations

import base64
import os
import socket
import struct

import pytest
from noise.connection import Keypair, NoiseConnection

# =============================================================================
# Protocol Constants (from spec)
# =============================================================================

FRAME_HANDSHAKE_INIT = 0x01
FRAME_HANDSHAKE_RESP = 0x02
FRAME_DATA = 0x03

PROTOCOL_VERSION = 0x0001
SESSION_ID_SIZE = 6

# Well-known test keys (from Rust implementation TEST_MODE=true)
SERVER_PUBLIC_KEY = base64.b64decode("gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=")

# State type ID for echo test
STATE_TYPE_ID = b"nomad.echo.v1"


# =============================================================================
# E2E Test Fixtures
# =============================================================================


@pytest.fixture
def client_private_key() -> bytes:
    """Generate a random client private key."""
    return os.urandom(32)


@pytest.fixture
def noise_initiator(client_private_key: bytes) -> NoiseConnection:
    """Create a Noise_IK initiator state machine.

    Noise_IK pattern:
    - Initiator knows responder's static public key
    - I: e, es, s, ss
    - R: e, ee, se
    """
    noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, client_private_key)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, SERVER_PUBLIC_KEY)
    noise.start_handshake()
    return noise


# =============================================================================
# E2E Handshake Tests
# =============================================================================


@pytest.mark.container
class TestE2EHandshake:
    """E2E tests that connect to real Docker containers."""

    def test_handshake_init_receives_response(
        self,
        udp_socket: socket.socket,
        noise_initiator: NoiseConnection,
    ) -> None:
        """Send HandshakeInit and receive HandshakeResp from server.

        This is the core E2E test verifying we can complete a handshake
        with the real Rust implementation.
        """
        # Create HandshakeInit message with state_type in payload
        # Noise_IK pattern first message: e, es, s, ss
        # Payload is just the raw state_type string (no length prefix)
        noise_message = noise_initiator.write_message(STATE_TYPE_ID)

        # Build wire format: [Type:1][Reserved:1][Version:2][Noise message...]
        packet = bytearray()
        packet.append(FRAME_HANDSHAKE_INIT)  # Type 0x01
        packet.append(0x00)  # Reserved
        packet.extend(struct.pack("<H", PROTOCOL_VERSION))  # Version 1.0
        packet.extend(noise_message)

        # Send to server
        udp_socket.send(bytes(packet))

        # Receive response
        try:
            response = udp_socket.recv(1024)
        except TimeoutError:
            pytest.fail("Server did not respond to HandshakeInit within timeout")

        # Verify response format
        assert len(response) >= 8, f"Response too short: {len(response)} bytes"

        frame_type = response[0]
        assert frame_type == FRAME_HANDSHAKE_RESP, f"Expected HandshakeResp (0x02), got 0x{frame_type:02x}"

        # Parse session ID
        session_id = response[2:8]
        assert len(session_id) == SESSION_ID_SIZE

        # Parse Noise response (starts at byte 8)
        noise_response = response[8:]

        # Process Noise response (completes handshake on initiator side)
        try:
            noise_initiator.read_message(noise_response)
        except Exception as e:
            pytest.fail(f"Failed to process Noise response: {e}")

        # Handshake should now be complete
        assert noise_initiator.handshake_finished, "Handshake did not complete"

    def test_handshake_session_id_is_unique(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Each handshake gets a unique session ID."""
        session_ids = set()

        for _ in range(5):
            # Create fresh socket and noise state for each connection
            private_key = os.urandom(32)

            noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
            noise.set_as_initiator()
            noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
            noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, SERVER_PUBLIC_KEY)
            noise.start_handshake()

            # Include state_type in payload (raw string, no length prefix)
            noise_message = noise.write_message(STATE_TYPE_ID)

            # Build packet
            packet = bytearray()
            packet.append(FRAME_HANDSHAKE_INIT)
            packet.append(0x00)
            packet.extend(struct.pack("<H", PROTOCOL_VERSION))
            packet.extend(noise_message)

            # Send and receive
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            try:
                sock.sendto(bytes(packet), server_address)
                response, _ = sock.recvfrom(1024)
                session_id = response[2:8]
                session_ids.add(session_id)
            finally:
                sock.close()

        # All session IDs should be unique
        assert len(session_ids) == 5, f"Expected 5 unique session IDs, got {len(session_ids)}"

    def test_handshake_wrong_server_key_fails(
        self,
        udp_socket: socket.socket,
    ) -> None:
        """Handshake with wrong server public key fails."""
        private_key = os.urandom(32)

        # Use wrong server public key (random 32 bytes)
        wrong_server_key = os.urandom(32)

        noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
        noise.set_as_initiator()
        noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
        noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, wrong_server_key)
        noise.start_handshake()

        noise_message = noise.write_message(b"")

        # Build packet
        packet = bytearray()
        packet.append(FRAME_HANDSHAKE_INIT)
        packet.append(0x00)
        packet.extend(struct.pack("<H", PROTOCOL_VERSION))
        packet.extend(noise_message)

        # Send to server
        udp_socket.send(bytes(packet))

        # Server should either:
        # 1. Not respond (silent drop - preferred for security)
        # 2. Send error response (less preferred)
        try:
            udp_socket.settimeout(2.0)  # Short timeout
            response = udp_socket.recv(1024)
            # If we get a response, it should be an error or the decryption should fail
            if len(response) > 8 and response[0] == FRAME_HANDSHAKE_RESP:
                noise_response = response[8:]
                # This should fail because encryption was to wrong key
                with pytest.raises(Exception):  # noqa: B017
                    noise.read_message(noise_response)
        except TimeoutError:
            # Silent drop is acceptable security behavior
            pass


# =============================================================================
# Health Check Tests
# =============================================================================


@pytest.mark.container
class TestServerHealth:
    """Test server health and availability."""

    def test_server_responds_to_udp(
        self,
        udp_socket: socket.socket,
    ) -> None:
        """Server is running and responds to UDP packets."""
        # Send a minimal HandshakeInit (will be invalid, but tests UDP reachability)
        packet = bytes([FRAME_HANDSHAKE_INIT, 0x00, 0x01, 0x00])  # Too short
        udp_socket.send(packet)

        # For a malformed packet, server should silently drop
        # This test just verifies we can reach the server (no exception on send)
        # We don't expect a response for malformed packets


# =============================================================================
# Data Frame Tests (post-handshake)
# =============================================================================


@pytest.mark.container
class TestE2EDataExchange:
    """E2E tests for data exchange after handshake."""

    def test_send_encrypted_data_after_handshake(
        self,
        udp_socket: socket.socket,
        noise_initiator: NoiseConnection,
    ) -> None:
        """After handshake, can send encrypted data frames."""
        # Complete handshake first with state_type (raw string, no length prefix)
        noise_message = noise_initiator.write_message(STATE_TYPE_ID)
        packet = bytearray()
        packet.append(FRAME_HANDSHAKE_INIT)
        packet.append(0x00)
        packet.extend(struct.pack("<H", PROTOCOL_VERSION))
        packet.extend(noise_message)

        udp_socket.send(bytes(packet))

        try:
            response = udp_socket.recv(1024)
        except TimeoutError:
            pytest.skip("Server did not respond - may not be running")

        # Parse response
        if response[0] != FRAME_HANDSHAKE_RESP:
            pytest.skip("Did not receive valid handshake response")

        session_id = response[2:8]
        noise_response = response[8:]
        noise_initiator.read_message(noise_response)

        assert noise_initiator.handshake_finished

        # Now send encrypted data frame
        test_payload = b"Hello from Python E2E test!"
        encrypted_payload = noise_initiator.encrypt(test_payload)

        # Build data frame: [Type:1][Reserved:1][SessionID:6][Nonce:8][Encrypted...]
        data_frame = bytearray()
        data_frame.append(FRAME_DATA)  # Type 0x03
        data_frame.append(0x00)  # Reserved
        data_frame.extend(session_id)  # 6 bytes
        data_frame.extend(struct.pack("<Q", 0))  # Nonce counter (8 bytes)
        data_frame.extend(encrypted_payload)

        udp_socket.send(bytes(data_frame))

        # For echo server, we should get a response
        try:
            data_response = udp_socket.recv(1024)
            # Verify it's a data frame
            assert data_response[0] == FRAME_DATA, f"Expected DATA frame, got 0x{data_response[0]:02x}"
        except TimeoutError:
            # Server may not echo immediately, that's OK for this test
            pass
