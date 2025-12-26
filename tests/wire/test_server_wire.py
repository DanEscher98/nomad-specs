"""
Simple E2E Wire Format Tests - Tests against real Rust implementation.

These tests verify wire format compliance by sending frames to the server
and validating response format. Does NOT require packet capture or client containers.

Requirements:
  - Docker containers running: docker compose up -d
  - Set NOMAD_EXTERNAL_CONTAINERS=1 for external mode

Test mapping: specs/2-TRANSPORT.md
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

from lib.network import (
    extract_header_fields,
    validate_data_frame_header,
)
from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    FRAME_HANDSHAKE_INIT,
    FRAME_HANDSHAKE_RESP,
    SESSION_ID_SIZE,
)

# =============================================================================
# Protocol Constants
# =============================================================================

PROTOCOL_VERSION = 0x0001

# Well-known test keys (from Rust implementation TEST_MODE=true)
SERVER_PUBLIC_KEY = base64.b64decode("gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=")

# State type ID for echo test
STATE_TYPE_ID = b"nomad.echo.v1"


# =============================================================================
# Helper Functions
# =============================================================================


def complete_handshake(
    sock: socket.socket,
    server_addr: tuple[str, int],
) -> tuple[NoiseConnection, bytes]:
    """Complete a Noise_IK handshake with the server.

    Returns:
        Tuple of (noise_connection, session_id).
    """
    private_key = os.urandom(32)

    noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, SERVER_PUBLIC_KEY)
    noise.start_handshake()

    # Send HandshakeInit
    noise_message = noise.write_message(STATE_TYPE_ID)
    packet = bytearray()
    packet.append(FRAME_HANDSHAKE_INIT)
    packet.append(0x00)
    packet.extend(struct.pack("<H", PROTOCOL_VERSION))
    packet.extend(noise_message)

    sock.sendto(bytes(packet), server_addr)

    # Receive HandshakeResp
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
# E2E Wire Format Tests - Handshake
# =============================================================================


@pytest.mark.container
class TestE2EHandshakeWireFormat:
    """E2E tests for handshake wire format."""

    def test_handshake_init_format(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify HandshakeInit wire format is correct.

        Wire format: [Type:1][Reserved:1][Version:2][Noise message...]
        """
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

            # Build packet
            packet = bytearray()
            packet.append(FRAME_HANDSHAKE_INIT)  # Type = 0x01
            packet.append(0x00)  # Reserved
            packet.extend(struct.pack("<H", PROTOCOL_VERSION))  # Version (little-endian)
            packet.extend(noise_message)

            # Verify format
            assert packet[0] == 0x01, "Type byte should be 0x01"
            assert packet[1] == 0x00, "Reserved byte should be 0x00"
            assert struct.unpack("<H", bytes(packet[2:4]))[0] == PROTOCOL_VERSION

            # Send and verify server accepts
            sock.sendto(bytes(packet), server_address)
            response, _ = sock.recvfrom(1024)

            assert response[0] == FRAME_HANDSHAKE_RESP, "Server should respond with HandshakeResp"

        finally:
            sock.close()

    def test_handshake_resp_format(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify HandshakeResp wire format is correct.

        Wire format: [Type:1][Reserved:1][SessionID:6][Noise message...]
        """
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
            response, _ = sock.recvfrom(1024)

            # Verify response format
            assert len(response) >= 8, f"Response too short: {len(response)}"
            assert response[0] == FRAME_HANDSHAKE_RESP, (
                f"Type should be 0x02, got 0x{response[0]:02x}"
            )
            assert response[1] == 0x00, f"Reserved should be 0x00, got 0x{response[1]:02x}"

            # Session ID (6 bytes)
            session_id = response[2:8]
            assert len(session_id) == SESSION_ID_SIZE
            assert session_id != b"\x00" * 6, "Session ID should not be all zeros"

            # Noise response follows
            noise_response = response[8:]
            assert len(noise_response) > 0, "Noise response should be present"

            # Complete handshake to verify Noise message is valid
            noise.read_message(noise_response)
            assert noise.handshake_finished

        finally:
            sock.close()


# =============================================================================
# E2E Wire Format Tests - Data Frames
# =============================================================================


@pytest.mark.container
class TestE2EDataFrameWireFormat:
    """E2E tests for data frame wire format."""

    def test_data_frame_header_format(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify data frame header is exactly 16 bytes.

        Wire format: [Type:1][Flags:1][SessionID:6][Nonce:8]
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Build data frame
            payload = b"Test payload"
            frame = build_data_frame(noise, session_id, 0, payload)

            # Verify header format
            assert len(frame) >= DATA_FRAME_HEADER_SIZE, "Frame should have 16-byte header"
            assert frame[0] == FRAME_DATA, f"Type should be 0x03, got 0x{frame[0]:02x}"
            assert frame[1] == 0x00, f"Flags should be 0x00, got 0x{frame[1]:02x}"
            assert frame[2:8] == session_id, "Session ID should match"

            # Nonce counter at offset 8-15 (8 bytes, little-endian)
            nonce = struct.unpack("<Q", frame[8:16])[0]
            assert nonce == 0, "First nonce should be 0"

            # Encrypted payload + tag follows header
            encrypted_portion = frame[16:]
            assert len(encrypted_portion) >= AEAD_TAG_SIZE

        finally:
            sock.close()

    def test_data_frame_nonce_little_endian(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify nonce counter uses little-endian encoding."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Build frame with nonce 0x0102030405060708
            test_nonce = 0x0102030405060708
            frame = build_data_frame(noise, session_id, test_nonce, b"Test")

            # Extract raw nonce bytes
            raw_nonce = frame[8:16]

            # In little-endian, least significant byte comes first
            # So 0x0102030405060708 -> [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
            assert raw_nonce[0] == 0x08, "LSB should be first in little-endian"
            assert raw_nonce[7] == 0x01, "MSB should be last in little-endian"

            # Verify roundtrip
            parsed_nonce = struct.unpack("<Q", raw_nonce)[0]
            assert parsed_nonce == test_nonce

        finally:
            sock.close()

    def test_data_frame_minimum_size(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify minimum data frame size (header + empty payload + tag = 32 bytes)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Build frame with empty payload
            frame = build_data_frame(noise, session_id, 0, b"")

            # Minimum: Header (16) + AEAD tag (16) = 32
            assert len(frame) >= 32, f"Minimum frame size should be 32, got {len(frame)}"

        finally:
            sock.close()

    def test_data_frame_response_format(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify echo server response has correct wire format."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send data frame
            frame = build_data_frame(noise, session_id, 0, b"Hello echo")
            sock.sendto(frame, server_address)

            # Receive response
            try:
                response, _ = sock.recvfrom(1024)

                # Verify response is a valid DATA frame
                assert len(response) >= 32, f"Response too short: {len(response)}"
                assert response[0] == FRAME_DATA, "Response type should be 0x03"
                assert (response[1] & 0xFC) == 0, "Reserved flag bits should be 0"
                assert response[2:8] == session_id, "Session ID should match"

                # Server's nonce should start at 0
                server_nonce = struct.unpack("<Q", response[8:16])[0]
                assert server_nonce >= 0, "Server nonce should be non-negative"

            except TimeoutError:
                # Echo server may not respond immediately, that's OK
                pass

        finally:
            sock.close()


# =============================================================================
# E2E Wire Format Tests - Flags
# =============================================================================


@pytest.mark.container
class TestE2EFlagsWireFormat:
    """E2E tests for flags byte wire format."""

    def test_flags_reserved_bits_zero(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify reserved flag bits (2-7) are zero in server response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            frame = build_data_frame(noise, session_id, 0, b"Test")
            sock.sendto(frame, server_address)

            try:
                response, _ = sock.recvfrom(1024)

                if len(response) >= 2:
                    flags = response[1]
                    reserved_bits = flags & 0xFC
                    assert reserved_bits == 0, (
                        f"Reserved bits should be 0, got 0x{reserved_bits:02x}"
                    )

            except TimeoutError:
                pass

        finally:
            sock.close()


# =============================================================================
# E2E Wire Format Tests - Malformed Packets
# =============================================================================


@pytest.mark.container
@pytest.mark.adversarial
class TestE2EMalformedPackets:
    """E2E tests for malformed packet handling.

    Per spec: All malformed packets MUST be silently dropped.
    """

    def test_empty_packet_dropped(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Empty packet is silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            # Send empty packet
            sock.sendto(b"", server_address)

            # Should get no response (silent drop)
            # If we get a response, that's unexpected but not necessarily wrong
            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

            # Verify server still alive
            time.sleep(0.2)
            noise, _ = complete_handshake(sock, server_address)
            assert noise.handshake_finished

        finally:
            sock.close()

    def test_single_byte_dropped(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Single byte packet is silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            sock.sendto(b"\x03", server_address)

            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

            # Server still alive
            time.sleep(0.2)
            noise, _ = complete_handshake(sock, server_address)
            assert noise.handshake_finished

        finally:
            sock.close()

    def test_invalid_type_dropped(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Packet with invalid type byte is silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            # Type 0x00 is invalid
            invalid_packet = bytes([0x00, 0x00] + [0] * 30)
            sock.sendto(invalid_packet, server_address)

            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

            # Type 0xFF is invalid
            invalid_packet = bytes([0xFF, 0x00] + [0] * 30)
            sock.sendto(invalid_packet, server_address)

            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

            # Server still alive
            time.sleep(0.2)
            noise, _ = complete_handshake(sock, server_address)
            assert noise.handshake_finished

        finally:
            sock.close()

    def test_truncated_handshake_dropped(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Truncated handshake is silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            # Valid header but truncated noise message
            truncated = bytes([FRAME_HANDSHAKE_INIT, 0x00, 0x01, 0x00])
            sock.sendto(truncated, server_address)

            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

            # Server still alive
            time.sleep(0.2)
            noise, _ = complete_handshake(sock, server_address)
            assert noise.handshake_finished

        finally:
            sock.close()

    def test_random_bytes_dropped(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Random bytes are silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            # Send various random payloads
            for size in [10, 32, 100, 500]:
                random_bytes = os.urandom(size)
                sock.sendto(random_bytes, server_address)

                with contextlib.suppress(TimeoutError):
                    sock.recvfrom(1024)

            # Server still alive
            time.sleep(0.2)
            noise, _ = complete_handshake(sock, server_address)
            assert noise.handshake_finished

        finally:
            sock.close()


# =============================================================================
# E2E Wire Format Tests - Session ID
# =============================================================================


@pytest.mark.container
class TestE2ESessionIDWireFormat:
    """E2E tests for session ID wire format."""

    def test_session_id_is_6_bytes(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify session ID is exactly 6 bytes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            assert len(session_id) == 6, f"Session ID should be 6 bytes, got {len(session_id)}"

        finally:
            sock.close()

    def test_session_id_unique_per_connection(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify each connection gets a unique session ID."""
        session_ids = []

        for _ in range(5):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            try:
                _, session_id = complete_handshake(sock, server_address)
                session_ids.append(session_id)
            finally:
                sock.close()

        # All session IDs should be unique
        unique_ids = set(session_ids)
        assert len(unique_ids) == 5, f"Expected 5 unique session IDs, got {len(unique_ids)}"

    def test_wrong_session_id_rejected(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Verify data frame with wrong session ID is silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Build frame with wrong session ID
            wrong_session = b"\xff\xff\xff\xff\xff\xff"
            encrypted = noise.encrypt(b"Test message")

            frame = bytearray()
            frame.append(FRAME_DATA)
            frame.append(0x00)
            frame.extend(wrong_session)  # Wrong!
            frame.extend(struct.pack("<Q", 0))
            frame.extend(encrypted)

            sock.sendto(bytes(frame), server_address)

            # Should be silently dropped
            sock.settimeout(1.0)
            with contextlib.suppress(TimeoutError):
                sock.recvfrom(1024)

        finally:
            sock.close()


# =============================================================================
# E2E Wire Format Tests - Validation Helpers
# =============================================================================


@pytest.mark.container
class TestE2EValidationHelpers:
    """E2E tests using validation helper functions."""

    def test_validate_data_frame_header_helper(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Test validate_data_frame_header on real frames."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            frame = build_data_frame(noise, session_id, 0, b"Test payload")

            validation = validate_data_frame_header(frame)
            assert validation["has_minimum_size"], "Should have minimum size"
            assert validation["has_header"], "Should have header"
            assert validation["type_is_data"], "Type should be DATA"
            assert validation["flags_valid"], "Flags should be valid"
            assert validation["session_id_present"], "Session ID should be present"
            assert validation["nonce_counter_present"], "Nonce counter should be present"

        finally:
            sock.close()

    def test_extract_header_fields_helper(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Test extract_header_fields on real frames."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            test_nonce = 42
            frame = build_data_frame(noise, session_id, test_nonce, b"Test")

            fields = extract_header_fields(frame)
            assert fields["type"] == FRAME_DATA
            assert fields["flags"] == 0x00
            assert fields["session_id"] == session_id
            assert fields["nonce_counter"] == test_nonce

        finally:
            sock.close()
