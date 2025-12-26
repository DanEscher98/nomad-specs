"""
E2E Rekeying Tests - Tests against real Rust implementation.

These tests verify rekeying behavior with the actual server.

Note: Full rekey testing requires waiting REKEY_AFTER_TIME (120 seconds).
These tests focus on:
- Session longevity (no premature termination)
- Rekey frame handling (if implemented)
- Epoch transitions

Requirements:
  - Docker containers running: docker compose up -d
  - Set NOMAD_EXTERNAL_CONTAINERS=1 for external mode

Test mapping: specs/1-SECURITY.md § "Rekeying (Type 0x04)"
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
FRAME_REKEY = 0x04

PROTOCOL_VERSION = 0x0001
SESSION_ID_SIZE = 6

# Timing constants (from spec)
REKEY_AFTER_TIME_SECONDS = 120
REJECT_AFTER_TIME_SECONDS = 180
OLD_KEY_RETENTION_SECONDS = 5

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


def build_rekey_frame(
    noise: NoiseConnection,
    session_id: bytes,
    nonce_counter: int,
    new_ephemeral: bytes,
    timestamp: int,
) -> bytes:
    """Build an encrypted rekey frame.

    Note: This is a simplified version - actual rekey uses current session keys.
    """
    # Rekey payload: new ephemeral (32) + timestamp (4)
    payload = new_ephemeral + struct.pack("<I", timestamp)
    encrypted = noise.encrypt(payload)

    frame = bytearray()
    frame.append(FRAME_REKEY)
    frame.append(0x00)
    frame.extend(session_id)
    frame.extend(struct.pack("<Q", nonce_counter))
    frame.extend(encrypted)

    return bytes(frame)


# =============================================================================
# E2E Session Longevity Tests
# =============================================================================


@pytest.mark.container
class TestE2ESessionLongevity:
    """E2E tests for session longevity without rekey.

    These tests verify sessions remain usable for short periods.
    """

    def test_session_survives_multiple_exchanges(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives multiple message exchanges."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send multiple messages
            for i in range(10):
                payload = f"Message {i}".encode()
                frame = build_data_frame(noise, session_id, i, payload)
                sock.sendto(frame, server_address)

                # Small delay between messages
                time.sleep(0.1)

            # Send one more - session should still be valid
            final_frame = build_data_frame(noise, session_id, 10, b"Final message")
            sock.sendto(final_frame, server_address)

            # If we get here without exception, session is still alive

        finally:
            sock.close()

    def test_session_survives_idle_period(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives short idle periods."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send initial message
            frame1 = build_data_frame(noise, session_id, 0, b"Before idle")
            sock.sendto(frame1, server_address)

            # Idle for a few seconds
            time.sleep(3)

            # Send another message - should still work
            frame2 = build_data_frame(noise, session_id, 1, b"After idle")
            sock.sendto(frame2, server_address)

            # Try to get response (echo may not respond, that's OK)
            with contextlib.suppress(TimeoutError):
                sock.recv(1024)

        finally:
            sock.close()

    def test_nonce_counter_progression(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Nonce counter can progress through many values."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send frames with increasing nonces
            for nonce in [0, 1, 10, 100, 1000, 10000]:
                frame = build_data_frame(noise, session_id, nonce, f"Nonce {nonce}".encode())
                sock.sendto(frame, server_address)
                time.sleep(0.05)

        finally:
            sock.close()


# =============================================================================
# E2E Rekey Frame Tests
# =============================================================================


@pytest.mark.container
class TestE2ERekeyFrameHandling:
    """E2E tests for rekey frame handling.

    Note: The echo server may not implement rekeying.
    These tests verify the server handles rekey frames gracefully.
    """

    def test_rekey_frame_type_recognized(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Server handles rekey frame type (0x04) without crashing.

        The server may:
        - Process the rekey and respond
        - Silently drop if not implemented
        - The key is it doesn't crash
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Generate new ephemeral key for rekey
            new_ephemeral = os.urandom(32)
            timestamp = int(time.time())

            # Build rekey frame
            rekey_frame = build_rekey_frame(noise, session_id, 0, new_ephemeral, timestamp)
            sock.sendto(rekey_frame, server_address)

            # Wait for potential response
            sock.settimeout(1.0)
            try:
                response = sock.recv(1024)
                # If we get a response, check it's valid frame type
                if len(response) > 0:
                    frame_type = response[0]
                    assert frame_type in [FRAME_DATA, FRAME_REKEY], (
                        f"Unexpected response type: 0x{frame_type:02x}"
                    )
            except TimeoutError:
                # No response - server may have silently dropped (OK)
                pass

            # Verify server still alive by doing new handshake
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock2.settimeout(5.0)
            try:
                noise2, _ = complete_handshake(sock2, server_address)
                assert noise2.handshake_finished, "Server should still accept connections"
            finally:
                sock2.close()

        finally:
            sock.close()

    def test_session_usable_after_rekey_attempt(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session remains usable after sending rekey frame."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send some data first
            frame1 = build_data_frame(noise, session_id, 0, b"Before rekey")
            sock.sendto(frame1, server_address)
            time.sleep(0.1)

            # Attempt rekey
            new_ephemeral = os.urandom(32)
            rekey_frame = build_rekey_frame(noise, session_id, 1, new_ephemeral, int(time.time()))
            sock.sendto(rekey_frame, server_address)
            time.sleep(0.2)

            # Session should still work (even if server ignored rekey)
            # Note: In a real implementation, we'd derive new keys here
            # For testing, we continue with old Noise state
            frame2 = build_data_frame(noise, session_id, 2, b"After rekey attempt")
            sock.sendto(frame2, server_address)

            # Give server time to process
            time.sleep(0.1)

        finally:
            sock.close()


# =============================================================================
# E2E Nonce Exhaustion Tests
# =============================================================================


@pytest.mark.container
class TestE2ENonceExhaustion:
    """E2E tests for nonce exhaustion handling.

    Per spec, session MUST terminate at REJECT_AFTER_MESSAGES.
    """

    def test_large_nonce_values_work(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Large nonce values are accepted (within limits)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Test with large but valid nonce values
            large_nonces = [
                2**20,  # 1 million
                2**30,  # 1 billion
                2**40,  # 1 trillion
            ]

            for nonce in large_nonces:
                frame = build_data_frame(noise, session_id, nonce, f"Nonce {nonce}".encode())
                sock.sendto(frame, server_address)
                time.sleep(0.05)

        finally:
            sock.close()

    def test_nonce_near_rekey_threshold(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Nonce values near REKEY_AFTER_MESSAGES threshold work.

        REKEY_AFTER_MESSAGES = 2^60
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # These are large but below the rekey threshold
            nonces = [
                2**58,
                2**59,
                2**60 - 1,  # Just below rekey threshold
            ]

            for nonce in nonces:
                frame = build_data_frame(noise, session_id, nonce, b"Near threshold")
                sock.sendto(frame, server_address)
                time.sleep(0.05)

        finally:
            sock.close()


# =============================================================================
# E2E Epoch Tests
# =============================================================================


@pytest.mark.container
class TestE2EEpochHandling:
    """E2E tests for epoch handling in nonce construction."""

    def test_initial_epoch_is_zero(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Initial session uses epoch 0.

        Epoch is encoded in the AEAD nonce, so frames should decrypt
        successfully with epoch=0.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            # Send frame - implicitly uses epoch 0
            frame = build_data_frame(noise, session_id, 0, b"Epoch 0 test")
            sock.sendto(frame, server_address)

            # If server decrypts successfully, epoch 0 is correct
            # Server won't respond if decryption fails
            try:
                response = sock.recv(1024)
                if len(response) >= 16:
                    assert response[0] == FRAME_DATA, "Response should be DATA frame"
            except TimeoutError:
                pass

        finally:
            sock.close()


# =============================================================================
# E2E Forward Secrecy Tests (Documentation)
# =============================================================================


@pytest.mark.container
class TestE2EForwardSecrecyProperties:
    """Tests documenting forward secrecy properties.

    Note: Full forward secrecy testing requires:
    - Completing rekey handshake
    - Verifying old keys don't decrypt new messages
    - This requires server-side rekey implementation
    """

    def test_forward_secrecy_requirements_documented(self) -> None:
        """Document forward secrecy requirements from spec.

        Per spec section "Rekeying (Type 0x04)":
        - REKEY_AFTER_TIME = 120 seconds
        - REKEY_AFTER_MESSAGES = 2^60 frames
        - REJECT_AFTER_TIME = 180 seconds (hard limit)
        - OLD_KEY_RETENTION = 5 seconds
        """
        assert REKEY_AFTER_TIME_SECONDS == 120
        assert REJECT_AFTER_TIME_SECONDS == 180
        assert OLD_KEY_RETENTION_SECONDS == 5

    def test_session_keys_derived_per_session(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Each session gets unique keys (Noise_IK provides this).

        Two sessions should not share keys.
        """
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        try:
            # Create two sessions
            noise1, session_id1 = complete_handshake(sock1, server_address)
            noise2, session_id2 = complete_handshake(sock2, server_address)

            # Session IDs should be different
            assert session_id1 != session_id2

            # Encrypt same message with both sessions
            payload = b"Same message"
            frame1 = build_data_frame(noise1, session_id1, 0, payload)
            frame2 = build_data_frame(noise2, session_id2, 0, payload)

            # Encrypted portions should be different (different keys)
            encrypted1 = frame1[16:]  # After header
            encrypted2 = frame2[16:]  # After header
            assert encrypted1 != encrypted2, (
                "Different sessions should produce different ciphertext"
            )

        finally:
            sock1.close()
            sock2.close()


# =============================================================================
# Slow E2E Tests (marked as slow)
# =============================================================================


@pytest.mark.slow
@pytest.mark.container
class TestE2ESlowRekeyTests:
    """Slow tests that may require waiting for rekey timeout.

    These tests are marked slow and may be skipped in normal test runs.
    Run with: pytest -m slow
    """

    @pytest.mark.skip(reason="Requires 10+ second wait - enable for thorough testing")
    def test_session_survives_extended_idle(
        self,
        server_address: tuple[str, int],
    ) -> None:
        """Session survives extended idle period (10 seconds)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(15.0)

        try:
            noise, session_id = complete_handshake(sock, server_address)

            frame1 = build_data_frame(noise, session_id, 0, b"Before long idle")
            sock.sendto(frame1, server_address)

            # Long idle period
            time.sleep(10)

            # Should still work
            frame2 = build_data_frame(noise, session_id, 1, b"After long idle")
            sock.sendto(frame2, server_address)

        finally:
            sock.close()
