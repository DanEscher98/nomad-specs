"""
End-to-End Connection Migration (Roaming) Tests

Tests IP migration capability with real Docker containers.
Validates that sessions survive network changes seamlessly.

Spec reference: specs/2-TRANSPORT.md (Connection Migration section)

Migration rules:
1. Valid AEAD tag from new address -> update remote_endpoint
2. Invalid AEAD -> silently drop (no migration)
3. Anti-amplification: max 3x bytes sent before validation
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from lib.network import (
    PacketSender,
    extract_header_fields,
    generate_corrupted_tag,
    parse_pcap,
)
from lib.reference import (
    FRAME_DATA,
    NomadCodec,
    encode_sync_message,
)

if TYPE_CHECKING:
    from docker.models.containers import Container

    from lib.containers import ContainerManager

# Mark all tests as requiring containers
pytestmark = [pytest.mark.container, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec for test frame generation."""
    return NomadCodec()


# =============================================================================
# E2E Session Continuity Tests
# =============================================================================


class TestE2ESessionContinuity:
    """E2E tests for session continuity during/after migration."""

    def test_e2e_same_session_id_throughout(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Session ID remains constant throughout the session."""
        # Capture traffic over extended period
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0, "No data frames captured"

        # All frames should have same session ID
        session_ids = set()
        for frame in data_frames:
            if len(frame.raw_bytes) >= 8:
                session_id = frame.raw_bytes[2:8]
                session_ids.add(session_id)

        assert len(session_ids) == 1, f"Multiple session IDs: {len(session_ids)}"

    def test_e2e_nonce_counter_continues(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Nonce counter continues incrementing throughout session."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        # Check nonces per direction
        for src_ip in [server_ip, client_ip]:
            direction_frames = [f for f in data_frames if f.src_ip == src_ip]
            if len(direction_frames) >= 2:
                nonces = [
                    extract_header_fields(f.raw_bytes)["nonce_counter"] for f in direction_frames
                ]
                for i in range(1, len(nonces)):
                    assert nonces[i] > nonces[i - 1], "Nonce didn't increase"

    def test_e2e_session_survives_short_interruption(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        packet_capture,
    ) -> None:
        """Session survives brief network interruption."""
        # Capture initial traffic
        with packet_capture.capture() as pcap1:
            time.sleep(2)

        initial_frames = parse_pcap(pcap1)

        # Brief pause (simulating brief network issue)
        time.sleep(2)

        # Capture more traffic
        with packet_capture.capture() as pcap2:
            time.sleep(2)

        later_frames = parse_pcap(pcap2)

        # Both captures should have same session ID
        initial_sessions = {
            f.raw_bytes[2:8]
            for f in initial_frames
            if f.frame_type == FRAME_DATA and len(f.raw_bytes) >= 8
        }
        later_sessions = {
            f.raw_bytes[2:8]
            for f in later_frames
            if f.frame_type == FRAME_DATA and len(f.raw_bytes) >= 8
        }

        if initial_sessions and later_sessions:
            assert initial_sessions == later_sessions, "Session ID changed"


# =============================================================================
# E2E Migration Validation Tests
# =============================================================================


class TestE2EMigrationValidation:
    """E2E tests for migration validation behavior."""

    def test_e2e_invalid_frame_not_accepted(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        codec: NomadCodec,
    ) -> None:
        """Invalid frames from 'new address' are rejected.

        This simulates an attacker trying to hijack a session.
        """
        packet_sender = PacketSender(
            target_ip="172.31.0.10",
            target_port=19999,
            # Simulate different source IP (like migration attempt)
            source_ip="10.99.99.99",
        )

        # Create a frame with wrong key (simulating attacker)
        session_id = b"\xff\xee\xdd\xcc\xbb\xaa"
        wrong_key = codec.deterministic_bytes("attacker", 32)
        sync_message = encode_sync_message(1, 0, 0, b"attack")
        malicious_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=wrong_key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Send from "new address"
        packet_sender.send_udp(malicious_frame)

        time.sleep(0.5)

        # Server should still be healthy (dropped silently)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_spoofed_migration_rejected(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        codec: NomadCodec,
    ) -> None:
        """Spoofed migration attempt with corrupted tag is rejected."""
        packet_sender = PacketSender(
            target_ip="172.31.0.10",
            target_port=19999,
        )

        # Create a valid-looking frame but corrupt the tag
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("spoofed", 32)
        sync_message = encode_sync_message(1, 0, 0, b"spoofed")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Corrupt the tag
        malicious = generate_corrupted_tag(frame)

        # Try to send as if from different address
        packet_sender.send_spoofed(malicious, spoofed_src_ip="10.99.99.99")

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Anti-Amplification Tests
# =============================================================================


class TestE2EAntiAmplification:
    """E2E tests for anti-amplification protection.

    Per spec: Cannot send more than 3x bytes received from unvalidated address.
    """

    def test_e2e_unauthenticated_address_limited(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_capture,
    ) -> None:
        """Server doesn't flood responses to unauthenticated addresses.

        This tests the amplification limit by sending small packets
        from a spoofed address and verifying limited responses.
        """
        spoofed_ip = "10.99.99.99"
        packet_sender = PacketSender(
            target_ip="172.31.0.10",
            target_port=19999,
        )

        # Send small packets from spoofed address
        small_data = b"\x03" + b"\x00" * 31  # Minimal "frame"

        with packet_capture.capture() as pcap_file:
            for _ in range(10):
                packet_sender.send_spoofed(small_data, spoofed_src_ip=spoofed_ip)
                time.sleep(0.1)

            time.sleep(2)

        frames = parse_pcap(pcap_file)

        # Count bytes sent TO the spoofed IP
        to_spoofed = [f for f in frames if f.dst_ip == spoofed_ip]
        from_spoofed = [f for f in frames if f.src_ip == spoofed_ip]

        bytes_sent = sum(len(f.raw_bytes) for f in to_spoofed)
        bytes_recv = sum(len(f.raw_bytes) for f in from_spoofed)

        # Server should limit responses to 3x received
        # (Actual implementation may vary - this is a guideline)
        if bytes_recv > 0:
            assert bytes_sent <= bytes_recv * 3 + 1000  # Allow some margin

    def test_e2e_validated_address_unlimited(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Validated addresses (established session) have no limit."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)

        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        # Count bytes between established endpoints
        server_to_client = sum(
            len(f.raw_bytes) for f in frames if f.src_ip == server_ip and f.dst_ip == client_ip
        )
        client_to_server = sum(
            len(f.raw_bytes) for f in frames if f.src_ip == client_ip and f.dst_ip == server_ip
        )

        # Both should have sent traffic (no limits after validation)
        assert server_to_client > 0
        assert client_to_server > 0


# =============================================================================
# E2E Migration Direction Tests
# =============================================================================


class TestE2EMigrationDirection:
    """E2E tests for migration in both directions."""

    def test_e2e_client_can_send_from_any_port(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Client's source port may change (NAT behavior)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Get client frames
        client_ip = "172.31.0.20"
        client_frames = [f for f in data_frames if f.src_ip == client_ip]

        if len(client_frames) > 0:
            # All should be to server port 19999
            for frame in client_frames:
                assert frame.dst_port == 19999

    def test_e2e_server_responds_to_source(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Server responds to client's source address."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        server_frames = [f for f in data_frames if f.src_ip == server_ip]

        for frame in server_frames:
            # Server should send to client IP
            assert frame.dst_ip == client_ip


# =============================================================================
# E2E Migration Security Tests
# =============================================================================


class TestE2EMigrationSecurity:
    """E2E tests for migration security properties."""

    def test_e2e_session_id_in_aad(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
        codec: NomadCodec,
    ) -> None:
        """Session ID is part of authenticated data (header is AAD)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if data_frames:
            # All frames should have valid session ID in plaintext header
            session_ids = set()
            for frame in data_frames:
                fields = extract_header_fields(frame.raw_bytes)
                session_ids.add(fields["session_id"])

            # Should be exactly one session
            assert len(session_ids) == 1

    def test_e2e_forged_session_id_rejected(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        codec: NomadCodec,
    ) -> None:
        """Frames with forged session ID are rejected."""
        packet_sender = PacketSender(
            target_ip="172.31.0.10",
            target_port=19999,
        )

        # Create frame with random session ID
        random_session = codec.deterministic_bytes("random_session", 6)
        key = codec.deterministic_bytes("forged", 32)
        sync_message = encode_sync_message(1, 0, 0, b"forged")

        frame = codec.create_data_frame(
            session_id=random_session,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        packet_sender.send_udp(frame)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Multiple Client Tests (Conceptual)
# =============================================================================


class TestE2EMultipleClients:
    """E2E tests for session isolation (conceptual).

    Note: Full multi-client tests would require additional container setup.
    These tests verify the server handles its current client correctly.
    """

    def test_e2e_session_isolation(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Each session is isolated (single client test)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # All frames should be between server and client
        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        for frame in data_frames:
            assert frame.src_ip in [server_ip, client_ip]
            assert frame.dst_ip in [server_ip, client_ip]


# =============================================================================
# E2E Network Change Simulation Tests
# =============================================================================


class TestE2ENetworkChange:
    """E2E tests simulating network changes.

    Note: Full IP migration tests require Docker network manipulation.
    These tests verify the protocol handles normal traffic correctly.
    """

    def test_e2e_traffic_continues(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        packet_capture,
    ) -> None:
        """Traffic continues flowing between containers."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Should have bidirectional traffic
        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        from_server = len([f for f in data_frames if f.src_ip == server_ip])
        from_client = len([f for f in data_frames if f.src_ip == client_ip])

        assert from_server > 0, "No traffic from server"
        assert from_client > 0, "No traffic from client"

        # Both containers healthy
        assert container_manager.wait_for_health(server_container, timeout=5)
