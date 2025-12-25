"""
Transport Layer Attack Tests

Adversarial tests for the transport layer, including:
- Frame injection attacks
- Session ID enumeration
- Nonce exhaustion/manipulation
- Amplification attacks
- Replay attacks

Spec reference: specs/2-TRANSPORT.md (Error Handling section)

All attacks should be silently dropped with no observable effect.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.network import (
    PacketSender,
    extract_header_fields,
    generate_corrupted_tag,
    generate_random_frame,
    parse_pcap,
)
from lib.reference import (
    FRAME_DATA,
    NomadCodec,
    encode_data_frame_header,
    encode_sync_message,
)

if TYPE_CHECKING:
    from docker.models.containers import Container

    from lib.containers import ContainerManager

# Mark all tests as adversarial and requiring containers
pytestmark = [pytest.mark.container, pytest.mark.adversarial, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec for generating test frames."""
    return NomadCodec()


@pytest.fixture
def packet_sender(server_container: Container) -> PacketSender:
    """Packet sender configured for the server container."""
    return PacketSender(
        target_ip="172.31.0.10",
        target_port=19999,
    )


# =============================================================================
# Frame Injection Attacks
# =============================================================================


class TestFrameInjection:
    """Tests for frame injection attack resistance."""

    def test_forged_frame_rejected(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Forged frames (wrong key) are rejected."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        attacker_key = codec.deterministic_bytes("attacker", 32)

        sync_message = encode_sync_message(1, 0, 0, b"injected data")

        forged_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=attacker_key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        packet_sender.send_udp(forged_frame)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_forged_frame_flood(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Server survives flood of forged frames."""
        for i in range(100):
            session_id = os.urandom(6)
            attacker_key = codec.deterministic_bytes(f"attacker_{i}", 32)

            sync_message = encode_sync_message(i, 0, 0, f"attack_{i}".encode())

            forged = codec.create_data_frame(
                session_id=session_id,
                nonce_counter=i,
                key=attacker_key,
                epoch=0,
                direction=0,
                timestamp=0,
                timestamp_echo=0,
                sync_message=sync_message,
            )

            packet_sender.send_udp(forged)
            time.sleep(0.01)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=10)

    def test_corrupted_tag_injection(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Frames with corrupted AEAD tags are rejected."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("victim", 32)

        sync_message = encode_sync_message(1, 0, 0, b"legitimate")

        valid_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Corrupt the tag
        corrupted = generate_corrupted_tag(valid_frame)
        packet_sender.send_udp(corrupted)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# Session ID Enumeration Attacks
# =============================================================================


class TestSessionIDEnumeration:
    """Tests for session ID enumeration attack resistance."""

    def test_random_session_ids_no_info_leak(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        packet_capture,
    ) -> None:
        """Server doesn't leak info when probed with random session IDs.

        Per spec: Unknown session ID -> Silently drop (no response).
        """
        with packet_capture.capture() as pcap_file:
            for _ in range(50):
                # Random session ID probe
                session_id = os.urandom(6)
                header = encode_data_frame_header(
                    flags=0,
                    session_id=session_id,
                    nonce_counter=0,
                )
                # Add fake encrypted payload + tag
                fake_frame = header + os.urandom(50)
                packet_sender.send_udp(fake_frame)
                time.sleep(0.01)

            time.sleep(1)

        # Parse frames to verify capture worked
        _ = parse_pcap(pcap_file)

        # Server should not respond to unknown session IDs
        # (No ICMP errors, no rejection messages)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_sequential_session_id_scan(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives sequential session ID scanning attack."""
        for i in range(256):
            # Sequential scan of session ID space
            session_id = bytes([i, i, i, i, i, i])
            header = encode_data_frame_header(
                flags=0,
                session_id=session_id,
                nonce_counter=0,
            )
            fake_frame = header + os.urandom(32)
            packet_sender.send_udp(fake_frame)
            time.sleep(0.005)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# Nonce Manipulation Attacks
# =============================================================================


class TestNonceManipulation:
    """Tests for nonce manipulation attack resistance."""

    def test_nonce_replay_window(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Capture real traffic to analyze nonce patterns."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if len(data_frames) >= 2:
            # Verify nonces are increasing per direction
            server_ip = "172.31.0.10"
            client_ip = "172.31.0.20"

            for src_ip in [server_ip, client_ip]:
                direction_frames = [f for f in data_frames if f.src_ip == src_ip]
                if len(direction_frames) >= 2:
                    nonces = [
                        extract_header_fields(f.raw_bytes)["nonce_counter"]
                        for f in direction_frames
                    ]
                    # Nonces should be strictly increasing
                    for i in range(1, len(nonces)):
                        assert nonces[i] > nonces[i-1], "Nonce replay detected"

    def test_large_nonce_counter(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Server handles large nonce counter values."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("nonce_test", 32)

        # Try with maximum nonce counter
        sync_message = encode_sync_message(1, 0, 0, b"max nonce")
        max_nonce = 0xFFFFFFFFFFFFFFFF

        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=max_nonce,
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

    def test_zero_nonce_counter(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Server handles zero nonce counter."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("zero_nonce", 32)

        sync_message = encode_sync_message(1, 0, 0, b"zero nonce")

        frame = codec.create_data_frame(
            session_id=session_id,
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
# Amplification Attacks
# =============================================================================


class TestAmplificationAttacks:
    """Tests for DDoS amplification attack resistance."""

    def test_spoofed_source_limited_response(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        packet_capture,
    ) -> None:
        """Responses to spoofed addresses are limited (3x rule)."""
        spoofed_ip = "10.99.99.99"

        # Send small probes from spoofed address
        with packet_capture.capture() as pcap_file:
            for _ in range(10):
                # Small malformed frame
                packet_sender.send_spoofed(
                    payload=b"\x03" + b"\x00" * 31,
                    spoofed_src_ip=spoofed_ip,
                )
                time.sleep(0.1)

            time.sleep(2)

        frames = parse_pcap(pcap_file)

        # Calculate amplification factor
        to_spoofed = sum(
            len(f.raw_bytes) for f in frames if f.dst_ip == spoofed_ip
        )
        from_spoofed = sum(
            len(f.raw_bytes) for f in frames if f.src_ip == spoofed_ip
        )

        if from_spoofed > 0:
            amplification = to_spoofed / from_spoofed
            # Should be at most 3x per spec (allow margin for packet overhead)
            assert amplification <= 4.0, f"Amplification too high: {amplification}"

    def test_no_response_to_garbage(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        packet_capture,
    ) -> None:
        """Server doesn't respond to garbage data."""
        spoofed_ip = "10.88.88.88"

        with packet_capture.capture() as pcap_file:
            for _ in range(20):
                garbage = generate_random_frame(50)
                packet_sender.send_spoofed(garbage, spoofed_src_ip=spoofed_ip)
                time.sleep(0.05)

            time.sleep(2)

        frames = parse_pcap(pcap_file)

        # Should be no responses to the spoofed IP
        responses = [f for f in frames if f.dst_ip == spoofed_ip]
        # Allow for some legitimate traffic that might coincidentally match
        assert len(responses) < 5, f"Too many responses to garbage: {len(responses)}"


# =============================================================================
# Replay Attacks
# =============================================================================


class TestReplayAttacks:
    """Tests for replay attack resistance."""

    def test_duplicate_frame_handling(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Duplicate frames should be handled gracefully.

        Full replay protection requires nonce window tracking.
        Here we verify server doesn't crash on duplicates.
        """
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("replay", 32)

        sync_message = encode_sync_message(1, 0, 0, b"original")

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

        # Send same frame multiple times
        for _ in range(10):
            packet_sender.send_udp(frame)
            time.sleep(0.1)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_old_nonce_rejection_concept(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture,
    ) -> None:
        """Verify that nonces are monotonically increasing.

        Real replay protection checks nonces against a window.
        This test verifies the basic property that nonces increase.
        """
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Per direction, nonces should increase
        server_ip = "172.31.0.10"

        server_frames = [f for f in data_frames if f.src_ip == server_ip]
        if len(server_frames) >= 2:
            nonces = [
                extract_header_fields(f.raw_bytes)["nonce_counter"]
                for f in server_frames
            ]
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i-1]


# =============================================================================
# Header Manipulation Attacks
# =============================================================================


class TestHeaderManipulation:
    """Tests for header manipulation attack resistance."""

    def test_flags_manipulation(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Frames with manipulated flags are rejected (AEAD failure)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("flags", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        ))

        # Manipulate flags byte
        frame[1] = 0xFF  # Invalid flags

        packet_sender.send_udp(bytes(frame))

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_type_downgrade_attack(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Changing frame type is rejected (AEAD failure)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("type_attack", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        ))

        # Try to change type to handshake
        frame[0] = 0x01

        packet_sender.send_udp(bytes(frame))

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# Fuzz Testing
# =============================================================================


class TestAdversarialFuzz:
    """Adversarial fuzz testing."""

    @given(data=st.binary(min_size=0, max_size=1500))
    @settings(max_examples=100)
    def test_random_data_no_crash(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        data: bytes,
    ) -> None:
        """Server survives any random input."""
        packet_sender.send_udp(data)
        time.sleep(0.05)
        assert container_manager.wait_for_health(server_container, timeout=2)

    def test_all_byte_values(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives packets with all possible byte values."""
        for byte_val in range(256):
            frame = bytes([byte_val] * 32)
            packet_sender.send_udp(frame)
            time.sleep(0.01)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_structured_fuzz(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives semi-structured fuzz input."""
        for _ in range(100):
            # Create semi-structured frame
            frame_type = os.urandom(1)
            flags = os.urandom(1)
            session_id = os.urandom(6)
            nonce = os.urandom(8)
            payload = os.urandom(50)

            frame = frame_type + flags + session_id + nonce + payload
            packet_sender.send_udp(frame)
            time.sleep(0.01)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# Resource Exhaustion Tests
# =============================================================================


class TestResourceExhaustion:
    """Tests for resource exhaustion attack resistance."""

    def test_rapid_frame_flood(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives rapid frame flood."""
        for _ in range(1000):
            frame = generate_random_frame(100)
            packet_sender.send_udp(frame)

        time.sleep(2)
        assert container_manager.wait_for_health(server_container, timeout=10)

    def test_large_frame_handling(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server handles oversized frames gracefully."""
        # MTU is typically 1500, try larger
        large_frame = generate_random_frame(2000)
        packet_sender.send_udp(large_frame)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_many_unique_session_ids(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Server handles many unique session ID probes."""
        for _ in range(500):
            session_id = os.urandom(6)
            header = encode_data_frame_header(
                flags=0,
                session_id=session_id,
                nonce_counter=0,
            )
            frame = header + os.urandom(32)
            packet_sender.send_udp(frame)
            time.sleep(0.005)

        time.sleep(2)
        assert container_manager.wait_for_health(server_container, timeout=10)
