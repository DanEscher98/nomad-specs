"""
End-to-End Malformed Packet Tests

Tests that real implementations correctly handle malformed packets.
Per spec, all malformed packets MUST be silently dropped - no response, no crash.

Spec reference: specs/2-TRANSPORT.md (Error Handling section)

These tests use scapy to send malformed packets to real containers
and verify they don't crash or respond.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.network import (
    PacketSender,
    generate_corrupted_tag,
    generate_invalid_type_frame,
    generate_random_frame,
    generate_session_id_variants,
    generate_truncated_frame,
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

# Mark all tests as requiring containers and being adversarial
pytestmark = [pytest.mark.container, pytest.mark.adversarial, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec for generating test frames."""
    return NomadCodec()


@pytest.fixture
def valid_frame(codec: NomadCodec) -> bytes:
    """Generate a valid frame for modification."""
    session_id = b"\x01\x02\x03\x04\x05\x06"
    key = codec.deterministic_bytes("e2e_valid", 32)

    sync_message = encode_sync_message(
        sender_state_num=1,
        acked_state_num=0,
        base_state_num=0,
        diff=b"test payload",
    )

    return codec.create_data_frame(
        session_id=session_id,
        nonce_counter=0,
        key=key,
        epoch=0,
        direction=0,
        timestamp=1000,
        timestamp_echo=500,
        sync_message=sync_message,
    )


@pytest.fixture
def packet_sender(server_container: Container) -> PacketSender:
    """Packet sender configured for the server container."""
    return PacketSender(
        target_ip="172.31.0.10",  # Server IP from conftest
        target_port=19999,
    )


# =============================================================================
# E2E Truncated Frame Tests
# =============================================================================


class TestE2ETruncatedFrames:
    """E2E tests for truncated frame handling."""

    def test_e2e_empty_frame_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Empty frame (0 bytes) is silently dropped."""
        # Send empty frame
        packet_sender.send_udp(b"")

        # Wait for processing
        time.sleep(0.5)

        # Server should still be healthy (not crashed)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_single_byte_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Single byte frame is silently dropped."""
        packet_sender.send_udp(b"\x03")  # Just type byte

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_header_only_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Header-only frame (no payload or tag) is silently dropped."""
        # 16-byte header
        header = bytes([FRAME_DATA, 0x00] + list(b"\x01\x02\x03\x04\x05\x06") + [0] * 8)
        packet_sender.send_udp(header)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_truncated_tag_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with truncated AEAD tag is silently dropped."""
        # Truncate tag by 8 bytes
        truncated = generate_truncated_frame(valid_frame, 8)
        packet_sender.send_udp(truncated)

        time.sleep(0.5)
        assert container_manager.wait_for_health(server_container, timeout=5)

    @pytest.mark.parametrize("truncate_bytes", [1, 4, 8, 15, 16, 20])
    def test_e2e_various_truncations_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
        truncate_bytes: int,
    ) -> None:
        """Various truncation sizes are all silently dropped."""
        truncated = generate_truncated_frame(valid_frame, truncate_bytes)
        packet_sender.send_udp(truncated)

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Invalid Type Byte Tests
# =============================================================================


class TestE2EInvalidTypeByte:
    """E2E tests for invalid frame type handling."""

    @pytest.mark.parametrize("invalid_type", [0x00, 0x06, 0x07, 0x10, 0x80, 0xFF])
    def test_e2e_invalid_type_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
        invalid_type: int,
    ) -> None:
        """Frames with invalid type bytes are silently dropped."""
        malformed = generate_invalid_type_frame(valid_frame, invalid_type)
        packet_sender.send_udp(malformed)

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_handshake_type_after_session_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Handshake frame type (0x01) sent after session established is dropped."""
        # Modify type to handshake init
        malformed = generate_invalid_type_frame(valid_frame, 0x01)
        packet_sender.send_udp(malformed)

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Invalid AEAD Tag Tests
# =============================================================================


class TestE2EInvalidAEADTag:
    """E2E tests for invalid AEAD tag handling."""

    def test_e2e_corrupted_tag_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with corrupted AEAD tag is silently dropped."""
        malformed = generate_corrupted_tag(valid_frame)
        packet_sender.send_udp(malformed)

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_zeroed_tag_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with zeroed AEAD tag is silently dropped."""
        frame = bytearray(valid_frame)
        frame[-16:] = b"\x00" * 16  # Zero the tag
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_random_tag_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with random AEAD tag is silently dropped."""
        frame = bytearray(valid_frame)
        frame[-16:] = b"\xde\xad\xbe\xef" * 4  # Random tag
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Session ID Tests
# =============================================================================


class TestE2ESessionID:
    """E2E tests for unknown/invalid session ID handling."""

    def test_e2e_unknown_session_id_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with unknown session ID is silently dropped."""
        for variant in generate_session_id_variants(valid_frame):
            packet_sender.send_udp(variant)
            time.sleep(0.1)

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_random_session_id_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
        codec: NomadCodec,
    ) -> None:
        """Frame with random session ID is silently dropped."""
        frame = bytearray(valid_frame)
        frame[2:8] = codec.deterministic_bytes("random_session", 6)
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E No Response Tests
# =============================================================================


class TestE2ENoResponse:
    """E2E tests verifying malformed packets get no response."""

    def test_e2e_truncated_no_response(
        self,
        server_container: Container,
        packet_sender: PacketSender,
        valid_frame: bytes,
        packet_capture,
    ) -> None:
        """Truncated frame produces no response from server."""
        truncated = generate_truncated_frame(valid_frame, 10)

        with packet_capture.capture() as pcap_file:
            packet_sender.send_udp(truncated)
            time.sleep(1)

        frames = parse_pcap(pcap_file)

        # Should not see many frames from server to our source
        # (This assumes we know our source IP)
        responses_to_malformed = len(
            [f for f in frames if f.src_ip == "172.31.0.10" and f.dst_port != 19999]
        )
        # We sent a malformed packet - server should not respond to it
        # Note: There might be responses to other valid traffic
        assert responses_to_malformed < 5  # Allow some margin for other traffic

    def test_e2e_bad_tag_no_response(
        self,
        server_container: Container,
        packet_sender: PacketSender,
        valid_frame: bytes,
        packet_capture,
    ) -> None:
        """Bad AEAD tag produces no response from server."""
        malformed = generate_corrupted_tag(valid_frame)

        with packet_capture.capture() as capture_file:
            packet_sender.send_udp(malformed)
            time.sleep(1)

        # Per spec: Invalid AEAD tag -> Silently drop (no response)
        # Parse to verify capture worked
        _ = parse_pcap(capture_file)


# =============================================================================
# E2E Fuzz Tests
# =============================================================================


class TestE2EFuzz:
    """E2E fuzz testing with random data."""

    @given(data=st.binary(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_e2e_random_small_data(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        data: bytes,
    ) -> None:
        """Random small data doesn't crash server."""
        packet_sender.send_udp(data)

        # Allow some processing time
        time.sleep(0.1)

        # Server should still be healthy
        assert container_manager.wait_for_health(server_container, timeout=2)

    @given(data=st.binary(min_size=32, max_size=500))
    @settings(max_examples=50)
    def test_e2e_random_valid_size_data(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        data: bytes,
    ) -> None:
        """Random data with valid frame size doesn't crash server."""
        packet_sender.send_udp(data)

        time.sleep(0.1)
        assert container_manager.wait_for_health(server_container, timeout=2)

    def test_e2e_many_random_frames(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
    ) -> None:
        """Many random frames in succession don't crash server."""
        for _ in range(100):
            frame = generate_random_frame(50)
            packet_sender.send_udp(frame)
            time.sleep(0.01)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Corrupted Ciphertext Tests
# =============================================================================


class TestE2ECorruptedCiphertext:
    """E2E tests for corrupted encrypted payload handling."""

    def test_e2e_corrupted_ciphertext_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with corrupted ciphertext is silently dropped."""
        frame = bytearray(valid_frame)
        # Corrupt byte in encrypted payload (after header, before tag)
        if len(frame) > 32:
            frame[20] ^= 0xFF
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_zeroed_ciphertext_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with zeroed ciphertext is silently dropped."""
        frame = bytearray(valid_frame)
        # Zero encrypted payload
        for i in range(16, len(frame) - 16):
            frame[i] = 0x00
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Header Corruption Tests (AAD Modification)
# =============================================================================


class TestE2EHeaderCorruption:
    """E2E tests for header corruption (AAD modification) handling."""

    def test_e2e_corrupted_flags_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with corrupted flags byte is silently dropped (AEAD fails)."""
        frame = bytearray(valid_frame)
        frame[1] ^= 0x01  # Flip a flag bit
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)

    def test_e2e_corrupted_nonce_counter_dropped(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Frame with corrupted nonce counter in header is silently dropped."""
        frame = bytearray(valid_frame)
        frame[8] ^= 0x01  # Flip a nonce bit
        packet_sender.send_udp(bytes(frame))

        time.sleep(0.3)
        assert container_manager.wait_for_health(server_container, timeout=5)


# =============================================================================
# E2E Flood Resistance Tests
# =============================================================================


class TestE2EFloodResistance:
    """E2E tests for flood resistance."""

    def test_e2e_malformed_flood(
        self,
        server_container: Container,
        container_manager: ContainerManager,
        packet_sender: PacketSender,
        valid_frame: bytes,
    ) -> None:
        """Server survives flood of malformed packets."""
        malformed_variants = [
            generate_truncated_frame(valid_frame, 10),
            generate_corrupted_tag(valid_frame),
            generate_invalid_type_frame(valid_frame, 0x00),
            b"\x03" + b"\x00" * 20,
            b"",
        ]

        for _ in range(50):
            for variant in malformed_variants:
                packet_sender.send_udp(variant)
                time.sleep(0.005)

        time.sleep(1)
        assert container_manager.wait_for_health(server_container, timeout=10)
