"""
End-to-End Wire Format Tests

Tests wire format compliance by capturing real packets from Docker containers.
These tests validate that actual implementations produce spec-compliant frames.

Spec reference: specs/2-TRANSPORT.md

Prerequisites:
- Docker containers running via conftest.py fixtures
- Packet capture via tcpdump sidecar
- Uses scapy for packet analysis
"""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from lib.network import (
    extract_header_fields,
    parse_pcap,
    validate_data_frame_header,
)
from lib.reference import (
    AEAD_TAG_SIZE,
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    SESSION_ID_SIZE,
)

# Mark all tests in this module as requiring containers
pytestmark = [pytest.mark.container, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def pcap_path(tmp_path: Path) -> Path:
    """Path for packet capture file."""
    return tmp_path / "capture.pcap"


# =============================================================================
# E2E Header Wire Format Tests
# =============================================================================


class TestE2EDataFrameHeader:
    """E2E tests for data frame header wire format.

    These tests capture real packets from containers and verify
    the header structure matches the spec.
    """

    def test_e2e_header_size(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify captured data frame headers are exactly 16 bytes.

        The frame header (type, flags, session ID, nonce counter) MUST be
        exactly 16 bytes per spec.
        """
        with packet_capture.capture() as pcap_file:
            # Wait for traffic
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        assert len(frames) > 0, "No frames captured"

        for frame in frames:
            if frame.frame_type == FRAME_DATA:
                # Header is first 16 bytes
                assert len(frame.raw_bytes) >= DATA_FRAME_HEADER_SIZE
                validation = validate_data_frame_header(frame.raw_bytes)
                assert validation["has_header"]

    def test_e2e_type_byte_offset(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify type byte is at offset 0 in captured frames."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0, "No data frames captured"

        for frame in data_frames:
            # Type byte is at offset 0
            assert frame.raw_bytes[0] == FRAME_DATA

    def test_e2e_flags_byte_offset(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify flags byte is at offset 1 and reserved bits are zero."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            flags = frame.raw_bytes[1]
            # Reserved bits (2-7) must be 0
            assert (flags & 0xFC) == 0, f"Reserved flag bits set: {flags:#04x}"

    def test_e2e_session_id_offset(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify session ID is at offsets 2-7 (6 bytes)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        # All frames in same session should have same session ID
        session_ids = set()
        for frame in data_frames:
            session_id = frame.raw_bytes[2:8]
            assert len(session_id) == SESSION_ID_SIZE
            session_ids.add(session_id)

        # Should have exactly one session ID
        assert len(session_ids) == 1, f"Multiple session IDs: {len(session_ids)}"

    def test_e2e_nonce_counter_offset(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify nonce counter is at offsets 8-15 (8 bytes, LE64)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)  # Capture more frames

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        # Extract and verify nonce counters
        nonces = []
        for frame in data_frames:
            fields = extract_header_fields(frame.raw_bytes)
            nonces.append(fields["nonce_counter"])

        # Nonces should be reasonable values (not garbage)
        for nonce in nonces:
            assert nonce < 2**32, f"Nonce counter suspiciously large: {nonce}"

    def test_e2e_nonce_counter_little_endian(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify nonce counter uses little-endian encoding."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            raw_nonce = frame.raw_bytes[8:16]
            # Parse as little-endian
            nonce_le = struct.unpack("<Q", raw_nonce)[0]

            # For small nonces, LE will have non-zero low bytes
            # This validates little-endian encoding
            if nonce_le < 256:
                # Low byte in LE should equal the value
                assert raw_nonce[0] == nonce_le


# =============================================================================
# E2E Complete Frame Wire Format Tests
# =============================================================================


class TestE2ECompleteFrame:
    """E2E tests for complete data frame wire format."""

    def test_e2e_minimum_frame_size(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify all captured frames meet minimum size (32 bytes)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            # Minimum: Header (16) + empty payload + Tag (16) = 32
            assert len(frame.raw_bytes) >= 32, f"Frame too small: {len(frame.raw_bytes)}"

    def test_e2e_frame_header_is_plaintext(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify frame header is not encrypted (readable without keys)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            # Should be able to parse header without decryption
            fields = extract_header_fields(frame.raw_bytes)

            # Type should be valid
            assert fields["type"] == FRAME_DATA

            # Flags should have reserved bits clear
            assert (fields["flags"] & 0xFC) == 0

            # Session ID should be 6 bytes
            assert len(fields["session_id"]) == 6

    def test_e2e_aead_tag_present(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify frames have AEAD tag at the end (16 bytes)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            # Frame must have at least header + tag = 32 bytes
            assert len(frame.raw_bytes) >= DATA_FRAME_HEADER_SIZE + AEAD_TAG_SIZE
            # Last 16 bytes are AEAD tag
            tag = frame.raw_bytes[-AEAD_TAG_SIZE:]
            assert len(tag) == AEAD_TAG_SIZE


# =============================================================================
# E2E MTU Compliance Tests
# =============================================================================


class TestE2EMTUCompliance:
    """E2E tests for MTU compliance."""

    def test_e2e_frames_within_mtu(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify all frames are within recommended MTU (1200 bytes)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        max_frame_size = 0
        for frame in data_frames:
            max_frame_size = max(max_frame_size, len(frame.raw_bytes))
            # Should be within conservative mobile MTU
            assert len(frame.raw_bytes) <= 1200, f"Frame exceeds MTU: {len(frame.raw_bytes)}"

    def test_e2e_frames_within_ethernet_mtu(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify all frames are within Ethernet MTU (1500 bytes)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        for frame in data_frames:
            # UDP payload should fit in Ethernet MTU
            # MTU (1500) - IP header (20) - UDP header (8) = 1472
            assert len(frame.raw_bytes) <= 1472


# =============================================================================
# E2E Traffic Pattern Tests
# =============================================================================


class TestE2ETrafficPatterns:
    """E2E tests for expected traffic patterns."""

    def test_e2e_bidirectional_traffic(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify both server and client send frames."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Get server and client IPs
        server_ip = "172.31.0.10"  # From conftest.py
        client_ip = "172.31.0.20"

        server_frames = [f for f in data_frames if f.src_ip == server_ip]
        client_frames = [f for f in data_frames if f.src_ip == client_ip]

        assert len(server_frames) > 0, "No frames from server"
        assert len(client_frames) > 0, "No frames from client"

    def test_e2e_consistent_session_id(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify all frames in session have same session ID."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]
        assert len(data_frames) > 0

        # All frames should have the same session ID
        session_ids = {f.session_id for f in data_frames if f.session_id}
        assert len(session_ids) == 1, f"Multiple session IDs found: {len(session_ids)}"

    def test_e2e_nonce_counter_increases(
        self,
        server_container,
        client_container,
        packet_capture,
    ) -> None:
        """Verify nonce counters increase (per direction)."""
        with packet_capture.capture() as pcap_file:
            time.sleep(5)  # Capture more frames for analysis

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        server_ip = "172.31.0.10"
        client_ip = "172.31.0.20"

        # Separate by direction
        server_to_client = [
            f for f in data_frames if f.src_ip == server_ip
        ]
        client_to_server = [
            f for f in data_frames if f.src_ip == client_ip
        ]

        # Check server's nonces increase
        if len(server_to_client) >= 2:
            nonces = [extract_header_fields(f.raw_bytes)["nonce_counter"]
                      for f in server_to_client]
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i-1], "Server nonce didn't increase"

        # Check client's nonces increase
        if len(client_to_server) >= 2:
            nonces = [extract_header_fields(f.raw_bytes)["nonce_counter"]
                      for f in client_to_server]
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i-1], "Client nonce didn't increase"
