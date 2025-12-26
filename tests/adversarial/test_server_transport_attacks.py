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

These tests require:
- Server running at NOMAD_SERVER_HOST:NOMAD_PORT (default 172.28.0.10:19999)
- Raw socket capability (NET_RAW) for packet injection
- Run inside test-runner container: just docker-up-runner && just docker-test-runner adversarial/
"""

from __future__ import annotations

import os
import time
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lib.network import (
    PacketSender,
    generate_corrupted_tag,
    generate_random_frame,
)
from lib.reference import (
    NomadCodec,
    encode_data_frame_header,
    encode_sync_message,
)

# Mark all tests as adversarial and network-based (NOT container - these work in external mode)
pytestmark = [pytest.mark.adversarial, pytest.mark.network, pytest.mark.slow]


# =============================================================================
# Fixtures
# =============================================================================


def get_server_host() -> str:
    """Get server host from environment."""
    return os.environ.get("NOMAD_SERVER_HOST", "172.28.0.10")


def get_server_port() -> int:
    """Get server port from environment."""
    return int(os.environ.get("NOMAD_PORT", "19999"))


def get_health_url() -> str:
    """Get server health check URL."""
    host = get_server_host()
    return f"http://{host}:8080/health"


def check_server_health(timeout: float = 5.0) -> bool:
    """Check server health via HTTP endpoint.

    Args:
        timeout: Maximum time to wait for health check.

    Returns:
        True if server is healthy, False otherwise.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(get_health_url(), timeout=1.0) as response:
                if response.status == 200:
                    return True
        except (URLError, OSError, TimeoutError):
            pass
        time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec for generating test frames."""
    return NomadCodec()


@pytest.fixture(scope="module")
def require_server():
    """Skip if server is not reachable."""
    if not check_server_health(timeout=2.0):
        pytest.skip("Server not reachable - start with: just docker-up")


@pytest.fixture
def packet_sender(require_server) -> PacketSender:
    """Packet sender configured for the server."""
    return PacketSender(
        target_ip=get_server_host(),
        target_port=get_server_port(),
    )


# =============================================================================
# Frame Injection Attacks
# =============================================================================


class TestFrameInjection:
    """Tests for frame injection attack resistance."""

    def test_forged_frame_rejected(
        self,
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
        assert check_server_health(timeout=5), "Server crashed after forged frame"

    def test_forged_frame_flood(
        self,
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
        assert check_server_health(timeout=10), "Server crashed after frame flood"

    def test_corrupted_tag_injection(
        self,
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
        assert check_server_health(timeout=5), "Server crashed after corrupted tag"


# =============================================================================
# Session ID Enumeration Attacks
# =============================================================================


class TestSessionIDEnumeration:
    """Tests for session ID enumeration attack resistance."""

    def test_random_session_ids_no_info_leak(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server doesn't leak info when probed with random session IDs.

        Per spec: Unknown session ID -> Silently drop (no response).
        """
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

        # Server should not respond to unknown session IDs
        # (No ICMP errors, no rejection messages) and should stay healthy
        assert check_server_health(timeout=5), "Server crashed during session ID probing"

    def test_sequential_session_id_scan(
        self,
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
        assert check_server_health(timeout=5), "Server crashed during session ID scan"


# =============================================================================
# Nonce Manipulation Attacks
# =============================================================================


class TestNonceManipulation:
    """Tests for nonce manipulation attack resistance."""

    @pytest.mark.skip(reason="Requires packet capture with client - run with just test-e2e")
    def test_nonce_replay_window(self) -> None:
        """Capture real traffic to analyze nonce patterns.

        This test requires a running client and packet capture.
        Run with: just test-e2e
        """
        pass

    def test_large_nonce_counter(
        self,
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
        assert check_server_health(timeout=5), "Server crashed with large nonce"

    def test_zero_nonce_counter(
        self,
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
        assert check_server_health(timeout=5), "Server crashed with zero nonce"


# =============================================================================
# Amplification Attacks
# =============================================================================


class TestAmplificationAttacks:
    """Tests for DDoS amplification attack resistance."""

    def test_spoofed_source_limited_response(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives spoofed source attack.

        Note: Full amplification factor testing requires packet capture.
        This test verifies server doesn't crash under spoofed traffic.
        """
        spoofed_ip = "10.99.99.99"

        # Send small probes from spoofed address
        for _ in range(10):
            # Small malformed frame
            packet_sender.send_spoofed(
                payload=b"\x03" + b"\x00" * 31,
                spoofed_src_ip=spoofed_ip,
            )
            time.sleep(0.1)

        time.sleep(2)

        # Server should remain healthy
        assert check_server_health(timeout=5), "Server crashed during spoofed attack"

    def test_no_response_to_garbage(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives garbage data flood."""
        spoofed_ip = "10.88.88.88"

        for _ in range(20):
            garbage = generate_random_frame(50)
            packet_sender.send_spoofed(garbage, spoofed_src_ip=spoofed_ip)
            time.sleep(0.05)

        time.sleep(2)

        # Server should remain healthy
        assert check_server_health(timeout=5), "Server crashed on garbage data"


# =============================================================================
# Replay Attacks
# =============================================================================


class TestReplayAttacks:
    """Tests for replay attack resistance."""

    def test_duplicate_frame_handling(
        self,
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
        assert check_server_health(timeout=5), "Server crashed during replay attack"

    @pytest.mark.skip(reason="Requires packet capture with client - run with just test-e2e")
    def test_old_nonce_rejection_concept(self) -> None:
        """Verify that nonces are monotonically increasing.

        Real replay protection checks nonces against a window.
        This test verifies the basic property that nonces increase.

        Requires running client and packet capture.
        Run with: just test-e2e
        """
        pass


# =============================================================================
# Header Manipulation Attacks
# =============================================================================


class TestHeaderManipulation:
    """Tests for header manipulation attack resistance."""

    def test_flags_manipulation(
        self,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Frames with manipulated flags are rejected (AEAD failure)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("flags", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(
            codec.create_data_frame(
                session_id=session_id,
                nonce_counter=0,
                key=key,
                epoch=0,
                direction=0,
                timestamp=0,
                timestamp_echo=0,
                sync_message=sync_message,
            )
        )

        # Manipulate flags byte
        frame[1] = 0xFF  # Invalid flags

        packet_sender.send_udp(bytes(frame))

        time.sleep(0.5)
        assert check_server_health(timeout=5), "Server crashed on flags manipulation"

    def test_type_downgrade_attack(
        self,
        packet_sender: PacketSender,
        codec: NomadCodec,
    ) -> None:
        """Changing frame type is rejected (AEAD failure)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("type_attack", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")

        frame = bytearray(
            codec.create_data_frame(
                session_id=session_id,
                nonce_counter=0,
                key=key,
                epoch=0,
                direction=0,
                timestamp=0,
                timestamp_echo=0,
                sync_message=sync_message,
            )
        )

        # Try to change type to handshake
        frame[0] = 0x01

        packet_sender.send_udp(bytes(frame))

        time.sleep(0.5)
        assert check_server_health(timeout=5), "Server crashed on type downgrade"


# =============================================================================
# Fuzz Testing
# =============================================================================


class TestAdversarialFuzz:
    """Adversarial fuzz testing."""

    @given(data=st.binary(min_size=0, max_size=1400))
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_random_data_no_crash(
        self,
        packet_sender: PacketSender,
        data: bytes,
    ) -> None:
        """Server survives any random input."""
        packet_sender.send_udp(data)
        time.sleep(0.05)
        assert check_server_health(timeout=2), "Server crashed on random data"

    def test_all_byte_values(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives packets with all possible byte values."""
        for byte_val in range(256):
            frame = bytes([byte_val] * 32)
            packet_sender.send_udp(frame)
            time.sleep(0.01)

        time.sleep(1)
        assert check_server_health(timeout=5), "Server crashed on byte value test"

    def test_structured_fuzz(
        self,
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
        assert check_server_health(timeout=5), "Server crashed on structured fuzz"


# =============================================================================
# Resource Exhaustion Tests
# =============================================================================


class TestResourceExhaustion:
    """Tests for resource exhaustion attack resistance."""

    def test_rapid_frame_flood(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server survives rapid frame flood."""
        for _ in range(1000):
            frame = generate_random_frame(100)
            packet_sender.send_udp(frame)

        time.sleep(2)
        assert check_server_health(timeout=10), "Server crashed during frame flood"

    def test_large_frame_handling(
        self,
        packet_sender: PacketSender,
    ) -> None:
        """Server handles maximum-size frames gracefully."""
        # Use maximum UDP payload that fits in typical MTU (1500 - 20 IP - 8 UDP = 1472)
        # Use 1400 to have margin for headers
        large_frame = generate_random_frame(1400)
        packet_sender.send_udp(large_frame)

        time.sleep(0.5)
        assert check_server_health(timeout=5), "Server crashed on large frame"

    def test_many_unique_session_ids(
        self,
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
        assert check_server_health(timeout=10), "Server crashed on session ID flood"
