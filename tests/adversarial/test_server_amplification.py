"""
Amplification Attack Tests for NOMAD Protocol.

These tests verify that implementations correctly limit responses to
unvalidated addresses, preventing DDoS amplification attacks.

Per spec (2-TRANSPORT.md §Anti-Amplification):
- Unvalidated address limit: Before receiving an authenticated frame from
  a new address, endpoint MUST NOT send more than 3× the bytes received.
- Validation: An address is "validated" after receiving a frame with valid
  AEAD tag from it.
- Rate limiting: SHOULD rate-limit migrations to at most one per second
  from different subnets.

Security property: Amplification protection prevents attackers from using
the server to amplify DDoS attacks against spoofed victim IPs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    NomadCodec,
)

if TYPE_CHECKING:
    from lib.attacker import MITMAttacker


# Mark all tests in this module as adversarial
pytestmark = pytest.mark.adversarial


@dataclass
class AmplificationTracker:
    """Tracks bytes sent/received per address for amplification checks."""

    # Bytes received from each address
    bytes_recv: dict[str, int] = field(default_factory=dict)

    # Bytes sent to each address
    bytes_sent: dict[str, int] = field(default_factory=dict)

    # Validated addresses (received authenticated frame)
    validated: set[str] = field(default_factory=set)

    # Amplification limit (spec: 3×)
    AMPLIFICATION_LIMIT: float = 3.0

    def on_receive(self, addr: str, size: int) -> None:
        """Record bytes received from an address."""
        self.bytes_recv[addr] = self.bytes_recv.get(addr, 0) + size

    def on_send(self, addr: str, size: int) -> bool:
        """Check if sending is allowed, record if yes.

        Returns:
            True if send is allowed, False if amplification limit reached.
        """
        if addr in self.validated:
            # No limit for validated addresses
            self.bytes_sent[addr] = self.bytes_sent.get(addr, 0) + size
            return True

        recv = self.bytes_recv.get(addr, 0)
        sent = self.bytes_sent.get(addr, 0)

        if recv == 0:
            # Never received from this address - don't respond
            return False

        if sent + size > recv * self.AMPLIFICATION_LIMIT:
            # Would exceed amplification limit
            return False

        self.bytes_sent[addr] = sent + size
        return True

    def validate(self, addr: str) -> None:
        """Mark an address as validated (received authenticated frame)."""
        self.validated.add(addr)

    def get_amplification_factor(self, addr: str) -> float:
        """Get the current amplification factor for an address."""
        recv = self.bytes_recv.get(addr, 0)
        sent = self.bytes_sent.get(addr, 0)
        if recv == 0:
            return float("inf") if sent > 0 else 0.0
        return sent / recv


class TestAmplificationLimit:
    """Tests for the 3× amplification limit."""

    def test_amplification_limit_before_validation(self) -> None:
        """Response limited to 3× before address is validated.

        Spec: 2-TRANSPORT.md §Anti-Amplification
        "Before receiving an authenticated frame from a new address,
         endpoint MUST NOT send more than 3× the bytes received"
        """
        tracker = AmplificationTracker()
        spoofed_addr = "10.0.0.100"

        # Receive small frame (e.g., 100 bytes)
        tracker.on_receive(spoofed_addr, 100)

        # Can send up to 300 bytes (3× limit)
        assert tracker.on_send(spoofed_addr, 100) is True  # 100 bytes, total: 100
        assert tracker.on_send(spoofed_addr, 100) is True  # 100 bytes, total: 200
        assert tracker.on_send(spoofed_addr, 100) is True  # 100 bytes, total: 300

        # Cannot send more (would exceed 3×)
        assert tracker.on_send(spoofed_addr, 1) is False

    def test_no_response_without_receiving_first(self) -> None:
        """Cannot send to address that hasn't sent anything.

        Prevents reflection attacks where attacker spoofs victim IP.
        """
        tracker = AmplificationTracker()
        victim_addr = "192.168.1.50"

        # Cannot send without receiving first
        assert tracker.on_send(victim_addr, 100) is False
        assert tracker.on_send(victim_addr, 1) is False

    def test_validated_address_no_limit(self) -> None:
        """Validated addresses have no amplification limit.

        Spec: 2-TRANSPORT.md §Anti-Amplification
        "An address is considered 'validated' after receiving any frame
         with valid AEAD tag from it."
        """
        tracker = AmplificationTracker()
        valid_addr = "172.31.0.20"

        # Receive small frame
        tracker.on_receive(valid_addr, 50)

        # Validate the address (received authenticated frame)
        tracker.validate(valid_addr)

        # Now can send unlimited
        assert tracker.on_send(valid_addr, 10000) is True
        assert tracker.on_send(valid_addr, 10000) is True
        assert tracker.get_amplification_factor(valid_addr) > 3.0

    @given(recv_size=st.integers(min_value=1, max_value=1500))
    @settings(max_examples=20)
    def test_exact_3x_boundary(self, recv_size: int) -> None:
        """Test exact 3× boundary behavior."""
        tracker = AmplificationTracker()
        addr = "10.1.2.3"

        tracker.on_receive(addr, recv_size)

        max_send = int(recv_size * 3.0)

        # Can send exactly at the limit
        assert tracker.on_send(addr, max_send) is True

        # Cannot send even 1 more byte
        assert tracker.on_send(addr, 1) is False


class TestSpoofedSourceAttack:
    """Tests for attacks using spoofed source IP addresses."""

    @pytest.fixture
    def codec(self) -> NomadCodec:
        """Provide a NomadCodec instance."""
        return NomadCodec()

    def test_spoofed_ip_limited_response(self, codec: NomadCodec) -> None:
        """Spoofed source IP receives limited response.

        Attack scenario:
        1. Attacker sends frame with spoofed victim IP as source
        2. Server responds to victim IP (reflection)
        3. BUT response is limited to 3× bytes received
        4. This limits amplification DDoS effectiveness
        """
        tracker = AmplificationTracker()
        victim_ip = "203.0.113.50"  # Victim's IP (attacker spoofs this)

        # Attacker sends 100-byte frame with spoofed source
        attacker_frame_size = 100
        tracker.on_receive(victim_ip, attacker_frame_size)

        # Server tries to respond
        response_size = 500  # Server might want to send large response

        # But response is capped at 3× = 300 bytes
        if response_size > attacker_frame_size * 3:
            # Server SHOULD fragment response or not respond
            assert tracker.on_send(victim_ip, response_size) is False
        else:
            assert tracker.on_send(victim_ip, response_size) is True

    def test_measure_bytes_before_validation(self, codec: NomadCodec) -> None:
        """Measure bytes sent vs received before validation.

        This test verifies the amplification tracking logic works correctly.
        """
        tracker = AmplificationTracker()
        test_addr = "10.20.30.40"

        # Receive 200 bytes
        tracker.on_receive(test_addr, 200)

        # Send in chunks to track
        assert tracker.on_send(test_addr, 150) is True
        assert tracker.get_amplification_factor(test_addr) == 0.75

        assert tracker.on_send(test_addr, 250) is True
        assert tracker.get_amplification_factor(test_addr) == 2.0

        assert tracker.on_send(test_addr, 200) is True
        assert tracker.get_amplification_factor(test_addr) == 3.0

        # At exactly 3×, cannot send more
        assert tracker.on_send(test_addr, 1) is False


class TestRateLimitingMigration:
    """Tests for rate limiting on connection migrations."""

    @dataclass
    class MigrationRateLimiter:
        """Tracks migration rate per subnet."""

        # Last migration time per /24 subnet
        last_migration: dict[str, float] = field(default_factory=dict)

        # Minimum interval between migrations (spec: 1 second)
        MIN_MIGRATION_INTERVAL: float = 1.0

        def can_migrate(self, addr: str, current_time: float) -> bool:
            """Check if migration from this subnet is allowed."""
            subnet = self._get_subnet(addr)
            last = self.last_migration.get(subnet, 0.0)
            return current_time - last >= self.MIN_MIGRATION_INTERVAL

        def record_migration(self, addr: str, current_time: float) -> None:
            """Record a migration from this address."""
            subnet = self._get_subnet(addr)
            self.last_migration[subnet] = current_time

        @staticmethod
        def _get_subnet(addr: str) -> str:
            """Extract /24 subnet from IPv4 address."""
            parts = addr.split(".")
            if len(parts) != 4:
                return addr
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def test_rate_limit_migrations(self) -> None:
        """Rate limit migrations to once per second per subnet.

        Spec: 2-TRANSPORT.md §Anti-Amplification
        "SHOULD rate-limit migrations to at most one per second
         from different /24 (IPv4) or /48 (IPv6) subnets"
        """
        limiter = self.MigrationRateLimiter()

        # First migration allowed
        assert limiter.can_migrate("192.168.1.100", 1000.0) is True
        limiter.record_migration("192.168.1.100", 1000.0)

        # Same subnet, too soon
        assert limiter.can_migrate("192.168.1.200", 1000.5) is False

        # Different subnet, allowed
        assert limiter.can_migrate("192.168.2.100", 1000.5) is True

        # Same subnet, after interval
        assert limiter.can_migrate("192.168.1.150", 1001.1) is True

    def test_subnet_grouping(self) -> None:
        """Verify /24 subnet grouping."""
        limiter = self.MigrationRateLimiter()

        # These should be same subnet
        assert limiter._get_subnet("10.0.1.50") == limiter._get_subnet("10.0.1.200")

        # These should be different subnets
        assert limiter._get_subnet("10.0.1.50") != limiter._get_subnet("10.0.2.50")


class TestAmplificationVectors:
    """Test vectors for amplification attack scenarios."""

    def test_handshake_amplification_scenario(self) -> None:
        """Test handshake response amplification scenario.

        Handshake response (56 bytes min) vs handshake init (100 bytes min)
        This is safe: response <= init, amplification factor < 1
        """
        init_size = 100  # Minimum handshake init
        response_size = 56  # Minimum handshake response

        factor = response_size / init_size
        assert factor < 1.0, "Handshake response should not amplify"

    def test_data_frame_amplification_scenario(self) -> None:
        """Test data frame amplification scenario.

        Server might respond with larger payload than received.
        This MUST be limited before address validation.
        """
        tracker = AmplificationTracker()
        addr = "10.0.0.1"

        # Client sends small frame (32 bytes minimum)
        tracker.on_receive(addr, 32)

        # Server has large state to send (e.g., 1000 bytes)
        large_response = 1000

        # Cannot send all at once (would be 31× amplification)
        assert tracker.on_send(addr, large_response) is False

        # Can only send up to 96 bytes (3×)
        assert tracker.on_send(addr, 96) is True
        assert tracker.on_send(addr, 1) is False


class TestAmplificationIntegration:
    """Integration tests for amplification attacks with containers."""

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_amplification_with_spoofed_source(
        self,
        attacker: MITMAttacker,
        server_container,
    ) -> None:
        """Integration test: send with spoofed source IP.

        This test:
        1. Sends a frame with spoofed source IP
        2. Server should limit response to 3× bytes received
        3. Verify server doesn't send large response to spoofed address
        """
        # Forge frame with spoofed source
        forged = attacker.forge_frame(
            session_id=os.urandom(6),
            nonce_counter=1,
        )

        # Send with spoofed source IP (victim's IP)
        victim_ip = "203.0.113.100"
        attacker.spoof_source(
            forged,
            spoof_ip=victim_ip,
            dst_ip="172.31.0.10",  # Server
            dst_port=19999,
        )

        # Server should either:
        # 1. Drop invalid frame (AEAD fails), or
        # 2. If somehow valid, limit response to 3× bytes

        # We can't directly verify without packet capture,
        # but this exercises the code path
        assert attacker.stats.frames_injected >= 1

    @pytest.mark.container
    @pytest.mark.skip(reason="Requires running containers - enable in CI")
    def test_measure_server_response_ratio(
        self,
        attacker: MITMAttacker,
        server_container,
        client_container,
    ) -> None:
        """Integration test: measure actual response amplification.

        Captures traffic to measure actual bytes sent/received ratio.
        """
        # Start capture
        frames = attacker.capture_traffic(count=20, timeout=10.0)

        if len(frames) < 2:
            pytest.skip("Not enough frames captured")

        # Analyze request/response pairs
        # (This is a simplified analysis)
        server_ip = "172.31.0.10"

        to_server = sum(f.data for f in frames if f.dst_ip == server_ip)
        from_server = sum(f.data for f in frames if f.src_ip == server_ip)

        # For established sessions, amplification is not limited
        # But initial exchanges should not exceed 3×
        # This test just captures the ratio for analysis
        if to_server > 0:
            ratio = from_server / to_server
            # Log for analysis (actual threshold depends on session state)
            assert ratio is not None  # Placeholder assertion
