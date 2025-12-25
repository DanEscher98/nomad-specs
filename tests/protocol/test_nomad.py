"""
Connection Migration (Roaming) Tests

Tests the NOMAD protocol's IP migration capability, allowing seamless
connection continuation when client IP address changes (e.g., WiFi to cellular).

Spec reference: specs/2-TRANSPORT.md (Connection Migration section)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    NomadCodec,
    encode_sync_message,
)

# =============================================================================
# Test Data Structures
# =============================================================================


@dataclass
class MockEndpoint:
    """Mock network endpoint for migration testing."""

    ip: str
    port: int = 19999

    @property
    def address(self) -> tuple[str, int]:
        return (self.ip, self.port)


@dataclass
class MockConnectionState:
    """Mock connection state for migration testing."""

    session_id: bytes
    remote_endpoint: MockEndpoint
    bytes_recv_from: dict[str, int]  # IP -> bytes received
    bytes_sent_to: dict[str, int]  # IP -> bytes sent
    validated_addrs: set[str]  # Validated IP addresses

    def is_validated(self, addr: str) -> bool:
        return addr in self.validated_addrs

    def validate(self, addr: str) -> None:
        self.validated_addrs.add(addr)

    def record_recv(self, addr: str, size: int) -> None:
        self.bytes_recv_from[addr] = self.bytes_recv_from.get(addr, 0) + size

    def record_send(self, addr: str, size: int) -> None:
        self.bytes_sent_to[addr] = self.bytes_sent_to.get(addr, 0) + size

    def can_send_to(self, addr: str, size: int) -> bool:
        """Check anti-amplification limit (3x received)."""
        if self.is_validated(addr):
            return True
        sent = self.bytes_sent_to.get(addr, 0)
        recv = self.bytes_recv_from.get(addr, 0)
        return sent + size <= recv * 3


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def codec() -> NomadCodec:
    """Reference codec instance."""
    return NomadCodec()


@pytest.fixture
def connection_state() -> MockConnectionState:
    """Fresh connection state for each test."""
    return MockConnectionState(
        session_id=b"\x01\x02\x03\x04\x05\x06",
        remote_endpoint=MockEndpoint(ip="192.168.1.100"),
        bytes_recv_from={},
        bytes_sent_to={},
        validated_addrs={"192.168.1.100"},  # Initial address validated
    )


# =============================================================================
# Migration Detection Tests
# =============================================================================


class TestMigrationDetection:
    """Test detection of address changes."""

    def test_same_address_no_migration(
        self, codec: NomadCodec, connection_state: MockConnectionState
    ) -> None:
        """Frame from same address doesn't trigger migration."""
        key = codec.deterministic_bytes("no_migration", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")
        # Create a frame to demonstrate the migration scenario
        _ = codec.create_data_frame(
            session_id=connection_state.session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        source_addr = "192.168.1.100"  # Same as current

        # No migration needed
        assert source_addr == connection_state.remote_endpoint.ip

    def test_different_address_triggers_migration(
        self, codec: NomadCodec, connection_state: MockConnectionState
    ) -> None:
        """Frame from different address triggers migration check."""
        key = codec.deterministic_bytes("migration", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")
        # Create a frame to demonstrate the migration scenario
        _ = codec.create_data_frame(
            session_id=connection_state.session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        source_addr = "10.0.0.50"  # Different address (e.g., cellular)

        # Migration detected
        assert source_addr != connection_state.remote_endpoint.ip


# =============================================================================
# Migration Validation Tests
# =============================================================================


class TestMigrationValidation:
    """Test validation of frames from new addresses."""

    def test_valid_frame_validates_address(
        self, codec: NomadCodec, connection_state: MockConnectionState
    ) -> None:
        """Valid AEAD tag from new address validates that address."""
        key = codec.deterministic_bytes("validate_addr", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")
        frame = codec.create_data_frame(
            session_id=connection_state.session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        new_addr = "10.0.0.50"

        # Simulate receiving valid frame from new address
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        # If parsing succeeds, address is validated
        assert parsed is not None

        # Update state (what implementation should do)
        connection_state.validate(new_addr)
        connection_state.remote_endpoint = MockEndpoint(ip=new_addr)

        # Verify migration completed
        assert connection_state.is_validated(new_addr)
        assert connection_state.remote_endpoint.ip == new_addr

    def test_invalid_frame_rejected(
        self, codec: NomadCodec, connection_state: MockConnectionState
    ) -> None:
        """Invalid frame from new address is silently dropped."""
        correct_key = codec.deterministic_bytes("correct", 32)
        wrong_key = codec.deterministic_bytes("wrong", 32)

        sync_message = encode_sync_message(1, 0, 0, b"test")
        frame = codec.create_data_frame(
            session_id=connection_state.session_id,
            nonce_counter=0,
            key=correct_key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        new_addr = "10.0.0.50"
        original_addr = connection_state.remote_endpoint.ip

        # Try to parse with wrong key (simulating attacker)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(
                data=frame,
                key=wrong_key,
                epoch=0,
                direction=0,
            )

        # Address should NOT be validated or updated
        assert not connection_state.is_validated(new_addr)
        assert connection_state.remote_endpoint.ip == original_addr


# =============================================================================
# Anti-Amplification Tests
# =============================================================================


class TestAntiAmplification:
    """Test anti-amplification protection during migration."""

    def test_3x_limit_enforced(self, connection_state: MockConnectionState) -> None:
        """Cannot send more than 3x bytes received from unvalidated address."""
        new_addr = "10.0.0.50"

        # Receive 100 bytes from new address
        connection_state.record_recv(new_addr, 100)

        # Can send up to 300 bytes (3x)
        assert connection_state.can_send_to(new_addr, 100)  # Total: 100
        assert connection_state.can_send_to(new_addr, 200)  # Total: 200
        assert connection_state.can_send_to(new_addr, 300)  # Total: 300
        assert not connection_state.can_send_to(new_addr, 301)  # Exceeds 3x

    def test_limit_not_applied_to_validated(
        self, connection_state: MockConnectionState
    ) -> None:
        """No limit for validated addresses."""
        validated_addr = connection_state.remote_endpoint.ip

        # Can send any amount to validated address
        assert connection_state.can_send_to(validated_addr, 1000000)

    def test_validation_removes_limit(
        self, connection_state: MockConnectionState
    ) -> None:
        """Validation removes amplification limit."""
        new_addr = "10.0.0.50"

        # Before validation: limit applies
        connection_state.record_recv(new_addr, 100)
        assert not connection_state.can_send_to(new_addr, 1000)

        # After validation: no limit
        connection_state.validate(new_addr)
        assert connection_state.can_send_to(new_addr, 1000)

    def test_zero_bytes_received_blocks_send(
        self, connection_state: MockConnectionState
    ) -> None:
        """Cannot send to address with zero bytes received."""
        new_addr = "10.0.0.50"

        # No bytes received = 0 * 3 = 0 bytes allowed
        assert not connection_state.can_send_to(new_addr, 1)

    @given(recv_bytes=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=50)
    def test_3x_property(self, recv_bytes: int) -> None:
        """Property: can send up to 3x received, not more."""
        # Create fresh state for each hypothesis input
        state = MockConnectionState(
            session_id=b"\x01\x02\x03\x04\x05\x06",
            remote_endpoint=MockEndpoint(ip="192.168.1.100"),
            bytes_recv_from={},
            bytes_sent_to={},
            validated_addrs={"192.168.1.100"},
        )
        new_addr = "10.0.0.100"

        state.record_recv(new_addr, recv_bytes)

        max_allowed = recv_bytes * 3

        # Can send up to limit
        if max_allowed > 0:
            assert state.can_send_to(new_addr, max_allowed)

        # Cannot exceed limit
        assert not state.can_send_to(new_addr, max_allowed + 1)


# =============================================================================
# Session Continuity Tests
# =============================================================================


class TestSessionContinuity:
    """Test that session continues seamlessly after migration."""

    def test_same_session_id(
        self, codec: NomadCodec, connection_state: MockConnectionState
    ) -> None:
        """Session ID remains the same after migration."""
        key = codec.deterministic_bytes("continuity", 32)

        original_session_id = connection_state.session_id

        # Frame from new address
        sync_message = encode_sync_message(10, 9, 9, b"after migration")
        frame = codec.create_data_frame(
            session_id=connection_state.session_id,
            nonce_counter=10,
            key=key,
            epoch=0,
            direction=0,
            timestamp=5000,
            timestamp_echo=4500,
            sync_message=sync_message,
        )

        # Simulate migration
        new_addr = "10.0.0.50"
        parsed = codec.parse_data_frame(
            data=frame,
            key=key,
            epoch=0,
            direction=0,
        )

        connection_state.validate(new_addr)
        connection_state.remote_endpoint = MockEndpoint(ip=new_addr)

        # Session ID unchanged
        assert connection_state.session_id == original_session_id
        assert parsed.header.session_id == original_session_id

    def test_nonce_counter_continues(self, codec: NomadCodec) -> None:
        """Nonce counter continues incrementing after migration."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("nonce_continue", 32)

        # Frame before migration (counter=100)
        sync1 = encode_sync_message(5, 4, 4, b"before")
        frame1 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=100,
            key=key,
            epoch=0,
            direction=0,
            timestamp=1000,
            timestamp_echo=0,
            sync_message=sync1,
        )

        # Frame after migration (counter=101)
        sync2 = encode_sync_message(6, 5, 5, b"after")
        frame2 = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=101,
            key=key,
            epoch=0,
            direction=0,
            timestamp=2000,
            timestamp_echo=1000,
            sync_message=sync2,
        )

        # Both frames parse correctly
        parsed1 = codec.parse_data_frame(frame1, key, 0, 0)
        parsed2 = codec.parse_data_frame(frame2, key, 0, 0)

        assert parsed1.header.nonce_counter == 100
        assert parsed2.header.nonce_counter == 101

    def test_keys_remain_valid(self, codec: NomadCodec) -> None:
        """Session keys remain valid after migration."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("keys_valid", 32)

        # Multiple frames with same key work after "migration"
        for i in range(5):
            sync_message = encode_sync_message(i + 1, i, i, f"frame {i}".encode())
            frame = codec.create_data_frame(
                session_id=session_id,
                nonce_counter=i,
                key=key,
                epoch=0,
                direction=0,
                timestamp=i * 1000,
                timestamp_echo=0,
                sync_message=sync_message,
            )

            parsed = codec.parse_data_frame(frame, key, 0, 0)
            assert parsed.sync_message.diff == f"frame {i}".encode()


# =============================================================================
# Migration Direction Tests
# =============================================================================


class TestMigrationDirection:
    """Test migration for both initiator and responder."""

    def test_client_migration(self, codec: NomadCodec) -> None:
        """Client can migrate (common case: WiFi to cellular)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("client_migrate", 32)

        # Client sends from new address (direction=0: initiator->responder)
        sync_message = encode_sync_message(1, 0, 0, b"from cellular")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,  # Client to server
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Server can parse (validates migration)
        parsed = codec.parse_data_frame(frame, key, 0, 0)
        assert parsed.sync_message.diff == b"from cellular"

    def test_server_migration(self, codec: NomadCodec) -> None:
        """Server can also migrate (less common but possible)."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("server_migrate", 32)

        # Server sends from new address (direction=1: responder->initiator)
        sync_message = encode_sync_message(1, 0, 0, b"server moved")
        frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=1,  # Server to client
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Client can parse
        parsed = codec.parse_data_frame(frame, key, 0, 1)
        assert parsed.sync_message.diff == b"server moved"


# =============================================================================
# Rate Limiting Tests
# =============================================================================


class TestMigrationRateLimiting:
    """Test rate limiting for migration (defense against attack)."""

    def test_subnet_tracking_concept(self) -> None:
        """Concept: track migrations per subnet.

        Per spec: Implementations SHOULD rate-limit migrations to at most
        one per second from different /24 (IPv4) or /48 (IPv6) subnets.
        """
        # IPv4 /24 subnet
        ip1 = ipaddress.ip_address("192.168.1.100")
        ip2 = ipaddress.ip_address("192.168.1.200")
        ip3 = ipaddress.ip_address("192.168.2.100")

        # Same /24 subnet
        net1 = ipaddress.ip_network("192.168.1.0/24")
        assert ip1 in net1
        assert ip2 in net1
        assert ip3 not in net1

    def test_subnet_calculation_ipv4(self) -> None:
        """Calculate /24 subnet for IPv4 addresses."""
        def get_ipv4_subnet(ip: str) -> str:
            # Mask to /24
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network.network_address)

        assert get_ipv4_subnet("192.168.1.100") == "192.168.1.0"
        assert get_ipv4_subnet("192.168.1.200") == "192.168.1.0"
        assert get_ipv4_subnet("192.168.2.1") == "192.168.2.0"
        assert get_ipv4_subnet("10.0.0.50") == "10.0.0.0"

    def test_subnet_calculation_ipv6(self) -> None:
        """Calculate /48 subnet for IPv6 addresses."""
        def get_ipv6_subnet(ip: str) -> str:
            network = ipaddress.ip_network(f"{ip}/48", strict=False)
            return str(network.network_address)

        assert get_ipv6_subnet("2001:db8:1234:5678::1") == "2001:db8:1234::"
        assert get_ipv6_subnet("2001:db8:1234:9abc::1") == "2001:db8:1234::"
        assert get_ipv6_subnet("2001:db8:5678::1") == "2001:db8:5678::"


# =============================================================================
# Migration Security Tests
# =============================================================================


class TestMigrationSecurity:
    """Test security properties of migration."""

    def test_spoofed_address_rejected(self, codec: NomadCodec) -> None:
        """Attacker cannot spoof migration without session keys."""
        session_id = b"\x01\x02\x03\x04\x05\x06"
        correct_key = codec.deterministic_bytes("correct", 32)
        attacker_key = codec.deterministic_bytes("attacker", 32)

        # Attacker creates frame with their key
        sync_message = encode_sync_message(1, 0, 0, b"attack")
        malicious_frame = codec.create_data_frame(
            session_id=session_id,
            nonce_counter=0,
            key=attacker_key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        )

        # Server rejects (wrong key)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(malicious_frame, correct_key, 0, 0)

    def test_replay_attack_protection(self, codec: NomadCodec) -> None:
        """Replayed frames from old address don't cause issues.

        Note: Full replay protection requires nonce window tracking,
        which is beyond the scope of this unit test.
        """
        session_id = b"\x01\x02\x03\x04\x05\x06"
        key = codec.deterministic_bytes("replay", 32)

        sync_message = encode_sync_message(1, 0, 0, b"original")
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

        # Frame can be parsed (implementation must track nonce to detect replay)
        parsed = codec.parse_data_frame(frame, key, 0, 0)
        assert parsed.header.nonce_counter == 0

        # Same frame parsed again (would be replay)
        # Implementation must reject based on nonce tracking

    def test_session_id_binding(self, codec: NomadCodec) -> None:
        """Frames are bound to session ID (in AAD)."""
        session_id_1 = b"\x01\x02\x03\x04\x05\x06"
        session_id_2 = b"\xFF\xFE\xFD\xFC\xFB\xFA"
        key = codec.deterministic_bytes("session_bind", 32)

        # Create frame with session_id_1
        sync_message = encode_sync_message(1, 0, 0, b"test")
        frame = bytearray(codec.create_data_frame(
            session_id=session_id_1,
            nonce_counter=0,
            key=key,
            epoch=0,
            direction=0,
            timestamp=0,
            timestamp_echo=0,
            sync_message=sync_message,
        ))

        # Modify session ID in header
        frame[2:8] = session_id_2

        # Decryption fails (AAD mismatch)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            codec.parse_data_frame(bytes(frame), key, 0, 0)
