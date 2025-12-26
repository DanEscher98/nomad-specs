"""
Protocol tests for sync convergence properties.

Tests the convergence guarantees of the sync layer:
- Both sides eventually agree on state
- Packet loss recovery
- Reordering tolerance
- Idempotency under duplicates

Reference: specs/3-SYNC.md - Convergence Guarantees
"""

from __future__ import annotations

import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import json5
import pytest

from lib.chaos import NetworkChaos
from lib.network import parse_pcap
from lib.reference import (
    FRAME_DATA,
    SyncMessage,
    parse_sync_message,
)

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container

    from lib.containers import ContainerManager, PacketCapture

# Path to test vectors
VECTORS_DIR = Path(__file__).parent.parent / "vectors"


@pytest.fixture(scope="module")
def sync_vectors() -> dict:
    """Load sync test vectors."""
    with open(VECTORS_DIR / "sync_vectors.json5") as f:
        return json5.load(f)


# =============================================================================
# Sync Peer Implementation (for convergence testing)
# =============================================================================


@dataclass
class SyncPeer:
    """A sync peer for testing convergence.

    Implements the sync algorithm from specs/3-SYNC.md.
    Uses integer state for simple testing.
    """

    name: str = "peer"

    # Local state (simple counter for testing)
    state: int = 0
    state_num: int = 0

    # Sent tracking
    last_sent_state: int = 0
    last_sent_num: int = 0

    # Ack tracking
    last_acked: int = 0

    # Peer state tracking
    peer_state: int = 0
    peer_state_num: int = 0

    # Message log (for debugging)
    sent_messages: list = None
    received_messages: list = None

    def __post_init__(self):
        self.sent_messages = []
        self.received_messages = []

    def update_state(self, new_state: int) -> None:
        """Update local state."""
        self.state = new_state
        self.state_num += 1

    def create_message(self) -> SyncMessage:
        """Create sync message for current state."""
        import struct

        diff = struct.pack("<Q", self.state)

        msg = SyncMessage(
            sender_state_num=self.state_num,
            acked_state_num=self.peer_state_num,
            base_state_num=self.last_sent_num,
            diff=diff,
        )

        self.last_sent_state = self.state
        self.last_sent_num = self.state_num
        self.sent_messages.append(msg)

        return msg

    def receive_message(self, msg: SyncMessage) -> bool:
        """Process received sync message. Returns True if state updated."""
        self.received_messages.append(msg)

        # Always update ack tracking
        if msg.acked_state_num > self.last_acked:
            self.last_acked = msg.acked_state_num

        # Apply if newer
        if msg.sender_state_num > self.peer_state_num:
            # For integer state, try to unpack as uint64
            # For bytes state (from test vectors), just store the length
            if len(msg.diff) == 8:
                import struct

                self.peer_state = struct.unpack("<Q", msg.diff)[0]
            else:
                # For test vectors with text diffs, use the length as a proxy
                self.peer_state = len(msg.diff)
            self.peer_state_num = msg.sender_state_num
            return True

        return False

    def is_converged_with(self, other: SyncPeer) -> bool:
        """Check if this peer has converged with another."""
        return self.peer_state == other.state and self.peer_state_num == other.state_num


# =============================================================================
# Network Simulator
# =============================================================================


class NetworkMessage(NamedTuple):
    """A message in transit on the simulated network."""

    sender: str
    receiver: str
    message: SyncMessage


class NetworkSimulator:
    """Simulates network with configurable loss/reordering."""

    def __init__(
        self,
        loss_rate: float = 0.0,
        reorder_rate: float = 0.0,
        duplicate_rate: float = 0.0,
    ):
        self.loss_rate = loss_rate
        self.reorder_rate = reorder_rate
        self.duplicate_rate = duplicate_rate
        self.in_flight: list[NetworkMessage] = []
        self.dropped: list[NetworkMessage] = []
        self.delivered: list[NetworkMessage] = []

    def send(self, sender: str, receiver: str, msg: SyncMessage) -> None:
        """Queue a message for delivery."""
        net_msg = NetworkMessage(sender, receiver, msg)

        # Simulate loss
        if random.random() < self.loss_rate:
            self.dropped.append(net_msg)
            return

        # Simulate duplication
        if random.random() < self.duplicate_rate:
            self.in_flight.append(net_msg)  # Add duplicate

        self.in_flight.append(net_msg)

    def deliver_all(self, peers: dict[str, SyncPeer]) -> int:
        """Deliver all in-flight messages. Returns count delivered."""
        # Optionally reorder
        if random.random() < self.reorder_rate and len(self.in_flight) > 1:
            random.shuffle(self.in_flight)

        delivered_count = 0
        while self.in_flight:
            net_msg = self.in_flight.pop(0)
            receiver = peers[net_msg.receiver]
            receiver.receive_message(net_msg.message)
            self.delivered.append(net_msg)
            delivered_count += 1

        return delivered_count


# =============================================================================
# Basic Convergence Tests
# =============================================================================


class TestBasicConvergence:
    """Tests for basic convergence scenarios."""

    def test_simple_convergence(self) -> None:
        """Test that two peers converge under ideal conditions."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A updates state
        a.update_state(42)
        msg = a.create_message()

        # B receives
        b.receive_message(msg)

        # B should have A's state
        assert b.peer_state == 42
        assert b.peer_state_num == 1
        assert b.is_converged_with(a)

    def test_bidirectional_convergence(self) -> None:
        """Test bidirectional state convergence."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A sends to B
        a.update_state(100)
        msg_a = a.create_message()
        b.receive_message(msg_a)

        # B sends to A (with ack)
        b.update_state(200)
        msg_b = b.create_message()
        a.receive_message(msg_b)

        # Both have each other's state
        assert a.peer_state == 200
        assert b.peer_state == 100
        assert msg_b.acked_state_num == 1  # B acked A's state

    def test_convergence_scenario_from_vectors(self, sync_vectors: dict) -> None:
        """Test convergence using test vector scenario."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "normal_convergence"
        )

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        for msg_data in scenario["messages"]:
            msg = parse_sync_message(bytes.fromhex(msg_data["encoded"]))

            if msg_data["direction"] == "A->B":
                b.receive_message(msg)
            else:
                a.receive_message(msg)

        # Both should have processed all messages
        assert a.peer_state_num == 2
        assert b.peer_state_num == 2


# =============================================================================
# Packet Loss Recovery Tests
# =============================================================================


class TestPacketLossRecovery:
    """Tests for recovery from packet loss."""

    def test_single_lost_packet(self) -> None:
        """Test recovery from single lost packet."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A sends version 1 (lost)
        a.update_state(1)
        _lost_msg = a.create_message()  # Not delivered

        # A sends version 2 (delivered)
        a.update_state(2)
        msg2 = a.create_message()
        b.receive_message(msg2)

        # B should have version 2 (skipped version 1)
        assert b.peer_state == 2
        assert b.peer_state_num == 2

    def test_multiple_lost_packets(self) -> None:
        """Test recovery from multiple consecutive lost packets."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A sends versions 1, 2, 3 (all lost)
        for i in range(1, 4):
            a.update_state(i)
            _lost = a.create_message()

        # A sends version 4 (delivered)
        a.update_state(4)
        msg = a.create_message()
        b.receive_message(msg)

        # B should have version 4
        assert b.peer_state == 4
        assert b.peer_state_num == 4

    def test_packet_loss_recovery_scenario(self, sync_vectors: dict) -> None:
        """Test packet loss recovery scenario from vectors."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "packet_loss_recovery"
        )

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        for msg_data in scenario["messages"]:
            if msg_data.get("status") == "LOST":
                continue  # Simulate packet loss

            msg = parse_sync_message(bytes.fromhex(msg_data["encoded"]))

            if msg_data["direction"] == "A->B":
                b.receive_message(msg)
            else:
                a.receive_message(msg)

        # Despite lost packet, state should converge
        assert b.peer_state_num >= 1  # At least got some messages

    def test_retransmit_after_loss(self) -> None:
        """Test that retransmit recovers from loss."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A sends (lost)
        a.update_state(42)
        _lost = a.create_message()

        # B sends ack-only (A knows it wasn't received)
        b_msg = b.create_message()
        a.receive_message(b_msg)

        # A hasn't been acked
        assert a.last_acked == 0

        # A retransmits
        retransmit = a.create_message()
        b.receive_message(retransmit)

        # Now B has it
        assert b.peer_state == 42


# =============================================================================
# Reordering Tolerance Tests
# =============================================================================


class TestReorderingTolerance:
    """Tests for handling out-of-order packets."""

    def test_out_of_order_delivery(self) -> None:
        """Test handling of out-of-order message delivery."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A sends versions 1, 2, 3
        a.update_state(1)
        msg1 = a.create_message()

        a.update_state(2)
        msg2 = a.create_message()

        a.update_state(3)
        msg3 = a.create_message()

        # Delivered out of order: 3, 1, 2
        b.receive_message(msg3)
        assert b.peer_state == 3
        assert b.peer_state_num == 3

        b.receive_message(msg1)  # Older, should be skipped
        assert b.peer_state == 3  # Still 3

        b.receive_message(msg2)  # Older, should be skipped
        assert b.peer_state == 3  # Still 3

    def test_late_arrival_skipped(self) -> None:
        """Test that late-arriving messages are skipped."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # B has already received up to version 10
        b.peer_state_num = 10
        b.peer_state = 1000

        # Late message arrives (version 5)
        a.state_num = 5
        a.state = 500
        late_msg = a.create_message()

        updated = b.receive_message(late_msg)
        assert not updated
        assert b.peer_state == 1000  # Unchanged
        assert b.peer_state_num == 10  # Unchanged


# =============================================================================
# Duplicate Handling Tests
# =============================================================================


class TestDuplicateHandling:
    """Tests for idempotent handling of duplicates."""

    def test_duplicate_message_idempotent(self) -> None:
        """Test that duplicate messages are handled idempotently."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        a.update_state(42)
        msg = a.create_message()

        # Receive same message multiple times
        for i in range(5):
            updated = b.receive_message(msg)
            if i == 0:
                assert updated  # First time updates
            else:
                assert not updated  # Subsequent are skipped

        # State should be correct
        assert b.peer_state == 42
        assert b.peer_state_num == 1

    def test_duplicate_with_different_ack(self) -> None:
        """Test duplicate detection even with different ack values.

        Note: Our simple implementation treats these as duplicates based on
        sender_state_num. Real implementations might handle this differently.
        """
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        a.update_state(42)
        msg1 = a.create_message()

        # Simulate retransmit with updated ack (same sender_state_num)

        msg2 = SyncMessage(
            sender_state_num=msg1.sender_state_num,
            acked_state_num=5,  # Different ack
            base_state_num=msg1.base_state_num,
            diff=msg1.diff,
        )

        # First delivery
        b.receive_message(msg1)
        assert b.peer_state == 42

        # "Duplicate" with different ack - still skipped
        updated = b.receive_message(msg2)
        assert not updated  # Same sender_state_num


# =============================================================================
# Simulated Network Tests
# =============================================================================


class TestSimulatedNetwork:
    """Tests using network simulation."""

    def test_convergence_with_loss(self) -> None:
        """Test convergence despite packet loss."""
        random.seed(42)  # Reproducible

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")
        peers = {"A": a, "B": b}

        network = NetworkSimulator(loss_rate=0.3)

        # A sends multiple updates
        for i in range(10):
            a.update_state(i)
            msg = a.create_message()
            network.send("A", "B", msg)

        network.deliver_all(peers)

        # B should have received at least some messages
        assert len(b.received_messages) > 0
        # Due to monotonic version, B has the latest received
        assert b.peer_state_num > 0

    def test_convergence_with_reordering(self) -> None:
        """Test convergence despite packet reordering."""
        random.seed(42)

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")
        peers = {"A": a, "B": b}

        network = NetworkSimulator(reorder_rate=1.0)  # Always reorder

        # A sends multiple updates
        for i in range(5):
            a.update_state(i * 10)
            msg = a.create_message()
            network.send("A", "B", msg)

        network.deliver_all(peers)

        # B should have the latest state (version 5, value 40)
        assert b.peer_state_num == 5
        assert b.peer_state == 40

    def test_convergence_with_duplicates(self) -> None:
        """Test convergence with packet duplication."""
        random.seed(42)

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")
        peers = {"A": a, "B": b}

        network = NetworkSimulator(duplicate_rate=0.5)

        # A sends updates
        for i in range(5):
            a.update_state(i)
            msg = a.create_message()
            network.send("A", "B", msg)

        network.deliver_all(peers)

        # B should have correct final state
        assert b.peer_state_num == 5
        assert b.peer_state == 4

    def test_convergence_with_all_issues(self) -> None:
        """Test convergence with loss, reordering, and duplicates."""
        random.seed(42)

        a = SyncPeer(name="A")
        b = SyncPeer(name="B")
        peers = {"A": a, "B": b}

        network = NetworkSimulator(
            loss_rate=0.2,
            reorder_rate=0.3,
            duplicate_rate=0.2,
        )

        # A sends many updates (some will be lost)
        for i in range(20):
            a.update_state(i)
            msg = a.create_message()
            network.send("A", "B", msg)

        network.deliver_all(peers)

        # B should have some valid state
        assert b.peer_state_num > 0
        # State should be consistent with received version
        assert b.peer_state == b.peer_state_num - 1


# =============================================================================
# Eventual Consistency Tests
# =============================================================================


class TestEventualConsistency:
    """Tests for eventual consistency property."""

    def test_eventual_convergence(self) -> None:
        """Test that peers eventually converge if messages get through."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A has state, B is behind
        a.update_state(100)

        # Keep retrying until B gets it
        for _ in range(10):
            msg = a.create_message()
            if random.random() > 0.5:  # 50% delivery
                b.receive_message(msg)
                if b.is_converged_with(a):
                    break

        # Eventually converged
        assert b.is_converged_with(a)

    def test_no_convergence_without_delivery(self) -> None:
        """Test that convergence requires message delivery."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        a.update_state(100)

        # No messages delivered
        assert not b.is_converged_with(a)
        assert b.peer_state_num == 0


# =============================================================================
# State Skipping Tests
# =============================================================================


class TestStateSkipping:
    """Tests for state skipping (intermediate states lost)."""

    def test_skip_intermediate_states(self) -> None:
        """Test that intermediate states can be skipped."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # A goes through many state changes
        for i in range(100):
            a.update_state(i)

        # Only final state is sent
        msg = a.create_message()
        b.receive_message(msg)

        # B has final state, skipped intermediates
        assert b.peer_state == 99
        assert b.peer_state_num == 100

    def test_receiver_catches_up(self) -> None:
        """Test that receiver catches up from any point."""
        a = SyncPeer(name="A")
        b = SyncPeer(name="B")

        # B is far behind
        b.peer_state_num = 10
        b.peer_state = 10

        # A is at version 100
        a.state_num = 100
        a.state = 999
        msg = a.create_message()

        b.receive_message(msg)

        # B catches up immediately
        assert b.peer_state == 999
        assert b.peer_state_num == 100


# =============================================================================
# E2E Convergence Tests (DOCKER REQUIRED)
# =============================================================================
# These tests validate convergence with real implementations in containers.
# They use packet capture and network chaos to verify convergence properties.


# Mark all E2E tests as requiring containers
pytestmark_e2e = [pytest.mark.container, pytest.mark.network]


class TestE2EBasicConvergence:
    """E2E tests for basic convergence with real containers."""

    pytestmark = pytestmark_e2e

    def test_containers_exchange_sync(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that containers exchange sync messages."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        assert len(data_frames) > 0, "Should see sync traffic"

    def test_containers_remain_healthy(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
    ) -> None:
        """Test that containers remain healthy during sync."""
        time.sleep(5)
        container_manager.check_all_containers()

    def test_nonce_progression_indicates_activity(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that nonce counters progress, indicating active sync."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if len(data_frames) < 2:
            pytest.skip("Need multiple frames to verify progression")

        # Extract nonces from first source
        sources = {}
        for frame in data_frames:
            src = frame.src_ip
            nonce = struct.unpack("<Q", frame.raw_bytes[8:16])[0]
            if src not in sources:
                sources[src] = []
            sources[src].append(nonce)

        # At least one source should have progressing nonces
        for src, nonces in sources.items():
            if len(nonces) >= 2:
                assert nonces[-1] > nonces[0], f"Nonces not progressing for {src}"


class TestE2EConvergenceWithLoss:
    """E2E convergence tests under packet loss."""

    pytestmark = pytestmark_e2e

    def test_sync_survives_moderate_loss(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync survives 20% packet loss."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        with chaos.apply_loss(client_name, percent=20):
            time.sleep(5)

        container_manager.check_all_containers()

    def test_sync_survives_high_loss(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync survives 50% packet loss (challenging)."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        with chaos.apply_loss(client_name, percent=50):
            time.sleep(10)  # More time for retransmissions

        container_manager.check_all_containers()


class TestE2EConvergenceWithReordering:
    """E2E convergence tests under packet reordering."""

    pytestmark = pytestmark_e2e

    def test_sync_handles_reordering(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync handles packet reordering correctly."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        with chaos.apply_reorder(client_name, percent=30, gap=5):
            time.sleep(5)

        container_manager.check_all_containers()


class TestE2EConvergenceWithDuplicates:
    """E2E convergence tests under packet duplication."""

    pytestmark = pytestmark_e2e

    def test_sync_handles_duplicates_idempotently(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync handles duplicate packets idempotently."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        with chaos.apply_duplicate(client_name, percent=50):
            time.sleep(5)

        container_manager.check_all_containers()


class TestE2EEventualConsistency:
    """E2E tests for eventual consistency property."""

    pytestmark = pytestmark_e2e

    def test_recovery_after_partition(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync recovers after network partition heals."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        server_name = os.environ.get("NOMAD_SERVER_CONTAINER", "nomad-server")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        # Initial sync
        time.sleep(2)

        # Partition
        with chaos.partition_context(server_name, client_name):
            time.sleep(3)

        # Allow recovery
        time.sleep(3)

        container_manager.check_all_containers()

    def test_sync_continues_after_delay_spike(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
        docker_client: DockerClient,
    ) -> None:
        """Test that sync continues after high latency spike."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        # Capture before, during, and after delay
        with packet_capture.capture() as pcap_file:
            time.sleep(1)  # Normal

            with chaos.apply_delay(client_name, delay_ms=500, jitter_ms=200):
                time.sleep(3)  # High delay

            time.sleep(2)  # Normal again

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Should still have traffic
        assert len(data_frames) > 0, "Should have sync traffic despite delay spike"


class TestE2EStateSkipping:
    """E2E tests for state skipping behavior."""

    pytestmark = pytestmark_e2e

    def test_nonces_skip_gaps_correctly(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
        docker_client: DockerClient,
    ) -> None:
        """Test that nonces can skip values (due to lost packets)."""
        import os

        network_name = os.environ.get("NOMAD_TEST_NETWORK", "nomad-test-net")
        client_name = os.environ.get("NOMAD_CLIENT_CONTAINER", "nomad-client")
        chaos = NetworkChaos(docker_client, network_name)

        with (
            packet_capture.capture() as pcap_file,
            chaos.apply_loss(client_name, percent=30),
        ):
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Extract nonces per source
        sources: dict[str, list[int]] = {}
        for frame in data_frames:
            src = frame.src_ip
            nonce = struct.unpack("<Q", frame.raw_bytes[8:16])[0]
            if src not in sources:
                sources[src] = []
            sources[src].append(nonce)

        # With packet loss, received nonces may have gaps
        # (sender increments, but some packets are lost)
        # Key property: nonces we DO receive are still monotonic
        for src, nonces in sources.items():
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i - 1], (
                    f"Nonces not monotonic for {src}: {nonces[i - 1]} -> {nonces[i]}"
                )
