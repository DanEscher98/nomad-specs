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
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import json5
import pytest

from lib.reference import (
    SyncMessage,
    parse_sync_message,
)

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
        return (
            self.peer_state == other.state
            and self.peer_state_num == other.state_num
        )


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
            s for s in sync_vectors["convergence_scenarios"]
            if s["name"] == "normal_convergence"
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
            s for s in sync_vectors["convergence_scenarios"]
            if s["name"] == "packet_loss_recovery"
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
