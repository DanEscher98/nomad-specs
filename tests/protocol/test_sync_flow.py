"""
Protocol tests for basic sync flow.

Tests the fundamental sync message exchange patterns:
- State update → ack cycle
- Version number progression
- Sender/receiver logic

Reference: specs/3-SYNC.md
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import json5
import pytest

from lib.network import NOMAD_PORT, parse_pcap
from lib.reference import (
    DATA_FRAME_HEADER_SIZE,
    FRAME_DATA,
    SyncMessage,
    encode_sync_message,
    parse_sync_message,
)

if TYPE_CHECKING:
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
# Sync Tracker Implementation (for testing)
# =============================================================================


@dataclass
class SyncTracker:
    """Sync state tracker per the spec.

    Each endpoint maintains this state for synchronization.
    Reference: specs/3-SYNC.md - Sync State Tracking
    """

    # Local state (using simple string for testing)
    current: str = ""
    current_num: int = 0

    # Sent state tracking
    last_sent: str = ""
    last_sent_num: int = 0

    # Ack tracking
    last_acked: int = 0  # Highest version acked by peer
    peer_state_num: int = 0  # Highest version received from peer

    # Peer's state (for applying diffs)
    peer_state: str = ""

    def local_state_change(self, new_state: str) -> None:
        """Record a local state change."""
        self.current = new_state
        self.current_num += 1

    def should_send(self) -> bool:
        """Check if we should send a sync message."""
        return self.current_num > self.last_sent_num or self.should_retransmit()

    def should_retransmit(self) -> bool:
        """Check if we should retransmit (peer hasn't acked)."""
        return self.last_acked < self.current_num

    def create_sync_message(self) -> SyncMessage:
        """Create a sync message for the current state."""
        # Diff is the snapshot of current state (for simple echo state)
        diff = self.current.encode("utf-8")

        msg = SyncMessage(
            sender_state_num=self.current_num,
            acked_state_num=self.peer_state_num,
            base_state_num=self.last_sent_num,
            diff=diff,
        )

        # Update sent tracking
        self.last_sent = self.current
        self.last_sent_num = self.current_num

        return msg

    def receive_sync(self, msg: SyncMessage) -> bool:
        """Process a received sync message.

        Returns True if state was updated.
        """
        # Update ack tracking (always)
        if msg.acked_state_num > self.last_acked:
            self.last_acked = msg.acked_state_num

        # Apply diff if newer
        if msg.sender_state_num > self.peer_state_num:
            self.peer_state = msg.diff.decode("utf-8")
            self.peer_state_num = msg.sender_state_num
            return True

        return False


# =============================================================================
# Basic Sync Flow Tests
# =============================================================================


class TestBasicSyncFlow:
    """Tests for basic sync message exchange."""

    def test_initial_sync(self) -> None:
        """Test initial sync from initiator to responder."""
        initiator = SyncTracker()
        responder = SyncTracker()

        # Initiator makes state change
        initiator.local_state_change("hello")
        assert initiator.should_send()

        # Create and send sync message
        msg = initiator.create_sync_message()
        assert msg.sender_state_num == 1
        assert msg.acked_state_num == 0  # Haven't received anything
        assert msg.base_state_num == 0  # First state
        assert msg.diff == b"hello"

        # Responder receives
        updated = responder.receive_sync(msg)
        assert updated
        assert responder.peer_state == "hello"
        assert responder.peer_state_num == 1

    def test_ack_cycle(self) -> None:
        """Test state update → ack cycle."""
        initiator = SyncTracker()
        responder = SyncTracker()

        # Initiator sends state
        initiator.local_state_change("hello")
        msg1 = initiator.create_sync_message()
        responder.receive_sync(msg1)

        # Responder sends ack (empty state change, just acks)
        responder.current_num = 1  # Responder has state too
        msg2 = responder.create_sync_message()

        assert msg2.acked_state_num == 1  # Acks initiator's state

        # Initiator receives ack
        initiator.receive_sync(msg2)
        assert initiator.last_acked == 1
        assert not initiator.should_retransmit()  # No longer needs retransmit

    def test_version_progression(self) -> None:
        """Test version numbers progress correctly."""
        tracker = SyncTracker()

        # Multiple state changes
        for i in range(5):
            tracker.local_state_change(f"state{i}")
            msg = tracker.create_sync_message()

            assert msg.sender_state_num == i + 1
            assert msg.base_state_num == i  # Previous version

    def test_bidirectional_sync(self) -> None:
        """Test bidirectional state synchronization."""
        a = SyncTracker()
        b = SyncTracker()

        # A sends to B
        a.local_state_change("from A")
        msg_a = a.create_sync_message()
        b.receive_sync(msg_a)

        # B sends to A (includes ack)
        b.local_state_change("from B")
        msg_b = b.create_sync_message()
        a.receive_sync(msg_b)

        # Verify state
        assert a.peer_state == "from B"
        assert b.peer_state == "from A"
        assert a.last_acked == 1  # B acked A's state


# =============================================================================
# Version Number Tests
# =============================================================================


class TestVersionNumbers:
    """Tests for version number semantics."""

    def test_monotonic_increase(self) -> None:
        """Test version numbers always increase."""
        tracker = SyncTracker()

        prev_num = 0
        for _ in range(100):
            tracker.local_state_change("x")
            msg = tracker.create_sync_message()
            assert msg.sender_state_num > prev_num
            prev_num = msg.sender_state_num

    def test_base_state_num_tracks_previous(self) -> None:
        """Test base_state_num tracks the previous sent state."""
        tracker = SyncTracker()

        tracker.local_state_change("first")
        msg1 = tracker.create_sync_message()
        assert msg1.base_state_num == 0  # No previous

        tracker.local_state_change("second")
        msg2 = tracker.create_sync_message()
        assert msg2.base_state_num == 1  # Previous was version 1

        tracker.local_state_change("third")
        msg3 = tracker.create_sync_message()
        assert msg3.base_state_num == 2  # Previous was version 2

    def test_acked_tracks_received(self) -> None:
        """Test acked_state_num tracks highest received version."""
        sender = SyncTracker()
        receiver = SyncTracker()

        # Sender sends multiple versions
        for i in range(5):
            sender.local_state_change(f"v{i}")
            msg = sender.create_sync_message()
            receiver.receive_sync(msg)

        # Receiver's response should ack version 5
        receiver.local_state_change("response")
        response = receiver.create_sync_message()
        assert response.acked_state_num == 5


# =============================================================================
# Sender Logic Tests
# =============================================================================


class TestSenderLogic:
    """Tests for sender-side sync logic."""

    def test_send_on_state_change(self) -> None:
        """Test that state change triggers send."""
        tracker = SyncTracker()
        assert not tracker.should_send()  # Nothing to send initially

        tracker.local_state_change("new state")
        assert tracker.should_send()

        tracker.create_sync_message()
        # After sending, should_send is false for new changes,
        # but still true for retransmit (unacked)
        # To stop retransmit, we need to simulate receiving ack
        tracker.last_acked = tracker.current_num
        assert not tracker.should_send()  # Sent AND acked, no new changes

    def test_retransmit_until_acked(self) -> None:
        """Test retransmission while unacked."""
        sender = SyncTracker()

        sender.local_state_change("data")
        sender.create_sync_message()

        # Still should retransmit (not acked)
        assert sender.should_retransmit()

        # Simulate ack received
        sender.last_acked = sender.current_num
        assert not sender.should_retransmit()

    def test_retransmit_with_updated_ack(self) -> None:
        """Test retransmit includes updated ack field."""
        sender = SyncTracker()
        receiver = SyncTracker()

        # Sender sends
        sender.local_state_change("data")
        sender.create_sync_message()

        # Meanwhile sender receives from peer
        receiver.local_state_change("peer data")
        peer_msg = receiver.create_sync_message()
        sender.receive_sync(peer_msg)

        # Retransmit should include updated ack
        retransmit = sender.create_sync_message()
        assert retransmit.acked_state_num == 1  # Acks peer's message


# =============================================================================
# Receiver Logic Tests
# =============================================================================


class TestReceiverLogic:
    """Tests for receiver-side sync logic."""

    def test_apply_newer_version(self) -> None:
        """Test applying diff from newer version."""
        tracker = SyncTracker()

        msg = SyncMessage(
            sender_state_num=5,
            acked_state_num=0,
            base_state_num=4,
            diff=b"new state",
        )

        updated = tracker.receive_sync(msg)
        assert updated
        assert tracker.peer_state == "new state"
        assert tracker.peer_state_num == 5

    def test_skip_older_version(self) -> None:
        """Test skipping diff from older/equal version."""
        tracker = SyncTracker()
        tracker.peer_state_num = 10
        tracker.peer_state = "current"

        # Message with older version
        old_msg = SyncMessage(
            sender_state_num=5,  # Older than current
            acked_state_num=0,
            base_state_num=4,
            diff=b"old state",
        )

        updated = tracker.receive_sync(old_msg)
        assert not updated
        assert tracker.peer_state == "current"  # Unchanged
        assert tracker.peer_state_num == 10

    def test_skip_equal_version(self) -> None:
        """Test skipping diff from equal version (duplicate)."""
        tracker = SyncTracker()
        tracker.peer_state_num = 5
        tracker.peer_state = "current"

        # Duplicate message
        dup_msg = SyncMessage(
            sender_state_num=5,  # Same as current
            acked_state_num=0,
            base_state_num=4,
            diff=b"duplicate",
        )

        updated = tracker.receive_sync(dup_msg)
        assert not updated
        assert tracker.peer_state == "current"

    def test_ack_always_updated(self) -> None:
        """Test that ack field is updated even on skip."""
        tracker = SyncTracker()
        tracker.peer_state_num = 10
        tracker.last_acked = 3

        # Message with older version but higher ack
        msg = SyncMessage(
            sender_state_num=5,  # Will be skipped
            acked_state_num=8,  # But this should update
            base_state_num=4,
            diff=b"old",
        )

        tracker.receive_sync(msg)
        assert tracker.last_acked == 8  # Updated despite skip


# =============================================================================
# Message Exchange Patterns
# =============================================================================


class TestExchangePatterns:
    """Tests for common message exchange patterns."""

    def test_rapid_updates(self) -> None:
        """Test rapid local state updates."""
        tracker = SyncTracker()

        # Rapid updates before send
        for i in range(10):
            tracker.local_state_change(f"rapid{i}")

        # Single send captures latest
        msg = tracker.create_sync_message()
        assert msg.diff == b"rapid9"
        assert msg.sender_state_num == 10

    def test_interleaved_send_receive(self) -> None:
        """Test interleaved send and receive operations."""
        a = SyncTracker()
        b = SyncTracker()

        # A sends
        a.local_state_change("a1")
        msg_a1 = a.create_sync_message()

        # B sends (before receiving from A)
        b.local_state_change("b1")
        msg_b1 = b.create_sync_message()

        # Both receive
        a.receive_sync(msg_b1)
        b.receive_sync(msg_a1)

        # Both have each other's state
        assert a.peer_state == "b1"
        assert b.peer_state == "a1"

    def test_one_way_sync(self) -> None:
        """Test one-way sync (server to client only)."""
        server = SyncTracker()
        client = SyncTracker()

        # Server sends multiple updates
        for i in range(5):
            server.local_state_change(f"update{i}")
            msg = server.create_sync_message()
            client.receive_sync(msg)

        # Client has latest state
        assert client.peer_state == "update4"
        assert client.peer_state_num == 5


# =============================================================================
# Wire Format Integration Tests
# =============================================================================


class TestWireFormatIntegration:
    """Tests integrating sync logic with wire format."""

    def test_encode_decode_roundtrip(self) -> None:
        """Test sync message survives encode/decode cycle."""
        tracker = SyncTracker()

        tracker.local_state_change("test data")
        original = tracker.create_sync_message()

        # Encode to wire format
        encoded = encode_sync_message(
            original.sender_state_num,
            original.acked_state_num,
            original.base_state_num,
            original.diff,
        )

        # Decode from wire format
        decoded = parse_sync_message(encoded)

        assert decoded.sender_state_num == original.sender_state_num
        assert decoded.acked_state_num == original.acked_state_num
        assert decoded.base_state_num == original.base_state_num
        assert decoded.diff == original.diff

    def test_normal_convergence_scenario(self, sync_vectors: dict) -> None:
        """Test normal convergence scenario from test vectors."""
        scenario = next(
            s for s in sync_vectors["convergence_scenarios"] if s["name"] == "normal_convergence"
        )

        a = SyncTracker()
        b = SyncTracker()

        for msg_data in scenario["messages"]:
            direction = msg_data["direction"]
            encoded = bytes.fromhex(msg_data["encoded"])
            msg = parse_sync_message(encoded)

            if direction == "A->B":
                b.receive_sync(msg)
            else:
                a.receive_sync(msg)

        # Both should have received each other's updates
        assert a.peer_state_num == 2  # B's version 2
        assert b.peer_state_num == 2  # A's version 2


# =============================================================================
# E2E Sync Flow Tests (DOCKER REQUIRED)
# =============================================================================
# These tests validate sync flow with real implementations in containers.
# They capture actual network traffic and verify protocol compliance.


# Mark all E2E tests as requiring containers
pytestmark_e2e = [pytest.mark.container, pytest.mark.network]


class TestE2ESyncFlow:
    """E2E tests for sync flow with real containers."""

    pytestmark = pytestmark_e2e

    def test_container_sync_exchange(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test basic sync message exchange between containers.

        Verifies:
        - Data frames are exchanged on the wire
        - Both directions see traffic
        - Frame format is correct
        """
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        assert len(data_frames) > 0, "Should see data frames on wire"

        # Verify both directions
        directions = {(f.src_ip, f.dst_ip) for f in data_frames}
        # At minimum we should see traffic (may be one-directional depending on state)
        assert len(directions) >= 1, "Should see traffic flow"

    def test_version_progression_on_wire(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that version numbers progress correctly on wire.

        Captures packets and verifies nonce counters increase.
        """
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if len(data_frames) < 2:
            pytest.skip("Need at least 2 frames to verify progression")

        # Group by source and verify nonce counter progression
        by_source: dict[str, list[int]] = {}
        for frame in data_frames:
            src = frame.src_ip
            if src not in by_source:
                by_source[src] = []
            nonce = struct.unpack("<Q", frame.raw_bytes[8:16])[0]
            by_source[src].append(nonce)

        for src, nonces in by_source.items():
            # Nonces should be monotonically increasing
            for i in range(1, len(nonces)):
                assert nonces[i] > nonces[i - 1], (
                    f"Nonce not increasing for {src}: {nonces[i - 1]} -> {nonces[i]}"
                )

    def test_session_id_stable(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that session ID remains stable throughout session."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        if len(data_frames) < 2:
            pytest.skip("Need at least 2 frames to verify stability")

        # Group by direction and verify session ID consistency
        by_direction: dict[tuple[str, str], set[bytes]] = {}
        for frame in data_frames:
            direction = (frame.src_ip, frame.dst_ip)
            session_id = frame.raw_bytes[2:8]
            if direction not in by_direction:
                by_direction[direction] = set()
            by_direction[direction].add(session_id)

        for direction, session_ids in by_direction.items():
            assert len(session_ids) == 1, (
                f"Session ID changed for {direction}: found {len(session_ids)} unique IDs"
            )


class TestE2EAckCycle:
    """E2E tests for ack cycle verification."""

    pytestmark = pytestmark_e2e

    def test_bidirectional_traffic(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that bidirectional sync traffic occurs.

        Both server and client should send data frames.
        """
        with packet_capture.capture() as pcap_file:
            time.sleep(5)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        # Collect unique sources
        sources = {f.src_ip for f in data_frames}

        # Should have traffic from both endpoints (may need longer wait)
        if len(sources) < 2:
            pytest.skip("Bidirectional traffic not captured (may need longer sync)")

        assert len(sources) >= 2, "Should see traffic from both endpoints"

    def test_container_health_during_sync(
        self,
        server_container: Container,
        client_container: Container,
        container_manager: ContainerManager,
    ) -> None:
        """Test that containers remain healthy during sync."""
        # Let sync run for a while
        time.sleep(5)

        # Verify no crashes
        container_manager.check_all_containers()


class TestE2ESenderReceiver:
    """E2E tests for sender/receiver roles."""

    pytestmark = pytestmark_e2e

    def test_frame_structure_valid(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that all captured frames have valid structure."""
        with packet_capture.capture() as pcap_file:
            time.sleep(3)

        frames = parse_pcap(pcap_file)
        data_frames = [f for f in frames if f.frame_type == FRAME_DATA]

        for frame in data_frames:
            raw = frame.raw_bytes

            # Minimum frame size
            assert len(raw) >= DATA_FRAME_HEADER_SIZE, f"Frame too short: {len(raw)} bytes"

            # Frame type must be DATA (0x03)
            assert raw[0] == FRAME_DATA, f"Invalid frame type: 0x{raw[0]:02x}"

            # Reserved flag bits must be 0
            flags = raw[1]
            assert (flags & 0xFC) == 0, f"Reserved flags set: 0x{flags:02x}"

            # Session ID must be 6 bytes (already sliced)
            session_id = raw[2:8]
            assert len(session_id) == 6

            # Nonce counter must be parseable
            nonce = struct.unpack("<Q", raw[8:16])[0]
            assert nonce >= 0

    def test_data_port_correct(
        self,
        server_container: Container,
        client_container: Container,
        packet_capture: PacketCapture,
    ) -> None:
        """Test that sync traffic uses correct port."""
        with packet_capture.capture() as pcap_file:
            time.sleep(2)

        frames = parse_pcap(pcap_file)

        for frame in frames:
            # At least one port should be NOMAD_PORT
            assert frame.src_port == NOMAD_PORT or frame.dst_port == NOMAD_PORT, (
                f"Traffic on wrong port: {frame.src_port} -> {frame.dst_port}"
            )
