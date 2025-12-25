"""
Protocol tests for sync layer edge cases.

Tests edge cases and boundary conditions:
- Empty state
- Large state
- Rapid updates
- Maximum version numbers
- Ack-only messages

Reference: specs/3-SYNC.md
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import json5
import pytest

from lib.reference import (
    SYNC_MESSAGE_HEADER_SIZE,
    SyncMessage,
    encode_sync_message,
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
# Peer for Edge Case Testing
# =============================================================================


@dataclass
class EdgeCasePeer:
    """Sync peer for edge case testing."""

    state: bytes = b""
    state_num: int = 0
    last_sent_num: int = 0
    last_acked: int = 0
    peer_state: bytes = b""
    peer_state_num: int = 0

    def update(self, new_state: bytes) -> None:
        self.state = new_state
        self.state_num += 1

    def create_message(self) -> SyncMessage:
        msg = SyncMessage(
            sender_state_num=self.state_num,
            acked_state_num=self.peer_state_num,
            base_state_num=self.last_sent_num,
            diff=self.state,
        )
        self.last_sent_num = self.state_num
        return msg

    def receive(self, msg: SyncMessage) -> bool:
        if msg.acked_state_num > self.last_acked:
            self.last_acked = msg.acked_state_num

        if msg.sender_state_num > self.peer_state_num:
            self.peer_state = msg.diff
            self.peer_state_num = msg.sender_state_num
            return True
        return False


# =============================================================================
# Empty State Tests
# =============================================================================


class TestEmptyState:
    """Tests for empty state handling."""

    def test_initial_empty_state(self) -> None:
        """Test sync with initial empty state."""
        peer = EdgeCasePeer()
        msg = peer.create_message()

        assert msg.sender_state_num == 0
        assert msg.diff == b""

    def test_transition_to_empty(self) -> None:
        """Test transitioning from non-empty to empty state."""
        peer = EdgeCasePeer()

        # Start with content
        peer.update(b"content")
        msg1 = peer.create_message()
        assert msg1.diff == b"content"

        # Transition to empty
        peer.update(b"")
        msg2 = peer.create_message()
        assert msg2.diff == b""
        assert msg2.sender_state_num == 2

    def test_receive_empty_state(self) -> None:
        """Test receiving empty state."""
        sender = EdgeCasePeer()
        receiver = EdgeCasePeer()

        # Receiver has content
        receiver.peer_state = b"old content"
        receiver.peer_state_num = 0

        # Sender sends empty state
        sender.update(b"")
        msg = sender.create_message()

        receiver.receive(msg)
        assert receiver.peer_state == b""

    def test_empty_initial_from_vector(self, sync_vectors: dict) -> None:
        """Test empty initial state from test vector."""
        vector = next(
            v for v in sync_vectors["sync_messages"]
            if v["name"] == "empty_initial"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.diff == b""
        assert msg.sender_state_num == 1


# =============================================================================
# Large State Tests
# =============================================================================


class TestLargeState:
    """Tests for large state handling."""

    def test_large_diff_payload(self) -> None:
        """Test sync with large diff payload."""
        peer = EdgeCasePeer()

        # 1MB state
        large_state = b"x" * (1024 * 1024)
        peer.update(large_state)
        msg = peer.create_message()

        assert len(msg.diff) == 1024 * 1024
        assert msg.sender_state_num == 1

    def test_large_diff_encode_decode(self) -> None:
        """Test encode/decode roundtrip for large diff."""
        large_diff = b"y" * 65536  # 64KB

        encoded = encode_sync_message(1, 0, 0, large_diff)
        decoded = parse_sync_message(encoded)

        assert decoded.diff == large_diff
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE + 65536

    def test_diff_length_boundary(self) -> None:
        """Test diff at uint32 boundary (4GB not practical, test smaller)."""
        # Test at 16MB
        size = 16 * 1024 * 1024
        large_diff = bytes(size)

        encoded = encode_sync_message(1, 0, 0, large_diff)
        decoded = parse_sync_message(encoded)

        assert len(decoded.diff) == size

    def test_progressive_size_increase(self) -> None:
        """Test progressively larger states."""
        sizes = [0, 1, 100, 1000, 10000, 100000]

        for size in sizes:
            diff = b"x" * size
            encoded = encode_sync_message(1, 0, 0, diff)
            decoded = parse_sync_message(encoded)

            assert len(decoded.diff) == size


# =============================================================================
# Rapid Update Tests
# =============================================================================


class TestRapidUpdates:
    """Tests for rapid state updates."""

    def test_many_updates_before_send(self) -> None:
        """Test many local updates before sending."""
        peer = EdgeCasePeer()

        # Many rapid updates
        for i in range(1000):
            peer.update(str(i).encode())

        # Single send captures latest
        msg = peer.create_message()
        assert msg.diff == b"999"
        assert msg.sender_state_num == 1000

    def test_rapid_send_receive(self) -> None:
        """Test rapid send/receive cycle."""
        sender = EdgeCasePeer()
        receiver = EdgeCasePeer()

        for i in range(100):
            sender.update(str(i).encode())
            msg = sender.create_message()
            receiver.receive(msg)

        assert receiver.peer_state == b"99"
        assert receiver.peer_state_num == 100

    def test_version_number_stress(self) -> None:
        """Test version number progression under stress."""
        peer = EdgeCasePeer()

        for i in range(10000):
            peer.update(b"x")
            msg = peer.create_message()
            assert msg.sender_state_num == i + 1

    def test_interleaved_rapid_updates(self) -> None:
        """Test rapid updates from both sides."""
        a = EdgeCasePeer()
        b = EdgeCasePeer()

        for i in range(100):
            # A updates and sends to B
            a.update(f"a{i}".encode())
            msg_a = a.create_message()
            b.receive(msg_a)

            # B updates and sends to A
            b.update(f"b{i}".encode())
            msg_b = b.create_message()
            a.receive(msg_b)

        # Both should have each other's latest
        assert a.peer_state == b"b99"
        assert b.peer_state == b"a99"


# =============================================================================
# Maximum Version Number Tests
# =============================================================================


class TestMaxVersionNumbers:
    """Tests for maximum version number handling."""

    def test_large_version_from_vector(self, sync_vectors: dict) -> None:
        """Test large version numbers from test vector."""
        vector = next(
            v for v in sync_vectors["sync_messages"]
            if v["name"] == "large_version_numbers"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.sender_state_num == 281474976710655  # 48-bit max
        assert msg.acked_state_num == 281474976710654
        assert msg.base_state_num == 281474976710653

    def test_max_uint64(self) -> None:
        """Test maximum uint64 version number."""
        max_u64 = (1 << 64) - 1

        encoded = encode_sync_message(max_u64, max_u64, max_u64, b"")
        decoded = parse_sync_message(encoded)

        assert decoded.sender_state_num == max_u64
        assert decoded.acked_state_num == max_u64
        assert decoded.base_state_num == max_u64

    def test_version_near_overflow(self) -> None:
        """Test version numbers near uint64 boundary."""
        # Note: In practice, versions won't reach this
        near_max = (1 << 64) - 2

        encoded = encode_sync_message(near_max, near_max - 1, near_max - 2, b"test")
        decoded = parse_sync_message(encoded)

        assert decoded.sender_state_num == near_max

    def test_version_comparison_at_boundary(self) -> None:
        """Test version comparison works near max values."""
        peer = EdgeCasePeer()
        peer.peer_state_num = (1 << 64) - 2

        # Message with higher version
        msg = SyncMessage(
            sender_state_num=(1 << 64) - 1,
            acked_state_num=0,
            base_state_num=0,
            diff=b"new",
        )

        updated = peer.receive(msg)
        assert updated
        assert peer.peer_state == b"new"


# =============================================================================
# Ack-Only Message Tests
# =============================================================================


class TestAckOnlyMessages:
    """Tests for ack-only (empty diff) messages."""

    def test_ack_only_from_vector(self, sync_vectors: dict) -> None:
        """Test ack-only message from test vector."""
        vector = next(
            v for v in sync_vectors["sync_messages"]
            if v["name"] == "ack_only"
        )

        encoded = bytes.fromhex(vector["encoded"])
        msg = parse_sync_message(encoded)

        assert msg.diff == b""
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE
        assert msg.sender_state_num == msg.acked_state_num  # Typical for ack-only

    def test_ack_only_updates_tracking(self) -> None:
        """Test that ack-only message updates ack tracking."""
        peer = EdgeCasePeer()
        peer.state_num = 5

        # Receive ack-only message
        ack_msg = SyncMessage(
            sender_state_num=0,
            acked_state_num=5,  # Acking our version 5
            base_state_num=0,
            diff=b"",
        )

        peer.receive(ack_msg)
        assert peer.last_acked == 5

    def test_ack_only_no_state_change(self) -> None:
        """Test that ack-only message doesn't change peer state."""
        peer = EdgeCasePeer()
        peer.peer_state = b"existing"
        peer.peer_state_num = 10

        ack_msg = SyncMessage(
            sender_state_num=10,  # Same as current
            acked_state_num=5,
            base_state_num=0,
            diff=b"",
        )

        updated = peer.receive(ack_msg)
        assert not updated
        assert peer.peer_state == b"existing"

    def test_pure_ack_response(self) -> None:
        """Test generating pure ack response (no local change)."""
        peer = EdgeCasePeer()
        peer.peer_state_num = 5  # Received version 5 from peer

        # Create ack-only message
        msg = peer.create_message()
        assert msg.diff == b""  # No local state change
        assert msg.acked_state_num == 5  # Acking peer's version


# =============================================================================
# Retransmission Edge Cases
# =============================================================================


class TestRetransmissionEdgeCases:
    """Tests for retransmission edge cases."""

    def test_retransmit_with_updated_ack(self, sync_vectors: dict) -> None:
        """Test retransmit scenario from test vector."""
        vector = next(
            v for v in sync_vectors["sync_messages"]
            if v["name"] == "retransmit_scenario"
        )

        msg = parse_sync_message(bytes.fromhex(vector["encoded"]))

        # Sender state is 5, but acked is 7
        # This means peer has made progress while we're retransmitting
        assert msg.sender_state_num == 5
        assert msg.acked_state_num == 7  # Ack moved forward

    def test_retransmit_idempotent(self) -> None:
        """Test that receiving retransmit is idempotent."""
        receiver = EdgeCasePeer()

        msg = SyncMessage(
            sender_state_num=5,
            acked_state_num=0,
            base_state_num=4,
            diff=b"state5",
        )

        # First receive
        receiver.receive(msg)
        assert receiver.peer_state == b"state5"

        # Retransmit receive (duplicate)
        updated = receiver.receive(msg)
        assert not updated
        assert receiver.peer_state == b"state5"


# =============================================================================
# Binary Diff Edge Cases
# =============================================================================


class TestBinaryDiffEdgeCases:
    """Tests for binary diff payload edge cases."""

    def test_binary_diff_from_vector(self, sync_vectors: dict) -> None:
        """Test binary diff from test vector."""
        vector = next(
            v for v in sync_vectors["sync_messages"]
            if v["name"] == "binary_diff"
        )

        msg = parse_sync_message(bytes.fromhex(vector["encoded"]))

        # Verify binary content
        assert msg.diff == bytes.fromhex(vector["diff"]["hex"])
        assert b"\xde\xad\xbe\xef" in msg.diff

    def test_all_byte_values(self) -> None:
        """Test diff containing all possible byte values."""
        all_bytes = bytes(range(256))

        encoded = encode_sync_message(1, 0, 0, all_bytes)
        decoded = parse_sync_message(encoded)

        assert decoded.diff == all_bytes

    def test_null_byte_preservation(self) -> None:
        """Test that null bytes are preserved in diff."""
        diff_with_nulls = b"\x00test\x00middle\x00end\x00"

        encoded = encode_sync_message(1, 0, 0, diff_with_nulls)
        decoded = parse_sync_message(encoded)

        assert decoded.diff == diff_with_nulls

    def test_high_entropy_diff(self) -> None:
        """Test diff with high-entropy (random-looking) content."""
        import hashlib

        # Generate pseudo-random bytes
        high_entropy = hashlib.sha256(b"seed").digest() * 100

        encoded = encode_sync_message(1, 0, 0, high_entropy)
        decoded = parse_sync_message(encoded)

        assert decoded.diff == high_entropy


# =============================================================================
# Version Number Relationship Tests
# =============================================================================


class TestVersionRelationships:
    """Tests for version number relationships."""

    def test_base_less_than_sender(self) -> None:
        """Test that base_state_num < sender_state_num (typical case)."""
        peer = EdgeCasePeer()

        peer.update(b"v1")
        msg1 = peer.create_message()

        peer.update(b"v2")
        msg2 = peer.create_message()

        assert msg2.base_state_num < msg2.sender_state_num
        assert msg2.base_state_num == msg1.sender_state_num

    def test_base_equals_zero_initially(self) -> None:
        """Test that first message has base_state_num = 0."""
        peer = EdgeCasePeer()
        peer.update(b"first")
        msg = peer.create_message()

        assert msg.base_state_num == 0
        assert msg.sender_state_num == 1

    def test_acked_lags_sender(self) -> None:
        """Test acked_state_num lags behind sender's latest."""
        a = EdgeCasePeer()
        b = EdgeCasePeer()

        # A sends version 1
        a.update(b"a1")
        msg_a1 = a.create_message()
        b.receive(msg_a1)

        # B sends (acking version 1)
        b.update(b"b1")
        msg_b1 = b.create_message()
        assert msg_b1.acked_state_num == 1

        # A sends version 2 (before receiving B's ack)
        a.update(b"a2")
        msg_a2 = a.create_message()
        assert msg_a2.acked_state_num == 0  # A hasn't received from B yet


# =============================================================================
# Stress Tests
# =============================================================================


class TestStress:
    """Stress tests for sync layer."""

    def test_many_small_messages(self) -> None:
        """Test many small sync messages."""
        peer = EdgeCasePeer()

        for i in range(10000):
            peer.update(b"x")
            msg = peer.create_message()
            encoded = encode_sync_message(
                msg.sender_state_num,
                msg.acked_state_num,
                msg.base_state_num,
                msg.diff,
            )
            decoded = parse_sync_message(encoded)
            assert decoded.sender_state_num == i + 1

    def test_alternating_empty_nonempty(self) -> None:
        """Test alternating between empty and non-empty states."""
        peer = EdgeCasePeer()

        for i in range(1000):
            if i % 2 == 0:
                peer.update(b"")
            else:
                peer.update(b"content")

            msg = peer.create_message()
            encoded = encode_sync_message(
                msg.sender_state_num,
                msg.acked_state_num,
                msg.base_state_num,
                msg.diff,
            )
            decoded = parse_sync_message(encoded)

            if i % 2 == 0:
                assert decoded.diff == b""
            else:
                assert decoded.diff == b"content"
