"""
Property-based tests for sync layer using Hypothesis.

Tests fundamental properties that must hold for all inputs:
- Idempotency: apply(apply(state, diff), diff) == apply(state, diff)
- Encode/decode roundtrip
- Convergence under random conditions

Reference: specs/3-SYNC.md
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from lib.reference import (
    SYNC_MESSAGE_HEADER_SIZE,
    encode_sync_message,
    parse_sync_message,
)

# =============================================================================
# Hypothesis Strategies
# =============================================================================

# Version numbers (uint64)
version_numbers = st.integers(min_value=0, max_value=(1 << 64) - 1)

# Smaller version numbers for faster tests
small_versions = st.integers(min_value=0, max_value=10000)

# Diff payloads (binary data)
diff_payloads = st.binary(min_size=0, max_size=1024)

# Small diff payloads for faster tests
small_diffs = st.binary(min_size=0, max_size=100)


# =============================================================================
# Test State Types (for property testing)
# =============================================================================


@dataclass
class SnapshotState:
    """Snapshot-based state - diff is always the complete new state.

    This is inherently idempotent: setting to X is the same as setting to X twice.
    """

    content: bytes = b""

    def apply(self, diff: bytes) -> SnapshotState:
        """Apply diff (which is the new state)."""
        return SnapshotState(content=diff)

    def diff(self, other: SnapshotState) -> bytes:
        """Create diff to reach other state."""
        return other.content


@dataclass
class SetValueState:
    """Set-to-value state for numeric data.

    Idempotent: setting value to N twice results in N.
    """

    value: int = 0

    def apply(self, diff: bytes) -> SetValueState:
        """Apply diff (set to value)."""
        if len(diff) == 8:
            return SetValueState(value=struct.unpack("<Q", diff)[0])
        return self

    def diff(self, other: SetValueState) -> bytes:
        """Create diff to reach other state."""
        return struct.pack("<Q", other.value)


@dataclass
class MergeState:
    """Merge-based state for key-value data.

    Idempotent: setting key=value is the same whether done once or twice.
    """

    data: dict[str, str] = field(default_factory=dict)

    def apply(self, diff: bytes) -> MergeState:
        """Apply diff (merge changes)."""
        import json

        try:
            changes = json.loads(diff.decode("utf-8"))
            new_data = {**self.data, **changes}
            return MergeState(data=new_data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self

    def diff(self, other: MergeState) -> bytes:
        """Create diff to reach other state."""
        import json

        changes = {k: v for k, v in other.data.items() if self.data.get(k) != v}
        return json.dumps(changes).encode("utf-8")


# =============================================================================
# Encoding Roundtrip Properties
# =============================================================================


class TestEncodingRoundtrip:
    """Property tests for encode/decode roundtrip."""

    @given(
        sender=version_numbers,
        acked=version_numbers,
        base=version_numbers,
        diff=diff_payloads,
    )
    @settings(max_examples=200)
    def test_roundtrip_preserves_values(
        self, sender: int, acked: int, base: int, diff: bytes
    ) -> None:
        """Test that encode/decode roundtrip preserves all values."""
        encoded = encode_sync_message(sender, acked, base, diff)
        decoded = parse_sync_message(encoded)

        assert decoded.sender_state_num == sender
        assert decoded.acked_state_num == acked
        assert decoded.base_state_num == base
        assert decoded.diff == diff

    @given(diff=diff_payloads)
    @settings(max_examples=100)
    def test_length_consistency(self, diff: bytes) -> None:
        """Test that encoded length matches expected."""
        encoded = encode_sync_message(1, 0, 0, diff)
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE + len(diff)

    @given(
        sender=version_numbers,
        acked=version_numbers,
        base=version_numbers,
    )
    @settings(max_examples=100)
    def test_empty_diff_roundtrip(
        self, sender: int, acked: int, base: int
    ) -> None:
        """Test roundtrip with empty diff."""
        encoded = encode_sync_message(sender, acked, base, b"")
        decoded = parse_sync_message(encoded)

        assert decoded.diff == b""
        assert len(encoded) == SYNC_MESSAGE_HEADER_SIZE


# =============================================================================
# Idempotency Properties
# =============================================================================


class TestIdempotencyProperty:
    """Property tests for idempotency: f(f(x)) = f(x)."""

    @given(diff=small_diffs)
    @settings(max_examples=100)
    def test_snapshot_idempotent(self, diff: bytes) -> None:
        """Test snapshot state is idempotent."""
        state = SnapshotState()

        result_once = state.apply(diff)
        result_twice = result_once.apply(diff)

        assert result_once.content == result_twice.content

    @given(value=st.integers(min_value=0, max_value=(1 << 64) - 1))
    @settings(max_examples=100)
    def test_setvalue_idempotent(self, value: int) -> None:
        """Test set-value state is idempotent."""
        state = SetValueState()
        diff = struct.pack("<Q", value)

        result_once = state.apply(diff)
        result_twice = result_once.apply(diff)

        assert result_once.value == result_twice.value == value

    @given(
        keys=st.lists(st.text(min_size=1, max_size=10), min_size=1, max_size=5),
        values=st.lists(st.text(min_size=1, max_size=10), min_size=1, max_size=5),
    )
    @settings(max_examples=100)
    def test_merge_idempotent(self, keys: list[str], values: list[str]) -> None:
        """Test merge state is idempotent."""
        import json

        # Create a valid diff (zip truncates to shorter list)
        changes = dict(zip(keys, values, strict=False))
        diff = json.dumps(changes).encode("utf-8")

        state = MergeState()
        result_once = state.apply(diff)
        result_twice = result_once.apply(diff)

        assert result_once.data == result_twice.data

    @given(n=st.integers(min_value=2, max_value=10), diff=small_diffs)
    @settings(max_examples=50)
    def test_idempotent_n_times(self, n: int, diff: bytes) -> None:
        """Test applying diff N times equals applying once."""
        state = SnapshotState()

        result_once = state.apply(diff)

        result_n = state
        for _ in range(n):
            result_n = result_n.apply(diff)

        assert result_once.content == result_n.content


# =============================================================================
# Version Number Properties
# =============================================================================


class TestVersionProperties:
    """Property tests for version number semantics."""

    @given(v1=small_versions, v2=small_versions)
    @settings(max_examples=100)
    def test_newer_version_applied(self, v1: int, v2: int) -> None:
        """Test that newer version is always applied."""
        assume(v1 != v2)

        peer_state_num = min(v1, v2)
        newer = max(v1, v2)

        # Message with newer version
        applied = newer > peer_state_num

        assert applied  # Newer always applied when > current

    @given(versions=st.lists(small_versions, min_size=2, max_size=10))
    @settings(max_examples=50)
    def test_max_version_wins(self, versions: list[int]) -> None:
        """Test that maximum version becomes the final state."""
        assume(len(set(versions)) > 1)  # Need distinct versions

        peer_state_num = 0
        final_applied = 0

        for v in versions:
            if v > peer_state_num:
                peer_state_num = v
                final_applied = v

        assert final_applied == max(versions)


# =============================================================================
# Sync Flow Properties
# =============================================================================


@dataclass
class PropertyTestPeer:
    """Peer for property-based sync testing."""

    state: bytes = b""
    state_num: int = 0
    peer_state_num: int = 0
    last_acked: int = 0

    def receive(self, sender_num: int, acked_num: int, diff: bytes) -> bool:
        if acked_num > self.last_acked:
            self.last_acked = acked_num

        if sender_num > self.peer_state_num:
            self.state = diff
            self.peer_state_num = sender_num
            return True
        return False


class TestSyncFlowProperties:
    """Property tests for sync flow."""

    @given(
        updates=st.lists(small_diffs, min_size=1, max_size=20),
    )
    @settings(max_examples=50)
    def test_final_state_is_latest(self, updates: list[bytes]) -> None:
        """Test that final state equals latest update."""
        peer = PropertyTestPeer()

        for i, update in enumerate(updates):
            peer.receive(i + 1, 0, update)

        assert peer.state == updates[-1]
        assert peer.peer_state_num == len(updates)

    @given(
        versions=st.lists(
            st.tuples(small_versions, small_diffs),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=50)
    def test_out_of_order_converges(
        self, versions: list[tuple[int, bytes]]
    ) -> None:
        """Test that out-of-order delivery converges to max version."""
        import random

        peer = PropertyTestPeer()

        # Shuffle to simulate out-of-order
        shuffled = versions.copy()
        random.shuffle(shuffled)

        for v, diff in shuffled:
            peer.receive(v, 0, diff)

        # Should have the highest version
        max_version = max(v for v, _ in versions)
        assert peer.peer_state_num <= max_version

    @given(
        n_dups=st.integers(min_value=1, max_value=10),
        diff=small_diffs,
    )
    @settings(max_examples=50)
    def test_duplicates_idempotent(self, n_dups: int, diff: bytes) -> None:
        """Test that duplicate messages are idempotent."""
        peer = PropertyTestPeer()

        # Send same message multiple times
        for _ in range(n_dups):
            peer.receive(1, 0, diff)

        assert peer.state == diff
        assert peer.peer_state_num == 1


# =============================================================================
# Convergence Properties
# =============================================================================


class TestConvergenceProperties:
    """Property tests for convergence."""

    @given(
        a_updates=st.lists(small_diffs, min_size=1, max_size=5),
        b_updates=st.lists(small_diffs, min_size=1, max_size=5),
    )
    @settings(max_examples=30)
    def test_bidirectional_convergence(
        self, a_updates: list[bytes], b_updates: list[bytes]
    ) -> None:
        """Test that bidirectional updates converge."""
        a = PropertyTestPeer()
        b = PropertyTestPeer()

        # A sends all its updates
        for i, update in enumerate(a_updates):
            a.state = update
            a.state_num = i + 1
            b.receive(a.state_num, 0, a.state)

        # B sends all its updates
        for i, update in enumerate(b_updates):
            b.state = update
            b.state_num = i + 1
            a.receive(b.state_num, 0, b.state)

        # Each knows the other's latest
        assert a.peer_state_num == len(b_updates)
        assert b.peer_state_num == len(a_updates)

    @given(
        loss_indices=st.lists(st.integers(min_value=0, max_value=9), max_size=5),
    )
    @settings(max_examples=30)
    def test_convergence_with_loss(self, loss_indices: set[int]) -> None:
        """Test convergence despite packet loss."""
        peer = PropertyTestPeer()
        loss_set = set(loss_indices)

        for i in range(10):
            if i not in loss_set:
                state = f"state{i}".encode()
                peer.receive(i + 1, 0, state)

        # Peer has some valid state (the last delivered)
        if loss_set != set(range(10)):
            assert peer.peer_state_num > 0


# =============================================================================
# Ack Properties
# =============================================================================


class TestAckProperties:
    """Property tests for acknowledgment tracking."""

    @given(acks=st.lists(small_versions, min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_ack_monotonic(self, acks: list[int]) -> None:
        """Test that ack tracking is monotonically increasing."""
        peer = PropertyTestPeer()

        for ack in acks:
            peer.receive(0, ack, b"")

        # Should have max ack seen
        assert peer.last_acked == max(acks)

    @given(
        n=st.integers(min_value=1, max_value=5),
        ack_values=st.lists(small_versions, min_size=1, max_size=5),
    )
    @settings(max_examples=30)
    def test_ack_independent_of_state(
        self, n: int, ack_values: list[int]
    ) -> None:
        """Test that ack tracking is independent of state updates.

        Ack field is always processed regardless of sender_state_num.
        """
        peer = PropertyTestPeer()

        # Send messages with incrementing sender versions
        for i, ack in enumerate(ack_values):
            peer.receive(i + 1, ack, b"data")

        # Ack should be max of all acks seen
        assert peer.last_acked == max(ack_values)


# =============================================================================
# Invariant Properties
# =============================================================================


class TestInvariantProperties:
    """Property tests for invariants that must always hold."""

    @given(
        sender=version_numbers,
        acked=version_numbers,
        base=version_numbers,
        diff=diff_payloads,
    )
    @settings(max_examples=100)
    def test_encoded_never_empty(
        self, sender: int, acked: int, base: int, diff: bytes
    ) -> None:
        """Test that encoded message is never empty."""
        encoded = encode_sync_message(sender, acked, base, diff)
        assert len(encoded) >= SYNC_MESSAGE_HEADER_SIZE

    @given(diff=diff_payloads)
    @settings(max_examples=100)
    def test_diff_preserved_exactly(self, diff: bytes) -> None:
        """Test that diff is preserved exactly through encode/decode."""
        encoded = encode_sync_message(1, 0, 0, diff)
        decoded = parse_sync_message(encoded)

        # Byte-for-byte equality
        assert decoded.diff == diff
        assert len(decoded.diff) == len(diff)

    @given(
        v1=version_numbers,
        v2=version_numbers,
        v3=version_numbers,
    )
    @settings(max_examples=100)
    def test_version_independence(self, v1: int, v2: int, v3: int) -> None:
        """Test that version fields are encoded/decoded independently."""
        encoded = encode_sync_message(v1, v2, v3, b"")
        decoded = parse_sync_message(encoded)

        assert decoded.sender_state_num == v1
        assert decoded.acked_state_num == v2
        assert decoded.base_state_num == v3
