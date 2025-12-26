"""
Unit tests for idempotent diff application.

Tests the core sync layer property: applying the same diff multiple times
produces the same result as applying it once (idempotency).

This is critical for NOMAD's UDP-based reliability model:
- Duplicate packets are harmless
- Out-of-order packets handled via version comparison
- No retransmission logic needed at transport layer

Reference: specs/3-SYNC.md
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

import pytest

# =============================================================================
# Test State Types (Simple implementations for testing)
# =============================================================================


@dataclass
class EchoState:
    """Simple echo state for testing - just stores a string.

    This is the simplest possible SyncState implementation.
    The diff is always the complete new state (snapshot).
    """

    content: str = ""

    STATE_TYPE_ID = "nomad.echo.v1"

    def diff(self, old_state: EchoState, new_state: EchoState) -> bytes:
        """Create diff from old to new state.

        For echo state, diff is always the complete new content (snapshot).
        This makes diffs inherently idempotent.
        """
        return new_state.content.encode("utf-8")

    def apply(self, diff: bytes) -> EchoState:
        """Apply diff to produce new state.

        Idempotent: applying same diff twice returns same state.
        """
        return EchoState(content=diff.decode("utf-8"))


@dataclass
class CounterState:
    """Counter state for testing set-to-value semantics.

    The diff contains the absolute value, not an increment.
    This is idempotent: setting to 10 twice still results in 10.
    """

    value: int = 0

    STATE_TYPE_ID = "nomad.counter.v1"

    def diff(self, old_state: CounterState, new_state: CounterState) -> bytes:
        """Create diff - absolute value, not delta."""
        import struct

        return struct.pack("<Q", new_state.value)

    def apply(self, diff: bytes) -> CounterState:
        """Apply diff - sets value to diff content."""
        import struct

        value = struct.unpack("<Q", diff)[0]
        return CounterState(value=value)


@dataclass
class KeyValueState:
    """Key-value store state for testing partial update semantics.

    Diffs contain key-value pairs to set/update.
    Idempotent: setting key=value twice has same effect.
    """

    data: dict[str, str] = field(default_factory=dict)

    STATE_TYPE_ID = "nomad.kv.v1"

    def diff(self, old_state: KeyValueState, new_state: KeyValueState) -> bytes:
        """Create diff - only changed/new keys."""
        import json

        changes = {}
        for key, value in new_state.data.items():
            if old_state.data.get(key) != value:
                changes[key] = value
        return json.dumps(changes).encode("utf-8")

    def apply(self, diff: bytes) -> KeyValueState:
        """Apply diff - merge changes into current state."""
        import json

        changes = json.loads(diff.decode("utf-8"))
        new_data = copy.deepcopy(self.data)
        new_data.update(changes)
        return KeyValueState(data=new_data)


# =============================================================================
# Idempotency Tests
# =============================================================================


class TestIdempotency:
    """Core idempotency tests for diff application."""

    def test_echo_state_idempotent(self) -> None:
        """Test that echo state diffs are idempotent."""
        state = EchoState()
        diff = b"hello world"

        # Apply once
        state1 = state.apply(diff)

        # Apply twice
        state2 = state1.apply(diff)

        # Must be equal
        assert state1.content == state2.content == "hello world"

    def test_counter_state_idempotent(self) -> None:
        """Test that counter state diffs are idempotent."""
        state = CounterState(value=0)
        diff = CounterState(value=0).diff(CounterState(value=0), CounterState(value=42))

        # Apply once
        state1 = state.apply(diff)

        # Apply twice
        state2 = state1.apply(diff)

        # Must be equal
        assert state1.value == state2.value == 42

    def test_kv_state_idempotent(self) -> None:
        """Test that key-value state diffs are idempotent."""
        state = KeyValueState(data={"existing": "value"})
        diff = b'{"key1": "value1", "key2": "value2"}'

        # Apply once
        state1 = state.apply(diff)

        # Apply twice
        state2 = state1.apply(diff)

        # Must be equal
        assert state1.data == state2.data
        assert state1.data["key1"] == "value1"
        assert state1.data["key2"] == "value2"
        assert state1.data["existing"] == "value"

    def test_apply_n_times_equals_apply_once(self) -> None:
        """Test that applying diff N times equals applying once."""
        state = EchoState()
        diff = b"test content"

        # Apply once
        result_once = state.apply(diff)

        # Apply 10 times
        result_many = state
        for _ in range(10):
            result_many = result_many.apply(diff)

        assert result_once.content == result_many.content


# =============================================================================
# Out-of-Order Application Tests
# =============================================================================


class TestOutOfOrder:
    """Tests for out-of-order diff application.

    NOMAD handles out-of-order via version numbers at the sync layer.
    These tests verify that diffs themselves don't depend on order.
    """

    def test_kv_order_independent(self) -> None:
        """Test that KV diffs for different keys are order independent."""
        initial = KeyValueState(data={})

        diff_a = b'{"a": "1"}'
        diff_b = b'{"b": "2"}'

        # Apply A then B
        result_ab = initial.apply(diff_a).apply(diff_b)

        # Apply B then A
        result_ba = initial.apply(diff_b).apply(diff_a)

        # Both orders should produce same result
        assert result_ab.data == result_ba.data
        assert result_ab.data == {"a": "1", "b": "2"}

    def test_overlapping_keys_last_wins(self) -> None:
        """Test that overlapping key updates use last-applied value.

        This mirrors how version numbers work: higher version wins.
        """
        initial = KeyValueState(data={})

        diff_old = b'{"key": "old"}'
        diff_new = b'{"key": "new"}'

        # Apply old then new
        result = initial.apply(diff_old).apply(diff_new)
        assert result.data["key"] == "new"

        # Apply new then old (simulates reordering)
        result = initial.apply(diff_new).apply(diff_old)
        assert result.data["key"] == "old"  # Last applied wins

    def test_snapshot_diff_is_always_idempotent(self) -> None:
        """Test that snapshot-style diffs are inherently idempotent.

        EchoState uses snapshot diffs: the diff IS the new state.
        This is the simplest form of idempotent diff.
        """
        states = [
            EchoState(content=""),
            EchoState(content="hello"),
            EchoState(content="world"),
            EchoState(content="hello world"),
        ]

        for old in states:
            for new in states:
                diff = old.diff(old, new)
                result1 = old.apply(diff)
                result2 = result1.apply(diff)

                # Idempotent: applying twice equals applying once
                assert result1.content == result2.content
                assert result1.content == new.content


# =============================================================================
# Empty State Tests
# =============================================================================


class TestEmptyState:
    """Tests for empty state and empty diff handling."""

    def test_empty_echo_state(self) -> None:
        """Test applying diff to empty state."""
        state = EchoState(content="")
        diff = b"new content"

        result = state.apply(diff)
        assert result.content == "new content"

    def test_empty_diff_to_echo(self) -> None:
        """Test applying empty diff to echo state."""
        state = EchoState(content="existing")
        diff = b""

        result = state.apply(diff)
        assert result.content == ""  # Empty diff replaces with empty

    def test_empty_kv_state(self) -> None:
        """Test applying diff to empty KV state."""
        state = KeyValueState(data={})
        diff = b'{"key": "value"}'

        result = state.apply(diff)
        assert result.data == {"key": "value"}

    def test_empty_kv_diff(self) -> None:
        """Test applying empty diff to KV state."""
        state = KeyValueState(data={"existing": "value"})
        diff = b"{}"  # Empty JSON object

        result = state.apply(diff)
        assert result.data == {"existing": "value"}  # Unchanged


# =============================================================================
# Sequence Tests (Simulating Sync Layer)
# =============================================================================


class TestSyncSequence:
    """Tests simulating sync layer message sequences.

    These tests simulate how the sync layer applies diffs based on
    version numbers, demonstrating idempotency in practice.
    """

    def test_sequence_with_skipped_versions(self) -> None:
        """Test sync sequence where intermediate versions are skipped.

        This is a key NOMAD feature: you only need the latest state.
        """
        state = EchoState(content="A")

        # Simulate: version 1 -> version 2 -> version 3
        # But only version 3 is received
        diff_v3 = b"C"  # Snapshot of version 3

        result = state.apply(diff_v3)
        assert result.content == "C"

        # Applying again (duplicate) has no additional effect
        result2 = result.apply(diff_v3)
        assert result2.content == "C"

    def test_sequence_with_retransmission(self) -> None:
        """Test sync sequence with retransmitted messages.

        Retransmissions should be harmless due to idempotency.
        """
        state = EchoState(content="initial")

        diff = b"updated"

        # First transmission
        state1 = state.apply(diff)

        # Retransmission (duplicate)
        state2 = state1.apply(diff)

        # Another retransmission
        state3 = state2.apply(diff)

        # All should be identical
        assert state1.content == state2.content == state3.content == "updated"


# =============================================================================
# Property: Idempotency Definition
# =============================================================================


class TestIdempotencyProperty:
    """Formal tests for the idempotency property.

    Definition: f(f(x)) = f(x)
    In our context: apply(apply(state, diff), diff) = apply(state, diff)
    """

    def test_formal_idempotency_echo(self) -> None:
        """Test formal idempotency: f(f(x)) = f(x) for EchoState."""
        state = EchoState()
        diff = b"test"

        fx = state.apply(diff)
        ffx = fx.apply(diff)

        assert fx.content == ffx.content

    def test_formal_idempotency_counter(self) -> None:
        """Test formal idempotency: f(f(x)) = f(x) for CounterState."""
        state = CounterState(value=10)

        # Create diff to set value to 42
        import struct

        diff = struct.pack("<Q", 42)

        fx = state.apply(diff)
        ffx = fx.apply(diff)

        assert fx.value == ffx.value == 42

    def test_formal_idempotency_kv(self) -> None:
        """Test formal idempotency: f(f(x)) = f(x) for KeyValueState."""
        state = KeyValueState(data={"a": "1"})
        diff = b'{"b": "2"}'

        fx = state.apply(diff)
        ffx = fx.apply(diff)

        assert fx.data == ffx.data


# =============================================================================
# Stability Tests
# =============================================================================


class TestDiffStability:
    """Tests for diff generation stability.

    Generating the same diff multiple times should produce identical bytes.
    """

    def test_echo_diff_stable(self) -> None:
        """Test that echo diff generation is stable."""
        old = EchoState(content="old")
        new = EchoState(content="new")

        diff1 = old.diff(old, new)
        diff2 = old.diff(old, new)

        assert diff1 == diff2

    def test_counter_diff_stable(self) -> None:
        """Test that counter diff generation is stable."""
        old = CounterState(value=10)
        new = CounterState(value=20)

        diff1 = old.diff(old, new)
        diff2 = old.diff(old, new)

        assert diff1 == diff2

    def test_kv_diff_stable(self) -> None:
        """Test that KV diff generation is stable."""
        old = KeyValueState(data={"a": "1"})
        new = KeyValueState(data={"a": "1", "b": "2"})

        diff1 = old.diff(old, new)
        diff2 = old.diff(old, new)

        assert diff1 == diff2


# =============================================================================
# Binary Diff Tests
# =============================================================================


class TestBinaryDiffs:
    """Tests for binary diff payloads."""

    def test_binary_echo_diff(self) -> None:
        """Test echo state with binary content."""
        state = EchoState(content="")

        # Use latin-1 for binary content that may not be valid UTF-8
        # For actual binary, you'd use a different state type
        binary_diff = bytes(range(256))  # All byte values

        # EchoState expects UTF-8, so this would fail
        # This test demonstrates the need for proper state type design
        with pytest.raises(UnicodeDecodeError):
            state.apply(binary_diff)

    def test_counter_accepts_binary(self) -> None:
        """Test counter state accepts binary diff."""
        state = CounterState(value=0)

        import struct

        binary_diff = struct.pack("<Q", 12345678901234567890)

        result = state.apply(binary_diff)
        assert result.value == 12345678901234567890

    def test_null_bytes_in_diff(self) -> None:
        """Test handling of null bytes in diff payload."""
        state = KeyValueState(data={})

        # JSON with escaped content
        diff = b'{"key": "value\\u0000with\\u0000nulls"}'

        result = state.apply(diff)
        assert "key" in result.data


# =============================================================================
# Large State Tests
# =============================================================================


class TestLargeState:
    """Tests for large state and diff handling."""

    def test_large_echo_state(self) -> None:
        """Test echo state with large content."""
        state = EchoState(content="")
        large_diff = ("x" * 1_000_000).encode("utf-8")  # 1MB

        result = state.apply(large_diff)
        assert len(result.content) == 1_000_000

        # Idempotent
        result2 = result.apply(large_diff)
        assert result.content == result2.content

    def test_large_kv_state(self) -> None:
        """Test KV state with many keys."""
        import json

        state = KeyValueState(data={})

        # Create diff with 1000 keys
        changes = {f"key{i}": f"value{i}" for i in range(1000)}
        diff = json.dumps(changes).encode("utf-8")

        result = state.apply(diff)
        assert len(result.data) == 1000

        # Idempotent
        result2 = result.apply(diff)
        assert result.data == result2.data
