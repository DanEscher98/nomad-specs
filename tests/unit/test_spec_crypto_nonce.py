"""
Nonce construction tests for XChaCha20-Poly1305.

Tests the security layer's nonce construction against test vectors
and validates nonce properties with hypothesis.

Test mapping: specs/1-SECURITY.md § "Nonce Construction"
"""

from __future__ import annotations

import struct
from pathlib import Path

import json5
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    AEAD_NONCE_SIZE,
    NonceComponents,
    construct_nonce,
    parse_nonce,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def nonce_vectors() -> dict:
    """Load nonce test vectors."""
    vectors_path = Path(__file__).parent.parent / "vectors" / "nonce_vectors.json5"
    with open(vectors_path) as f:
        return json5.load(f)


# =============================================================================
# Test Vector Validation
# =============================================================================


class TestNonceVectors:
    """Test nonce construction against known test vectors."""

    def test_initial_initiator(self, nonce_vectors: dict) -> None:
        """Initial initiator->responder nonce."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "initial_initiator")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]
        assert len(nonce) == AEAD_NONCE_SIZE

    def test_initial_responder(self, nonce_vectors: dict) -> None:
        """Initial responder->initiator nonce."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "initial_responder")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]

    def test_second_frame(self, nonce_vectors: dict) -> None:
        """Second frame nonce (counter=1)."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "second_frame")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]

    def test_after_rekey(self, nonce_vectors: dict) -> None:
        """Nonce after rekey (epoch=1, counter reset)."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "after_rekey")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]

    def test_max_counter(self, nonce_vectors: dict) -> None:
        """Maximum counter value (2^64 - 1)."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "max_counter")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]

    def test_max_epoch(self, nonce_vectors: dict) -> None:
        """Maximum epoch value (2^32 - 1)."""
        vector = next(v for v in nonce_vectors["vectors"] if v["name"] == "max_epoch")

        nonce = construct_nonce(
            epoch=vector["epoch"],
            direction=vector["direction"],
            counter=vector["counter"],
        )

        assert nonce.hex() == vector["nonce"]

    def test_all_vectors(self, nonce_vectors: dict) -> None:
        """All vectors produce expected nonces."""
        for vector in nonce_vectors["vectors"]:
            nonce = construct_nonce(
                epoch=vector["epoch"],
                direction=vector["direction"],
                counter=vector["counter"],
            )

            assert nonce.hex() == vector["nonce"], f"Failed for vector: {vector['name']}"


# =============================================================================
# Nonce Layout Tests
# =============================================================================


class TestNonceLayout:
    """Test nonce byte layout matches spec."""

    def test_nonce_length(self) -> None:
        """Nonce is exactly 24 bytes."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        assert len(nonce) == 24
        assert len(nonce) == AEAD_NONCE_SIZE

    def test_epoch_at_offset_0(self) -> None:
        """Epoch is at bytes 0-3 (little-endian)."""
        nonce = construct_nonce(epoch=0x12345678, direction=0, counter=0)

        epoch = struct.unpack_from("<I", nonce, 0)[0]
        assert epoch == 0x12345678

    def test_direction_at_offset_4(self) -> None:
        """Direction is at byte 4."""
        nonce_initiator = construct_nonce(epoch=0, direction=0, counter=0)
        nonce_responder = construct_nonce(epoch=0, direction=1, counter=0)

        assert nonce_initiator[4] == 0
        assert nonce_responder[4] == 1

    def test_zeros_at_offset_5_to_15(self) -> None:
        """Bytes 5-15 are zeros (padding)."""
        nonce = construct_nonce(epoch=0xFFFFFFFF, direction=1, counter=0xFFFFFFFFFFFFFFFF)

        for i in range(5, 16):
            assert nonce[i] == 0, f"Byte {i} should be 0, got {nonce[i]}"

    def test_counter_at_offset_16(self) -> None:
        """Counter is at bytes 16-23 (little-endian)."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0x123456789ABCDEF0)

        counter = struct.unpack_from("<Q", nonce, 16)[0]
        assert counter == 0x123456789ABCDEF0


# =============================================================================
# Parse Nonce Tests
# =============================================================================


class TestParseNonce:
    """Test nonce parsing back to components."""

    def test_roundtrip(self) -> None:
        """Construct then parse recovers original components."""
        epoch = 42
        direction = 1
        counter = 1000000

        nonce = construct_nonce(epoch, direction, counter)
        parsed = parse_nonce(nonce)

        assert parsed.epoch == epoch
        assert parsed.direction == direction
        assert parsed.counter == counter

    def test_parse_all_zeros(self) -> None:
        """Parse all-zeros nonce."""
        nonce = b"\x00" * 24
        parsed = parse_nonce(nonce)

        assert parsed.epoch == 0
        assert parsed.direction == 0
        assert parsed.counter == 0

    def test_parse_max_values(self) -> None:
        """Parse nonce with maximum values."""
        nonce = construct_nonce(
            epoch=0xFFFFFFFF,
            direction=1,
            counter=0xFFFFFFFFFFFFFFFF,
        )
        parsed = parse_nonce(nonce)

        assert parsed.epoch == 0xFFFFFFFF
        assert parsed.direction == 1
        assert parsed.counter == 0xFFFFFFFFFFFFFFFF

    def test_parse_returns_noncecomponents(self) -> None:
        """Parse returns NonceComponents dataclass."""
        nonce = construct_nonce(epoch=1, direction=0, counter=100)
        parsed = parse_nonce(nonce)

        assert isinstance(parsed, NonceComponents)
        assert hasattr(parsed, "epoch")
        assert hasattr(parsed, "direction")
        assert hasattr(parsed, "counter")


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestNonceProperties:
    """Property-based tests for nonce construction."""

    @given(
        epoch=st.integers(min_value=0, max_value=0xFFFFFFFF),
        direction=st.integers(min_value=0, max_value=1),
        counter=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    @settings(max_examples=100)
    def test_roundtrip_property(self, epoch: int, direction: int, counter: int) -> None:
        """Construct then parse always recovers original values."""
        nonce = construct_nonce(epoch, direction, counter)
        parsed = parse_nonce(nonce)

        assert parsed.epoch == epoch
        assert parsed.direction == direction
        assert parsed.counter == counter

    @given(
        epoch=st.integers(min_value=0, max_value=0xFFFFFFFF),
        direction=st.integers(min_value=0, max_value=1),
        counter=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    @settings(max_examples=100)
    def test_nonce_length_property(self, epoch: int, direction: int, counter: int) -> None:
        """Nonce is always 24 bytes."""
        nonce = construct_nonce(epoch, direction, counter)
        assert len(nonce) == AEAD_NONCE_SIZE

    @given(
        epoch1=st.integers(min_value=0, max_value=0xFFFFFFFF),
        epoch2=st.integers(min_value=0, max_value=0xFFFFFFFF),
        counter=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    @settings(max_examples=50)
    def test_different_epochs_different_nonces(
        self, epoch1: int, epoch2: int, counter: int
    ) -> None:
        """Different epochs produce different nonces (if epochs differ)."""
        if epoch1 == epoch2:
            return

        nonce1 = construct_nonce(epoch1, direction=0, counter=counter)
        nonce2 = construct_nonce(epoch2, direction=0, counter=counter)

        assert nonce1 != nonce2

    @given(
        epoch=st.integers(min_value=0, max_value=0xFFFFFFFF),
        counter1=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
        counter2=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    @settings(max_examples=50)
    def test_different_counters_different_nonces(
        self, epoch: int, counter1: int, counter2: int
    ) -> None:
        """Different counters produce different nonces (if counters differ)."""
        if counter1 == counter2:
            return

        nonce1 = construct_nonce(epoch, direction=0, counter=counter1)
        nonce2 = construct_nonce(epoch, direction=0, counter=counter2)

        assert nonce1 != nonce2

    @given(
        epoch=st.integers(min_value=0, max_value=0xFFFFFFFF),
        counter=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    @settings(max_examples=50)
    def test_different_directions_different_nonces(self, epoch: int, counter: int) -> None:
        """Different directions produce different nonces."""
        nonce_initiator = construct_nonce(epoch, direction=0, counter=counter)
        nonce_responder = construct_nonce(epoch, direction=1, counter=counter)

        assert nonce_initiator != nonce_responder


# =============================================================================
# Direction Values
# =============================================================================


class TestNonceDirection:
    """Test nonce direction values."""

    def test_initiator_direction_is_zero(self) -> None:
        """Initiator->responder direction is 0."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        parsed = parse_nonce(nonce)

        assert parsed.direction == 0

    def test_responder_direction_is_one(self) -> None:
        """Responder->initiator direction is 1."""
        nonce = construct_nonce(epoch=0, direction=1, counter=0)
        parsed = parse_nonce(nonce)

        assert parsed.direction == 1


# =============================================================================
# Counter Limits
# =============================================================================


class TestNonceCounterLimits:
    """Test nonce counter edge cases per spec."""

    def test_counter_zero(self) -> None:
        """Counter starts at zero."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        parsed = parse_nonce(nonce)

        assert parsed.counter == 0

    def test_counter_max_value(self) -> None:
        """Counter can reach 2^64 - 1."""
        max_counter = 2**64 - 1
        nonce = construct_nonce(epoch=0, direction=0, counter=max_counter)
        parsed = parse_nonce(nonce)

        assert parsed.counter == max_counter

    def test_counter_increment(self) -> None:
        """Incrementing counter produces unique nonces."""
        nonces = []
        for i in range(100):
            nonce = construct_nonce(epoch=0, direction=0, counter=i)
            nonces.append(nonce)

        # All nonces should be unique
        assert len(set(nonces)) == 100


# =============================================================================
# Epoch Limits
# =============================================================================


class TestNonceEpochLimits:
    """Test nonce epoch edge cases per spec."""

    def test_epoch_zero(self) -> None:
        """Epoch starts at zero."""
        nonce = construct_nonce(epoch=0, direction=0, counter=0)
        parsed = parse_nonce(nonce)

        assert parsed.epoch == 0

    def test_epoch_max_value(self) -> None:
        """Epoch can reach 2^32 - 1."""
        max_epoch = 2**32 - 1
        nonce = construct_nonce(epoch=max_epoch, direction=0, counter=0)
        parsed = parse_nonce(nonce)

        assert parsed.epoch == max_epoch

    def test_epoch_increment(self) -> None:
        """Incrementing epoch produces unique nonces."""
        nonces = []
        for i in range(100):
            nonce = construct_nonce(epoch=i, direction=0, counter=0)
            nonces.append(nonce)

        # All nonces should be unique
        assert len(set(nonces)) == 100


# =============================================================================
# Nonce Uniqueness
# =============================================================================


class TestNonceUniqueness:
    """Test nonce uniqueness guarantees."""

    def test_same_params_same_nonce(self) -> None:
        """Same parameters produce identical nonce."""
        nonce1 = construct_nonce(epoch=5, direction=1, counter=100)
        nonce2 = construct_nonce(epoch=5, direction=1, counter=100)

        assert nonce1 == nonce2

    def test_any_different_param_different_nonce(self) -> None:
        """Any different parameter produces different nonce."""
        base = construct_nonce(epoch=5, direction=0, counter=100)

        different_epoch = construct_nonce(epoch=6, direction=0, counter=100)
        different_direction = construct_nonce(epoch=5, direction=1, counter=100)
        different_counter = construct_nonce(epoch=5, direction=0, counter=101)

        assert base != different_epoch
        assert base != different_direction
        assert base != different_counter

    def test_rekey_resets_counter_but_changes_epoch(self) -> None:
        """After rekey, counter resets but epoch changes, ensuring uniqueness."""
        # Before rekey: epoch=0, counter=1000
        before_rekey = construct_nonce(epoch=0, direction=0, counter=1000)

        # After rekey: epoch=1, counter=0 (reset)
        after_rekey = construct_nonce(epoch=1, direction=0, counter=0)

        assert before_rekey != after_rekey
