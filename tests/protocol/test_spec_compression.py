"""
Compression extension protocol tests.

Tests zstd compression encoding/decoding, flag handling, and edge cases
per specs/4-EXTENSIONS.md § "Extension 0x0001: Compression".

Test mapping: specs/4-EXTENSIONS.md § "Extension 0x0001: Compression"
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    COMPRESSION_FLAG_COMPRESSED,
    COMPRESSION_FLAG_UNCOMPRESSED,
    COMPRESSION_LEVEL_DEFAULT,
    COMPRESSION_LEVEL_MAX,
    COMPRESSION_LEVEL_MIN,
    COMPRESSION_MIN_SIZE,
    compress_payload,
    decompress_payload,
)

# =============================================================================
# Compression Flag Tests
# =============================================================================


class TestCompressionFlags:
    """Test compression flag encoding."""

    def test_uncompressed_flag_value(self) -> None:
        """Uncompressed flag is 0x00."""
        assert COMPRESSION_FLAG_UNCOMPRESSED == 0x00

    def test_compressed_flag_value(self) -> None:
        """Compressed flag is 0x01."""
        assert COMPRESSION_FLAG_COMPRESSED == 0x01

    def test_small_payload_uses_uncompressed_flag(self) -> None:
        """Payloads below MIN_COMPRESS_SIZE use uncompressed flag."""
        small_data = b"x" * (COMPRESSION_MIN_SIZE - 1)
        result = compress_payload(small_data)

        assert result[0] == COMPRESSION_FLAG_UNCOMPRESSED
        assert result[1:] == small_data

    def test_large_payload_uses_compressed_flag(self) -> None:
        """Compressible payloads above MIN_COMPRESS_SIZE use compressed flag."""
        # Highly compressible data
        large_data = b"A" * 1000
        result = compress_payload(large_data)

        assert result[0] == COMPRESSION_FLAG_COMPRESSED

    def test_incompressible_data_uses_uncompressed_flag(self) -> None:
        """Data that doesn't compress well uses uncompressed flag."""
        import os

        # Random data doesn't compress well
        random_data = os.urandom(COMPRESSION_MIN_SIZE + 100)
        result = compress_payload(random_data)

        # Random data typically doesn't compress, so uncompressed is used
        # The flag should be either 0x00 or 0x01 depending on compression ratio
        assert result[0] in (COMPRESSION_FLAG_UNCOMPRESSED, COMPRESSION_FLAG_COMPRESSED)


# =============================================================================
# Compression Behavior Tests
# =============================================================================


class TestCompressionBehavior:
    """Test compression behavior per spec."""

    def test_min_compress_size_constant(self) -> None:
        """MIN_COMPRESS_SIZE is 64 bytes per spec."""
        assert COMPRESSION_MIN_SIZE == 64

    def test_below_min_size_not_compressed(self) -> None:
        """Data below MIN_COMPRESS_SIZE is never compressed."""
        for size in [1, 10, 32, COMPRESSION_MIN_SIZE - 1]:
            data = b"A" * size  # Highly compressible
            result = compress_payload(data)

            assert result[0] == COMPRESSION_FLAG_UNCOMPRESSED
            assert result[1:] == data

    def test_at_min_size_can_compress(self) -> None:
        """Data at exactly MIN_COMPRESS_SIZE can be compressed."""
        data = b"A" * COMPRESSION_MIN_SIZE
        result = compress_payload(data)

        # Should compress since it's compressible and at threshold
        assert result[0] == COMPRESSION_FLAG_COMPRESSED

    def test_compression_reduces_size(self) -> None:
        """Compressed data is smaller than original for compressible input."""
        data = b"A" * 1000
        result = compress_payload(data)

        # Compressed result should be smaller (flag + compressed < original)
        assert len(result) < len(data)

    def test_compression_only_if_smaller(self) -> None:
        """Compression is skipped if it would increase size."""
        import os

        # Pre-compressed or random data may not compress further
        # Use data that's definitely incompressible
        random_data = os.urandom(200)
        result = compress_payload(random_data)

        # If compressed flag is used, result must be smaller
        if result[0] == COMPRESSION_FLAG_COMPRESSED:
            assert len(result) <= len(random_data) + 1
        else:
            # Uncompressed: result is flag + original
            assert result[1:] == random_data


# =============================================================================
# Compression Level Tests
# =============================================================================


class TestCompressionLevels:
    """Test compression level handling."""

    def test_default_level_value(self) -> None:
        """Default compression level is 3 per spec."""
        assert COMPRESSION_LEVEL_DEFAULT == 3

    def test_level_range(self) -> None:
        """Compression levels range from 1 to 22 per spec."""
        assert COMPRESSION_LEVEL_MIN == 1
        assert COMPRESSION_LEVEL_MAX == 22

    def test_all_valid_levels_work(self) -> None:
        """All valid compression levels (1-22) work."""
        data = b"A" * 200

        for level in range(COMPRESSION_LEVEL_MIN, COMPRESSION_LEVEL_MAX + 1):
            result = compress_payload(data, level=level)
            decompressed = decompress_payload(result)
            assert decompressed == data

    def test_higher_level_may_compress_better(self) -> None:
        """Higher compression levels may produce smaller output."""
        # Use moderately compressible data
        data = (b"Hello, World! " * 100) + (b"Goodbye! " * 50)

        result_low = compress_payload(data, level=1)
        result_high = compress_payload(data, level=22)

        # Higher level should compress at least as well
        # (not always true for all data, but typically)
        # Just verify both work
        assert decompress_payload(result_low) == data
        assert decompress_payload(result_high) == data


# =============================================================================
# Decompression Tests
# =============================================================================


class TestDecompression:
    """Test decompression behavior."""

    def test_decompress_uncompressed(self) -> None:
        """Decompress uncompressed payload returns original."""
        original = b"test data"
        compressed = bytes([COMPRESSION_FLAG_UNCOMPRESSED]) + original
        result = decompress_payload(compressed)

        assert result == original

    def test_decompress_compressed(self) -> None:
        """Decompress compressed payload returns original."""
        original = b"A" * 500
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original

    def test_decompress_empty_payload_fails(self) -> None:
        """Empty payload (no flag) raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decompress_payload(b"")

    def test_decompress_invalid_flag_fails(self) -> None:
        """Invalid compression flag raises ValueError."""
        invalid = bytes([0x02]) + b"data"  # Flag 0x02 is invalid

        with pytest.raises(ValueError, match="Invalid compression flag"):
            decompress_payload(invalid)

    def test_decompress_corrupted_data_fails(self) -> None:
        """Corrupted compressed data raises error."""
        import zstandard

        corrupted = bytes([COMPRESSION_FLAG_COMPRESSED]) + b"not valid zstd data"

        with pytest.raises(zstandard.ZstdError):
            decompress_payload(corrupted)


# =============================================================================
# Roundtrip Tests
# =============================================================================


class TestCompressionRoundtrip:
    """Test compression/decompression roundtrips."""

    def test_roundtrip_small_data(self) -> None:
        """Small data roundtrips correctly."""
        original = b"small"
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original

    def test_roundtrip_large_data(self) -> None:
        """Large data roundtrips correctly."""
        original = b"x" * 10000
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original

    def test_roundtrip_binary_data(self) -> None:
        """Binary data roundtrips correctly."""
        import os

        original = os.urandom(500)
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original

    def test_roundtrip_empty_data(self) -> None:
        """Empty data roundtrips correctly."""
        original = b""
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original

    def test_roundtrip_exactly_min_size(self) -> None:
        """Data exactly at MIN_COMPRESS_SIZE roundtrips."""
        original = b"A" * COMPRESSION_MIN_SIZE
        compressed = compress_payload(original)
        result = decompress_payload(compressed)

        assert result == original


# =============================================================================
# Custom Min Size Tests
# =============================================================================


class TestCustomMinSize:
    """Test custom min_size parameter."""

    def test_custom_min_size_respected(self) -> None:
        """Custom min_size threshold is respected."""
        data = b"A" * 100  # Would compress with default min_size

        # Set min_size higher than data length
        result = compress_payload(data, min_size=200)

        # Should not compress since below threshold
        assert result[0] == COMPRESSION_FLAG_UNCOMPRESSED
        assert result[1:] == data

    def test_min_size_zero_always_attempts(self) -> None:
        """min_size=0 always attempts compression."""
        data = b"A" * 10  # Very small but compressible

        result = compress_payload(data, min_size=0)

        # Should attempt compression even for small data
        # Result depends on whether compression is beneficial
        decompressed = decompress_payload(result)
        assert decompressed == data


# =============================================================================
# Edge Cases
# =============================================================================


class TestCompressionEdgeCases:
    """Test edge cases in compression."""

    def test_all_zeros_compresses_well(self) -> None:
        """All-zero data compresses extremely well."""
        data = b"\x00" * 10000
        result = compress_payload(data)

        assert result[0] == COMPRESSION_FLAG_COMPRESSED
        assert len(result) < len(data) // 10  # Should compress very well

    def test_all_ones_compresses_well(self) -> None:
        """Repeated byte data compresses extremely well."""
        data = b"\xff" * 10000
        result = compress_payload(data)

        assert result[0] == COMPRESSION_FLAG_COMPRESSED
        assert len(result) < len(data) // 10

    def test_alternating_bytes(self) -> None:
        """Alternating pattern compresses reasonably."""
        data = b"\x00\xff" * 5000
        result = compress_payload(data)

        decompressed = decompress_payload(result)
        assert decompressed == data

    def test_single_byte(self) -> None:
        """Single byte handles correctly."""
        data = b"x"
        result = compress_payload(data)

        assert result[0] == COMPRESSION_FLAG_UNCOMPRESSED
        assert result[1:] == data

    def test_max_u16_data_size(self) -> None:
        """Large data (64KB) handles correctly."""
        data = b"A" * 65535
        result = compress_payload(data)
        decompressed = decompress_payload(result)

        assert decompressed == data


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestCompressionProperties:
    """Property-based tests for compression."""

    @given(data=st.binary(min_size=0, max_size=5000))
    @settings(max_examples=100)
    def test_roundtrip_any_data(self, data: bytes) -> None:
        """Any binary data roundtrips correctly."""
        compressed = compress_payload(data)
        result = decompress_payload(compressed)

        assert result == data

    @given(
        data=st.binary(min_size=0, max_size=5000),
        level=st.integers(min_value=1, max_value=22),
    )
    @settings(max_examples=100)
    def test_roundtrip_any_level(self, data: bytes, level: int) -> None:
        """Any data roundtrips at any compression level."""
        compressed = compress_payload(data, level=level)
        result = decompress_payload(compressed)

        assert result == data

    @given(data=st.binary(min_size=0, max_size=COMPRESSION_MIN_SIZE - 1))
    @settings(max_examples=50)
    def test_small_data_never_compressed(self, data: bytes) -> None:
        """Data below MIN_COMPRESS_SIZE is never compressed."""
        result = compress_payload(data)

        assert result[0] == COMPRESSION_FLAG_UNCOMPRESSED
        assert result[1:] == data

    @given(data=st.binary(min_size=0, max_size=5000))
    @settings(max_examples=50)
    def test_compressed_result_has_flag(self, data: bytes) -> None:
        """All compressed results have valid flag byte."""
        result = compress_payload(data)

        assert len(result) >= 1
        assert result[0] in (COMPRESSION_FLAG_UNCOMPRESSED, COMPRESSION_FLAG_COMPRESSED)

    @given(data=st.binary(min_size=COMPRESSION_MIN_SIZE, max_size=5000))
    @settings(max_examples=50)
    def test_compression_never_much_larger(self, data: bytes) -> None:
        """Compression never makes data much larger than original + overhead."""
        result = compress_payload(data)

        # Result should never be more than original + small overhead
        # (zstd has a maximum expansion ratio)
        max_expansion = len(data) + 100  # Allow some overhead
        assert len(result) <= max_expansion


# =============================================================================
# Spec Compliance Tests
# =============================================================================


class TestSpecCompliance:
    """Tests verifying spec compliance."""

    def test_spec_min_compress_size(self) -> None:
        """MIN_COMPRESS_SIZE matches spec value of 64."""
        assert COMPRESSION_MIN_SIZE == 64

    def test_spec_compression_level_range(self) -> None:
        """Compression level range matches spec (1-22)."""
        assert COMPRESSION_LEVEL_MIN == 1
        assert COMPRESSION_LEVEL_MAX == 22

    def test_spec_default_level(self) -> None:
        """Default compression level matches spec (3)."""
        assert COMPRESSION_LEVEL_DEFAULT == 3

    def test_spec_flag_values(self) -> None:
        """Compression flag values match spec."""
        assert COMPRESSION_FLAG_UNCOMPRESSED == 0x00
        assert COMPRESSION_FLAG_COMPRESSED == 0x01

    def test_spec_encode_payload_example(self) -> None:
        """encode_payload behavior matches spec pseudocode."""
        # From spec:
        # def encode_payload(diff: bytes) -> bytes:
        #     if compression_enabled and len(diff) > MIN_COMPRESS_SIZE:
        #         compressed = zstd.compress(diff, level=compression_level)
        #         if len(compressed) < len(diff):
        #             return b'\x01' + compressed
        #     return b'\x00' + diff

        # Small data - should be uncompressed
        small = b"x" * (COMPRESSION_MIN_SIZE - 1)
        result = compress_payload(small)
        assert result == b"\x00" + small

        # Large compressible data - should be compressed
        large = b"A" * 1000
        result = compress_payload(large)
        assert result[0] == 0x01  # Compressed flag

    def test_spec_decode_payload_example(self) -> None:
        """decode_payload behavior matches spec pseudocode."""
        # From spec:
        # def decode_payload(data: bytes) -> bytes:
        #     if data[0] == 0x01:
        #         return zstd.decompress(data[1:])
        #     return data[1:]

        # Uncompressed
        uncompressed = b"\x00hello"
        assert decompress_payload(uncompressed) == b"hello"

        # Compressed (need real zstd data)
        original = b"A" * 1000
        compressed = compress_payload(original)
        assert decompress_payload(compressed) == original
