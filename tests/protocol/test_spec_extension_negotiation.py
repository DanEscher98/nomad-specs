"""
Extension negotiation protocol tests.

Tests the TLV extension encoding/decoding, extension list handling,
and negotiation logic per specs/4-EXTENSIONS.md.

Test mapping: specs/4-EXTENSIONS.md § "Extension Negotiation", "Extension Format (TLV)"
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lib.reference import (
    COMPRESSION_LEVEL_DEFAULT,
    EXT_COMPRESSION,
    EXT_HEADER_SIZE,
    EXT_MULTIPLEX,
    EXT_POST_QUANTUM,
    EXT_PREDICTION,
    EXT_SCROLLBACK,
    CompressionConfig,
    Extension,
    decode_compression_config,
    decode_extension,
    decode_extension_list,
    encode_compression_config,
    encode_extension,
    encode_extension_list,
    negotiate_extensions,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def compression_ext() -> Extension:
    """Create compression extension with default config."""
    config = CompressionConfig(level=COMPRESSION_LEVEL_DEFAULT)
    return Extension(ext_type=EXT_COMPRESSION, data=encode_compression_config(config))


@pytest.fixture
def scrollback_ext() -> Extension:
    """Create scrollback extension with max lines = 10000."""
    import struct

    data = struct.pack("<I", 10000)  # Max scrollback lines
    return Extension(ext_type=EXT_SCROLLBACK, data=data)


@pytest.fixture
def prediction_ext() -> Extension:
    """Create prediction extension with local echo enabled."""
    return Extension(ext_type=EXT_PREDICTION, data=bytes([0x01]))  # LOCAL_ECHO bit


# =============================================================================
# Single Extension Encoding Tests
# =============================================================================


class TestExtensionEncoding:
    """Test single extension TLV encoding."""

    def test_extension_header_size(self, compression_ext: Extension) -> None:
        """Extension header is 4 bytes (type + length)."""
        encoded = encode_extension(compression_ext)

        # Header: 2 bytes type + 2 bytes length
        assert len(encoded) == EXT_HEADER_SIZE + len(compression_ext.data)

    def test_extension_type_little_endian(self) -> None:
        """Extension type is encoded as LE16."""
        ext = Extension(ext_type=0x0102, data=b"")
        encoded = encode_extension(ext)

        # LE16: low byte first
        assert encoded[0] == 0x02
        assert encoded[1] == 0x01

    def test_extension_length_little_endian(self) -> None:
        """Extension length is encoded as LE16."""
        data = b"x" * 0x0304
        ext = Extension(ext_type=0x0001, data=data)
        encoded = encode_extension(ext)

        # Length at bytes 2-3, LE16
        assert encoded[2] == 0x04
        assert encoded[3] == 0x03

    def test_extension_data_preserved(self) -> None:
        """Extension data is preserved exactly."""
        original_data = b"\xde\xad\xbe\xef"
        ext = Extension(ext_type=EXT_COMPRESSION, data=original_data)
        encoded = encode_extension(ext)

        assert encoded[EXT_HEADER_SIZE:] == original_data

    def test_empty_data_extension(self) -> None:
        """Extension with empty data encodes correctly."""
        ext = Extension(ext_type=0x9999, data=b"")
        encoded = encode_extension(ext)

        assert len(encoded) == EXT_HEADER_SIZE
        assert encoded[2:4] == b"\x00\x00"  # Length = 0


class TestExtensionDecoding:
    """Test single extension TLV decoding."""

    def test_decode_compression_extension(self, compression_ext: Extension) -> None:
        """Decode compression extension correctly."""
        encoded = encode_extension(compression_ext)
        decoded, consumed = decode_extension(encoded)

        assert decoded.ext_type == EXT_COMPRESSION
        assert decoded.data == compression_ext.data
        assert consumed == len(encoded)

    def test_decode_with_offset(self) -> None:
        """Decode extension starting at offset."""
        prefix = b"garbage"
        ext = Extension(ext_type=0x1234, data=b"payload")
        encoded = encode_extension(ext)

        decoded, consumed = decode_extension(prefix + encoded, offset=len(prefix))

        assert decoded.ext_type == 0x1234
        assert decoded.data == b"payload"

    def test_decode_truncated_header_fails(self) -> None:
        """Truncated header raises ValueError."""
        truncated = b"\x01\x00\x02"  # Only 3 bytes, need 4

        with pytest.raises(ValueError, match="truncated"):
            decode_extension(truncated)

    def test_decode_truncated_data_fails(self) -> None:
        """Truncated data raises ValueError."""
        # Header says 10 bytes of data, but only 5 provided
        malformed = b"\x01\x00\x0a\x00\x01\x02\x03\x04\x05"

        with pytest.raises(ValueError, match="truncated"):
            decode_extension(malformed)

    def test_decode_returns_consumed_bytes(self) -> None:
        """Decode returns correct number of consumed bytes."""
        ext = Extension(ext_type=0x0001, data=b"12345678")
        encoded = encode_extension(ext)

        _, consumed = decode_extension(encoded)

        assert consumed == EXT_HEADER_SIZE + 8


# =============================================================================
# Extension List Encoding/Decoding Tests
# =============================================================================


class TestExtensionListEncoding:
    """Test multiple extension encoding."""

    def test_empty_list_encodes_to_empty(self) -> None:
        """Empty extension list encodes to empty bytes."""
        encoded = encode_extension_list([])

        assert encoded == b""

    def test_single_extension_list(self, compression_ext: Extension) -> None:
        """Single extension list matches single encoding."""
        single = encode_extension(compression_ext)
        list_encoded = encode_extension_list([compression_ext])

        assert list_encoded == single

    def test_multiple_extensions_concatenated(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
        prediction_ext: Extension,
    ) -> None:
        """Multiple extensions are concatenated."""
        extensions = [compression_ext, scrollback_ext, prediction_ext]
        encoded = encode_extension_list(extensions)

        expected = (
            encode_extension(compression_ext)
            + encode_extension(scrollback_ext)
            + encode_extension(prediction_ext)
        )
        assert encoded == expected

    def test_extension_order_preserved(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
    ) -> None:
        """Extension order is preserved in encoding."""
        # Order A
        encoded_a = encode_extension_list([compression_ext, scrollback_ext])
        decoded_a = decode_extension_list(encoded_a)

        assert decoded_a[0].ext_type == EXT_COMPRESSION
        assert decoded_a[1].ext_type == EXT_SCROLLBACK

        # Order B
        encoded_b = encode_extension_list([scrollback_ext, compression_ext])
        decoded_b = decode_extension_list(encoded_b)

        assert decoded_b[0].ext_type == EXT_SCROLLBACK
        assert decoded_b[1].ext_type == EXT_COMPRESSION


class TestExtensionListDecoding:
    """Test multiple extension decoding."""

    def test_empty_bytes_decodes_to_empty_list(self) -> None:
        """Empty bytes decodes to empty list."""
        decoded = decode_extension_list(b"")

        assert decoded == []

    def test_decode_multiple_extensions(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
    ) -> None:
        """Multiple extensions decode correctly."""
        encoded = encode_extension_list([compression_ext, scrollback_ext])
        decoded = decode_extension_list(encoded)

        assert len(decoded) == 2
        assert decoded[0].ext_type == compression_ext.ext_type
        assert decoded[0].data == compression_ext.data
        assert decoded[1].ext_type == scrollback_ext.ext_type
        assert decoded[1].data == scrollback_ext.data

    def test_decode_malformed_in_list_fails(self) -> None:
        """Malformed extension in list raises ValueError."""
        # Valid extension followed by truncated one
        valid = encode_extension(Extension(ext_type=0x0001, data=b"ok"))
        truncated = b"\x02\x00\xff\x00"  # Claims 255 bytes but has none

        with pytest.raises(ValueError, match="truncated"):
            decode_extension_list(valid + truncated)


# =============================================================================
# Extension Negotiation Tests
# =============================================================================


class TestExtensionNegotiation:
    """Test extension negotiation logic."""

    def test_negotiate_empty_offered(
        self,
        compression_ext: Extension,
    ) -> None:
        """Empty offered list results in empty negotiated."""
        negotiated = negotiate_extensions(offered=[], supported=[compression_ext])

        assert negotiated == []

    def test_negotiate_empty_supported(
        self,
        compression_ext: Extension,
    ) -> None:
        """Empty supported list results in empty negotiated."""
        negotiated = negotiate_extensions(offered=[compression_ext], supported=[])

        assert negotiated == []

    def test_negotiate_full_intersection(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
    ) -> None:
        """Full intersection returns all offered."""
        extensions = [compression_ext, scrollback_ext]
        negotiated = negotiate_extensions(offered=extensions, supported=extensions)

        assert len(negotiated) == 2

    def test_negotiate_partial_intersection(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
        prediction_ext: Extension,
    ) -> None:
        """Partial intersection returns only mutual support."""
        offered = [compression_ext, scrollback_ext, prediction_ext]
        supported = [compression_ext, prediction_ext]  # No scrollback

        negotiated = negotiate_extensions(offered=offered, supported=supported)

        assert len(negotiated) == 2
        types = [ext.ext_type for ext in negotiated]
        assert EXT_COMPRESSION in types
        assert EXT_PREDICTION in types
        assert EXT_SCROLLBACK not in types

    def test_negotiate_preserves_offered_order(
        self,
        compression_ext: Extension,
        scrollback_ext: Extension,
        prediction_ext: Extension,
    ) -> None:
        """Negotiation preserves order from offered list."""
        offered = [prediction_ext, scrollback_ext, compression_ext]
        supported = [compression_ext, scrollback_ext, prediction_ext]

        negotiated = negotiate_extensions(offered=offered, supported=supported)

        # Order should match offered, not supported
        assert negotiated[0].ext_type == EXT_PREDICTION
        assert negotiated[1].ext_type == EXT_SCROLLBACK
        assert negotiated[2].ext_type == EXT_COMPRESSION

    def test_unknown_extension_ignored(
        self,
        compression_ext: Extension,
    ) -> None:
        """Unknown extension types are ignored (forward compatibility)."""
        unknown = Extension(ext_type=0xFFFF, data=b"future")
        offered = [compression_ext, unknown]
        supported = [compression_ext]  # Doesn't know about 0xFFFF

        negotiated = negotiate_extensions(offered=offered, supported=supported)

        assert len(negotiated) == 1
        assert negotiated[0].ext_type == EXT_COMPRESSION


# =============================================================================
# Compression Config Tests
# =============================================================================


class TestCompressionConfig:
    """Test compression extension configuration."""

    def test_encode_default_level(self) -> None:
        """Default compression level encodes correctly."""
        config = CompressionConfig()
        encoded = encode_compression_config(config)

        assert len(encoded) == 2
        assert encoded[0] == COMPRESSION_LEVEL_DEFAULT
        assert encoded[1] == 0  # Reserved

    def test_encode_custom_level(self) -> None:
        """Custom compression level encodes correctly."""
        config = CompressionConfig(level=15)
        encoded = encode_compression_config(config)

        assert encoded[0] == 15

    def test_decode_compression_config(self) -> None:
        """Compression config decodes correctly."""
        config = CompressionConfig(level=10)
        encoded = encode_compression_config(config)
        decoded = decode_compression_config(encoded)

        assert decoded.level == 10

    def test_decode_ignores_reserved(self) -> None:
        """Reserved byte is ignored when decoding."""
        # Level 5, reserved = 0xFF (should be ignored)
        data = bytes([5, 0xFF])
        decoded = decode_compression_config(data)

        assert decoded.level == 5

    def test_invalid_level_rejected(self) -> None:
        """Invalid compression level is rejected."""
        with pytest.raises(ValueError, match="Compression level"):
            CompressionConfig(level=0)  # Below min

        with pytest.raises(ValueError, match="Compression level"):
            CompressionConfig(level=23)  # Above max


# =============================================================================
# Extension Validation Tests
# =============================================================================


class TestExtensionValidation:
    """Test extension dataclass validation."""

    def test_valid_extension_type_range(self) -> None:
        """Valid extension types (0-65535) are accepted."""
        Extension(ext_type=0, data=b"")
        Extension(ext_type=0xFFFF, data=b"")

    def test_invalid_extension_type_rejected(self) -> None:
        """Invalid extension types are rejected."""
        with pytest.raises(ValueError, match="Extension type"):
            Extension(ext_type=-1, data=b"")

        with pytest.raises(ValueError, match="Extension type"):
            Extension(ext_type=0x10000, data=b"")

    def test_oversized_data_rejected(self) -> None:
        """Data > 65535 bytes is rejected."""
        with pytest.raises(ValueError, match="too large"):
            Extension(ext_type=1, data=b"x" * 0x10000)


# =============================================================================
# Property-Based Tests
# =============================================================================


# Strategies for property-based testing
ext_type_strategy = st.integers(min_value=0, max_value=0xFFFF)
ext_data_strategy = st.binary(min_size=0, max_size=1000)


@st.composite
def extension_strategy(draw: st.DrawFn) -> Extension:
    """Generate random valid extensions."""
    ext_type = draw(ext_type_strategy)
    data = draw(ext_data_strategy)
    return Extension(ext_type=ext_type, data=data)


class TestExtensionProperties:
    """Property-based tests for extension encoding."""

    @given(ext=extension_strategy())
    @settings(max_examples=100)
    def test_extension_roundtrip(self, ext: Extension) -> None:
        """Encoding then decoding returns original extension."""
        encoded = encode_extension(ext)
        decoded, consumed = decode_extension(encoded)

        assert decoded.ext_type == ext.ext_type
        assert decoded.data == ext.data
        assert consumed == len(encoded)

    @given(extensions=st.lists(extension_strategy(), min_size=0, max_size=10))
    @settings(max_examples=50)
    def test_extension_list_roundtrip(self, extensions: list[Extension]) -> None:
        """Extension list roundtrips correctly."""
        encoded = encode_extension_list(extensions)
        decoded = decode_extension_list(encoded)

        assert len(decoded) == len(extensions)
        for orig, dec in zip(extensions, decoded, strict=True):
            assert dec.ext_type == orig.ext_type
            assert dec.data == orig.data

    @given(ext=extension_strategy())
    @settings(max_examples=50)
    def test_extension_length_field_correct(self, ext: Extension) -> None:
        """Extension length field matches actual data length."""
        import struct

        encoded = encode_extension(ext)
        length = struct.unpack_from("<H", encoded, 2)[0]

        assert length == len(ext.data)

    @given(
        offered=st.lists(extension_strategy(), min_size=0, max_size=5),
        supported=st.lists(extension_strategy(), min_size=0, max_size=5),
    )
    @settings(max_examples=50)
    def test_negotiation_subset_of_offered(
        self,
        offered: list[Extension],
        supported: list[Extension],
    ) -> None:
        """Negotiated extensions are always subset of offered."""
        negotiated = negotiate_extensions(offered, supported)

        offered_types = {ext.ext_type for ext in offered}
        for ext in negotiated:
            assert ext.ext_type in offered_types

    @given(level=st.integers(min_value=1, max_value=22))
    @settings(max_examples=22)
    def test_compression_config_roundtrip(self, level: int) -> None:
        """Compression config roundtrips for all valid levels."""
        config = CompressionConfig(level=level)
        encoded = encode_compression_config(config)
        decoded = decode_compression_config(encoded)

        assert decoded.level == level


# =============================================================================
# Defined Extension Type Tests
# =============================================================================


class TestDefinedExtensionTypes:
    """Test defined extension type values match spec."""

    def test_compression_type(self) -> None:
        """Compression extension is 0x0001."""
        assert EXT_COMPRESSION == 0x0001

    def test_scrollback_type(self) -> None:
        """Scrollback extension is 0x0002."""
        assert EXT_SCROLLBACK == 0x0002

    def test_prediction_type(self) -> None:
        """Prediction extension is 0x0003."""
        assert EXT_PREDICTION == 0x0003

    def test_multiplex_type(self) -> None:
        """Multiplex extension is 0x0004."""
        assert EXT_MULTIPLEX == 0x0004

    def test_post_quantum_type(self) -> None:
        """PostQuantum extension is 0x0005."""
        assert EXT_POST_QUANTUM == 0x0005
