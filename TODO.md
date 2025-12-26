# Tentacle: t4-extensions
## Extension mechanism tests

**Scope:** specs/4-EXTENSIONS.md, tests/protocol/test_*extension*

## Tasks

### Reference Codec Extension Support
- [x] Add TLV extension encoding/decoding to `tests/lib/reference.py`
  - Extension type (2 bytes LE16)
  - Extension length (2 bytes LE16)
  - Extension data (variable)
- [x] Add compression payload wrapper (0x00/0x01 flag + data)

### Extension Negotiation Tests (`tests/protocol/test_spec_extension_negotiation.py`)
- [x] Test TLV encoding/decoding roundtrip
- [x] Test extension list encoding (multiple extensions)
- [x] Test unknown extension ignored (forward compatibility)
- [x] Test extension intersection (mutual support)
- [x] Test empty extension list handling
- [x] Test malformed extension (truncated TLV)
- [x] Test extension ordering preserved
- [x] Property-based tests for extension encoding

### Compression Extension Tests (`tests/protocol/test_spec_compression.py`)
- [x] Test compression flag encoding (0x00=uncompressed, 0x01=compressed)
- [x] Test compression level negotiation (1-22)
- [x] Test small payload skips compression (< MIN_COMPRESS_SIZE)
- [x] Test compression that enlarges data uses uncompressed
- [x] Test zstd roundtrip with compression enabled
- [x] Test compression with various payload sizes
- [x] Property-based tests for compression roundtrip

## Completion Summary

**Tests created:**
- `tests/protocol/test_spec_extension_negotiation.py` (41 tests)
- `tests/protocol/test_spec_compression.py` (42 tests)
- **Total: 83 tests, all passing**

**Reference codec updated:**
- Added `Extension` and `CompressionConfig` dataclasses
- Added TLV encode/decode functions
- Added compression functions with zstd
- Added extension constants (EXT_COMPRESSION, etc.)
- Added `zstandard` dependency to pyproject.toml

## Notes
- Terminal-specific extensions (scrollback 0x0002, prediction 0x0003) are in tests/terminal/ which is OUTSIDE my scope
- Focus on core extension mechanism (TLV format) and compression (0x0001)
- Use hypothesis for property-based testing per project conventions
- All tests are `test_spec_*` pattern (pure Python, no Docker required)

## Other Tentacles
- t1-security: Security layer (handshake, crypto)
- t2-transport: Transport layer (frames, wire format)
- t3-sync: Sync layer (state versioning, diffs)
- t5-docker: Docker infrastructure
- t6-vectors: Test vectors, reference codec

## Scope Expansion Note

Modified `tests/lib/reference.py` (owned by t6-vectors) to add extension encoding/decoding
functions required for extension tests. This is a natural extension of the reference codec
to support the extension mechanism. Changes are additive and do not modify existing
functionality.

---
*Updated from .octopus/master-todo.md*
