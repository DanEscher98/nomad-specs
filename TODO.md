# Tentacle: t2-transport
## Transport layer spec + tests

**Scope:** specs/2-TRANSPORT.md, tests/unit/test_frame*, tests/wire/*

**BLOCKED BY:** ~~t6-vectors~~ (RESOLVED - reference codec available)

## Tasks

### Spec Refinement
- [x] Review/refine `specs/2-TRANSPORT.md` for completeness
  - [x] Frame format (header + encrypted payload)
  - [x] Session ID format (6 bytes)
  - [x] Nonce counter (8 bytes little-endian)
  - [x] Frame types (Data, Keepalive, Nomad)
  - [x] MTU considerations
  - [x] Mermaid packet diagrams

### Unit Tests (tests/unit/test_frame*.py)
- [x] `test_frame_encode.py` - Frame encoding (20 tests)
  - [x] Test against `tests/vectors/frame_vectors.json5`
  - [x] Header construction
  - [x] Payload encryption
- [x] `test_frame_decode.py` - Frame decoding (30 tests)
  - [x] Valid frame parsing
  - [x] Invalid frame rejection
  - [x] Truncated frame handling
- [x] `test_frame_types.py` - Frame type handling (34 tests)
  - [x] Data frames
  - [x] Keepalive frames
  - [x] Nonce/Direction/Epoch handling

### Wire Tests (tests/wire/*.py)
- [x] `test_wire_format.py` - Byte-level validation (39 tests)
  - [x] Endianness compliance
  - [x] Field offsets
  - [x] Size constraints
  - [x] MTU compliance
- [x] `test_wire_malformed.py` - Malformed packet handling (40 tests)
  - [x] Too short
  - [x] Invalid type byte
  - [x] Bad AEAD tag
  - [x] Fuzz testing with hypothesis

### Protocol Tests (tests/protocol/*.py)
- [x] `test_keepalive.py` - Keepalive mechanism (18 tests)
  - [x] Frame format (ACK_ONLY flag)
  - [x] Timing constants
  - [x] Security properties
- [x] `test_nomad.py` - IP migration/roaming (20 tests)
  - [x] Migration detection
  - [x] Address validation
  - [x] Anti-amplification (3x limit)
  - [x] Session continuity
  - [x] Security properties

## Test Summary
- **Total Tests:** 201
- **Unit tests:** 84
- **Wire tests:** 79
- **Protocol tests:** 38

## Dependencies
- `tests/lib/reference.py` from t6-vectors (AVAILABLE)
- `tests/vectors/frame_vectors.json5` from t6-vectors (AVAILABLE)

## Notes
- All multi-byte integers are little-endian
- Frame header is authenticated but not encrypted (session ID visible)
- Use hypothesis for property-based fuzz testing
- All tests pass with ruff lint checks clean

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
