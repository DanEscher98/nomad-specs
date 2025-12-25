# Tentacle: t2-transport
## Transport layer spec + tests

**Scope:** specs/2-TRANSPORT.md, tests/unit/test_frame*, tests/wire/*

**BLOCKED BY:** t6-vectors (need reference codec first)

## Tasks

### Spec Refinement
- [ ] Review/refine `specs/2-TRANSPORT.md` for completeness
  - [ ] Frame format (header + encrypted payload)
  - [ ] Session ID format (6 bytes)
  - [ ] Nonce counter (8 bytes little-endian)
  - [ ] Frame types (Data, Keepalive, Nomad)
  - [ ] MTU considerations
  - [ ] Mermaid packet diagrams

### Unit Tests (tests/unit/test_frame*.py)
- [ ] `test_frame_encode.py` - Frame encoding
  - [ ] Test against `tests/vectors/frame_vectors.json5`
  - [ ] Header construction
  - [ ] Payload encryption
- [ ] `test_frame_decode.py` - Frame decoding
  - [ ] Valid frame parsing
  - [ ] Invalid frame rejection
  - [ ] Truncated frame handling
- [ ] `test_frame_types.py` - Frame type handling
  - [ ] Data frames
  - [ ] Keepalive frames
  - [ ] Nomad (IP migration) frames

### Wire Tests (tests/wire/*.py)
- [ ] `test_wire_format.py` - Byte-level validation
  - [ ] Endianness compliance
  - [ ] Field offsets
  - [ ] Size constraints
- [ ] `test_wire_malformed.py` - Malformed packet handling
  - [ ] Too short
  - [ ] Invalid type byte
  - [ ] Bad AEAD tag

### Protocol Tests
- [ ] `test_keepalive.py` - Keepalive mechanism
  - [ ] Timeout detection
  - [ ] Keepalive response
- [ ] `test_nomad.py` - IP migration (nomading)
  - [ ] Client IP change
  - [ ] Session continuity

## Dependencies
- `tests/lib/reference.py` from t6-vectors
- `tests/vectors/frame_vectors.json5` from t6-vectors

## Notes
- All multi-byte integers are little-endian
- Frame header is authenticated but not encrypted (session ID visible)
- Use scapy for packet inspection in wire tests
- Use hypothesis for property-based fuzz testing

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
