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

---

## Phase 2: E2E Tests (DOCKER REQUIRED)

**Status:** COMPLETE

> Phase 1 tests validate the Python reference codec against test vectors.
> Phase 2 tests validate real implementations in Docker containers.

**Prerequisites:**
- Use fixtures from `tests/conftest.py`: `server_container`, `client_container`, `packet_capture`
- Container management via `tests/lib/containers.py` (ContainerManager)
- Network utilities via `tests/lib/network.py` (scapy helpers)
- Test keypairs configured in `tests/lib/containers.py`
- Use `container_manager.wait_for_health()` to detect crashes
- Mark tests with `@pytest.mark.container`

### E2E Wire Tests
- [x] `test_wire_format_e2e.py` - Capture real packets from containers
  - [x] Verify header size (16 bytes)
  - [x] Verify type byte offset (0)
  - [x] Verify flags byte offset (1)
  - [x] Verify session ID offset (2-7)
  - [x] Verify nonce counter offset (8-15, LE64)
  - [x] Verify frame header is plaintext (session ID visible)
  - [x] MTU compliance tests
  - [x] Traffic pattern validation (bidirectional, consistent session ID, nonce increases)
- [x] `test_wire_malformed_e2e.py` - Send malformed packets to real server
  - [x] Truncated frame handling (empty, single byte, header-only, partial tag)
  - [x] Invalid type byte rejection
  - [x] Invalid AEAD tag rejection (corrupted, zeroed, random)
  - [x] Unknown session ID rejection
  - [x] Fuzz testing with random data
  - [x] Header corruption (AAD modification)
  - [x] Flood resistance

### E2E Protocol Tests
- [x] `test_keepalive_e2e.py` - Keepalive mechanism with real containers
  - [x] Keepalive is Data frame (type 0x03)
  - [x] ACK_ONLY flag set
  - [x] Minimal frame size (empty diff)
  - [x] Session survives idle periods
  - [x] Bidirectional traffic validation
  - [x] Timestamp/nonce increase validation
  - [x] Connection health checks
- [x] `test_nomad_e2e.py` - IP migration/roaming with real containers
  - [x] Session ID continuity
  - [x] Nonce counter continuity
  - [x] Session survives short interruption
  - [x] Invalid migration attempts rejected
  - [x] Anti-amplification (3x limit) enforcement
  - [x] Migration security properties

### Adversarial Tests
- [x] `test_transport_attacks.py` - Security attack testing
  - [x] Frame injection attacks (forged frames, corrupted tags)
  - [x] Session ID enumeration (random probes, sequential scan)
  - [x] Nonce manipulation (replay window, large/zero counters)
  - [x] Amplification attacks (spoofed source, limited response)
  - [x] Replay attacks (duplicate frames)
  - [x] Header manipulation (flags, type downgrade)
  - [x] Fuzz testing (random data, all byte values, structured fuzz)
  - [x] Resource exhaustion (rapid flood, large frames, many session IDs)

## Test Summary
- **Total Phase 1 Tests:** 201
- **Unit tests:** 84
- **Wire tests:** 79
- **Protocol tests:** 38

**Phase 2 E2E Tests (NEW):**
- **Wire E2E:** ~20 tests
- **Malformed E2E:** ~25 tests
- **Keepalive E2E:** ~12 tests
- **Nomad E2E:** ~15 tests
- **Adversarial:** ~30 tests
- **Total Phase 2:** ~100+ tests

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
