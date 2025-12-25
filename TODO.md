# Tentacle: t3-sync
## Sync layer spec + tests

**Scope:** specs/3-SYNC.md, tests/protocol/test_sync*, tests/unit/test_diff*

**STATUS:** UNBLOCKED (t6-vectors merged)

## Tasks

### Spec Refinement
- [x] Review/refine `specs/3-SYNC.md` for completeness
  - [x] State versioning (sender_num, acked_num, base_num)
  - [x] Idempotent diff application
  - [x] Convergence guarantees
  - [x] SyncState trait/interface requirements
  - [x] Mermaid state machine diagrams (added stateDiagram-v2)

### Unit Tests (tests/unit/test_diff*.py)
- [x] `test_diff_encode.py` - Diff encoding
  - [x] Test against `tests/vectors/sync_vectors.json5`
  - [x] Various diff types
- [x] `test_diff_decode.py` - Diff decoding
  - [x] Valid diff parsing
  - [x] Malformed diff handling
- [x] `test_diff_apply.py` - Idempotent application
  - [x] Apply same diff twice = same result
  - [x] Out-of-order application

### Protocol Tests (tests/protocol/test_sync*.py)
- [x] `test_sync_flow.py` - Basic sync exchange
  - [x] State update → ack cycle
  - [x] Version number progression
- [x] `test_sync_convergence.py` - Convergence properties
  - [x] Both sides eventually agree
  - [x] Packet loss recovery
  - [x] Reordering tolerance
- [x] `test_sync_edge_cases.py` - Edge cases
  - [x] Empty state
  - [x] Large state
  - [x] Rapid updates

### Property Tests
- [x] `test_sync_properties.py` - Hypothesis tests
  - [x] Idempotency: apply(apply(state, diff), diff) == apply(state, diff)
  - [x] Commutativity where applicable
  - [x] Convergence under random packet loss

---

## Phase 2: E2E Tests (DOCKER REQUIRED)

**Status:** NOT STARTED

> Phase 1 tests validate the Python reference codec and simulated sync logic.
> Phase 2 tests validate real implementations in Docker containers.

**Prerequisites:**
- Use fixtures from `tests/conftest.py`: `server_container`, `client_container`, `packet_capture`
- Container management via `tests/lib/containers.py` (ContainerManager)
- Test keypairs configured in `tests/lib/containers.py`
- Use `container_manager.check_container_health()` to detect crashes
- Mark tests with `@pytest.mark.container`

### E2E Protocol Tests
- [ ] Refactor `test_sync_flow.py` for E2E
  - [ ] Test state sync with real server+client containers
  - [ ] Send state updates from client, verify server receives
  - [ ] Verify version number progression on wire
- [ ] Refactor `test_sync_convergence.py` for E2E
  - [ ] Test convergence with real packet loss (tc netem)
  - [ ] Verify idempotent diff application after retransmits
  - [ ] Measure convergence time under various loss rates

### Wire Tests (NEW)
- [ ] Add `test_sync_wire.py` - Byte-level sync validation
  - [ ] Capture sync messages on wire
  - [ ] Validate byte format (sender_num, acked_num, base_num, diff)
  - [ ] Verify little-endian encoding of all fields

### Resilience Tests
- [ ] Add `test_sync_resilience.py` - Network chaos with real containers
  - [ ] Test sync under 10%, 30%, 50% packet loss
  - [ ] Test sync with high latency (500ms)
  - [ ] Test sync with packet reordering

## Dependencies
- [x] `tests/lib/reference.py` from t6-vectors
- [x] `tests/vectors/sync_vectors.json5` from t6-vectors

## Notes
- Sync layer is state-type agnostic (works with any SyncState impl)
- Tests use a simple "echo" state type for validation
- Consult `brainstorm/` for Mosh-inspired design
- Key insight: diffs must be idempotent for UDP reliability

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
