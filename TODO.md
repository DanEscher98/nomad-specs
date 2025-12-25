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

**Status:** IN PROGRESS

> Phase 1 tests validate the Python reference codec and simulated sync logic.
> Phase 2 tests validate real implementations in Docker containers.

**Prerequisites:**
- Use fixtures from `tests/conftest.py`: `server_container`, `client_container`, `packet_capture`
- Container management via `tests/lib/containers.py` (ContainerManager)
- Network chaos via `tests/lib/chaos.py` (NetworkChaos with pumba/tc netem)
- Test keypairs configured in `tests/lib/containers.py`
- Use `container_manager.check_container_health()` to detect crashes
- Mark tests with `@pytest.mark.container`

### Wire Tests
- [x] Add `tests/wire/test_sync_wire.py` - Byte-level sync validation (14 tests)
  - [x] Capture sync messages on wire (TestSyncMessageWireFormat)
  - [x] Validate data frame header layout (type, flags, session_id, nonce)
  - [x] Verify session ID consistency across frames
  - [x] Verify nonce counter monotonicity
  - [x] Validate little-endian encoding (TestLittleEndianEncoding)
  - [x] Verify encrypted payload minimum size
  - [x] Test vector validation (TestWireVectorValidation)
  - [x] Binary diff preservation (TestBinaryDiffPayload)
  - [x] Empty diff encoding (TestEmptyDiff)

### Resilience Tests
- [x] Add `tests/protocol/test_sync_resilience.py` - Network chaos (19 tests)
  - [x] Packet loss tests (10%, 30%, 50%) - TestPacketLoss
  - [x] Asymmetric loss handling
  - [x] High latency tests (100ms, 500ms) - TestHighLatency
  - [x] Variable jitter handling
  - [x] Packet reordering tests - TestPacketReordering
  - [x] Packet duplication tests - TestPacketDuplication
  - [x] Combined chaos (loss + delay) - TestCombinedChaos
  - [x] Network partition tests - TestNetworkPartition
  - [x] Convergence timing measurement - TestConvergenceTiming
  - [x] Stress tests (extended loss, chaos cycling) - TestNetworkStress

### E2E Protocol Tests (PENDING)
- [ ] Refactor `test_sync_flow.py` for E2E
  - [ ] Test state sync with real server+client containers
  - [ ] Send state updates from client, verify server receives
  - [ ] Verify version number progression on wire
- [ ] Refactor `test_sync_convergence.py` for E2E
  - [ ] Test convergence with real packet loss (tc netem)
  - [ ] Verify idempotent diff application after retransmits
  - [ ] Measure convergence time under various loss rates

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
