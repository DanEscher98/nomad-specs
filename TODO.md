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
