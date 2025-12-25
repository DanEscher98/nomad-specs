# Tentacle: t3-sync
## Sync layer spec + tests

**Scope:** specs/3-SYNC.md, tests/protocol/test_sync*, tests/unit/test_diff*

**BLOCKED BY:** t6-vectors (need reference codec first)

## Tasks

### Spec Refinement
- [ ] Review/refine `specs/3-SYNC.md` for completeness
  - [ ] State versioning (sender_num, acked_num, base_num)
  - [ ] Idempotent diff application
  - [ ] Convergence guarantees
  - [ ] SyncState trait/interface requirements
  - [ ] Mermaid state machine diagrams

### Unit Tests (tests/unit/test_diff*.py)
- [ ] `test_diff_encode.py` - Diff encoding
  - [ ] Test against `tests/vectors/sync_vectors.json5`
  - [ ] Various diff types
- [ ] `test_diff_decode.py` - Diff decoding
  - [ ] Valid diff parsing
  - [ ] Malformed diff handling
- [ ] `test_diff_apply.py` - Idempotent application
  - [ ] Apply same diff twice = same result
  - [ ] Out-of-order application

### Protocol Tests (tests/protocol/test_sync*.py)
- [ ] `test_sync_flow.py` - Basic sync exchange
  - [ ] State update → ack cycle
  - [ ] Version number progression
- [ ] `test_sync_convergence.py` - Convergence properties
  - [ ] Both sides eventually agree
  - [ ] Packet loss recovery
  - [ ] Reordering tolerance
- [ ] `test_sync_edge_cases.py` - Edge cases
  - [ ] Empty state
  - [ ] Large state
  - [ ] Rapid updates

### Property Tests
- [ ] `test_sync_properties.py` - Hypothesis tests
  - [ ] Idempotency: apply(apply(state, diff), diff) == apply(state, diff)
  - [ ] Commutativity where applicable
  - [ ] Convergence under random packet loss

## Dependencies
- `tests/lib/reference.py` from t6-vectors
- `tests/vectors/sync_vectors.json5` from t6-vectors (need to create)

## Notes
- Sync layer is state-type agnostic (works with any SyncState impl)
- Tests use a simple "echo" state type for validation
- Consult `brainstorm/` for Mosh-inspired design
- Key insight: diffs must be idempotent for UDP reliability

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
