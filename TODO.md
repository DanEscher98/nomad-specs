# Tentacle: t7-resilience
## Network stress and resilience testing

**Scope:** tests/resilience/*, tests/lib/chaos.py, docker/docker-compose.yml

## Tasks

### Infrastructure
- [ ] Create `tests/resilience/__init__.py`
- [ ] Create `tests/lib/chaos.py` - NetworkChaos helper class
  - [ ] `apply_loss(container, percent)` - using pumba/netem
  - [ ] `apply_delay(container, ms, jitter_ms)`
  - [ ] `apply_reorder(container, percent, gap)`
  - [ ] `partition(container_a, container_b, duration)`
- [ ] Extend `docker/docker-compose.yml` with chaos profiles:
  - [ ] `chaos-loss-30` (30% packet loss)
  - [ ] `chaos-loss-50` (50% packet loss)
  - [ ] `chaos-reorder` (packet reordering)
  - [ ] `chaos-duplicate` (packet duplication)
- [ ] Add `@pytest.fixture def chaos()` to conftest.py

### Test Files (7 files)
- [ ] `tests/resilience/test_packet_loss.py`
  - [ ] 10% loss - sync converges
  - [ ] 30% loss - sync converges
  - [ ] **50% loss - sync converges within 10s** (MUST PASS)
- [ ] `tests/resilience/test_latency.py`
  - [ ] 100ms delay - session stable
  - [ ] **500ms delay - session stable** (MUST PASS)
  - [ ] Variable delay (100-500ms) - session stable
- [ ] `tests/resilience/test_jitter.py`
  - [ ] High jitter (±100ms) - no duplicate application
  - [ ] Extreme jitter (±300ms) - sync recovers
- [ ] `tests/resilience/test_reordering.py`
  - [ ] Out-of-order delivery - idempotent diffs handle
  - [ ] Verify no duplicate state application
- [ ] `tests/resilience/test_duplication.py`
  - [ ] Duplicate packets - handled gracefully
  - [ ] Triple duplication - still works
- [ ] `tests/resilience/test_partition.py`
  - [ ] **5s network partition - session recovers** (MUST PASS)
  - [ ] 10s partition - session recovers
  - [ ] Partition during active transfer - no data loss
- [ ] `tests/resilience/test_roaming.py`
  - [ ] IP migration during transfer - no data loss
  - [ ] Rapid IP changes (every 2s) - session stable
  - [ ] Migration under 50% loss - works

## Dependencies
- Docker with tc/netem support
- pumba container for chaos injection
- tests/lib/reference.py from t6

## Success Criteria
- [ ] Tests pass with **50% packet loss**
- [ ] Session survives 5s network partition
- [ ] IP migration works under load
- [ ] No duplicate state application on reordering
- [ ] 500ms latency doesn't break sync

## Notes
- Use pumba (gaiaadm/pumba) for netem manipulation
- Test pattern: apply chaos → send updates → verify convergence
- Sync should converge via idempotent diffs (no retransmit logic needed)
- All tests use @pytest.mark.resilience marker

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
