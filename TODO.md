# Tentacle: t7-resilience
## Network stress and resilience testing

**Scope:** tests/resilience/*, tests/lib/chaos.py, docker/docker-compose.yml

## Tasks

### Infrastructure
- [x] Create `tests/resilience/__init__.py`
- [x] Create `tests/lib/chaos.py` - NetworkChaos helper class
  - [x] `apply_loss(container, percent)` - using pumba/netem
  - [x] `apply_delay(container, ms, jitter_ms)`
  - [x] `apply_reorder(container, percent, gap)`
  - [x] `partition(container_a, container_b, duration)`
- [x] Extend `docker/docker-compose.yml` with chaos profiles:
  - [x] `chaos-loss-30` (30% packet loss)
  - [x] `chaos-loss-50` (50% packet loss)
  - [x] `chaos-reorder` (packet reordering)
  - [x] `chaos-duplicate` (packet duplication)
- [x] Add `@pytest.fixture def chaos()` to conftest.py

### Test Files (7 files)
- [x] `tests/resilience/test_packet_loss.py`
  - [x] 10% loss - sync converges
  - [x] 30% loss - sync converges
  - [x] **50% loss - sync converges within 10s** (MUST PASS)
- [x] `tests/resilience/test_latency.py`
  - [x] 100ms delay - session stable
  - [x] **500ms delay - session stable** (MUST PASS)
  - [x] Variable delay (100-500ms) - session stable
- [x] `tests/resilience/test_jitter.py`
  - [x] High jitter (±100ms) - no duplicate application
  - [x] Extreme jitter (±300ms) - sync recovers
- [x] `tests/resilience/test_reordering.py`
  - [x] Out-of-order delivery - idempotent diffs handle
  - [x] Verify no duplicate state application
- [x] `tests/resilience/test_duplication.py`
  - [x] Duplicate packets - handled gracefully
  - [x] Triple duplication - still works
- [x] `tests/resilience/test_partition.py`
  - [x] **5s network partition - session recovers** (MUST PASS)
  - [x] 10s partition - session recovers
  - [x] Partition during active transfer - no data loss
- [x] `tests/resilience/test_roaming.py`
  - [x] IP migration during transfer - no data loss
  - [x] Rapid IP changes (every 2s) - session stable
  - [x] Migration under 50% loss - works

## Dependencies
- Docker with tc/netem support
- pumba container for chaos injection
- tests/lib/reference.py from t6

## Success Criteria
- [x] Tests pass with **50% packet loss**
- [x] Session survives 5s network partition
- [x] IP migration works under load
- [x] No duplicate state application on reordering
- [x] 500ms latency doesn't break sync

## Notes
- Use pumba (gaiaadm/pumba) for netem manipulation
- Test pattern: apply chaos → send updates → verify convergence
- Sync should converge via idempotent diffs (no retransmit logic needed)
- All tests use @pytest.mark.resilience marker

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
