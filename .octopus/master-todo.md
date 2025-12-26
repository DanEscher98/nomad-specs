# Master Todo - Nomad Conformance Suite

## Test Phases

> **Phase 1:** Unit tests against Python reference codec (NO DOCKER)
> **Phase 2:** E2E tests against real implementations in Docker containers

All `tests/unit/` tests are Phase 1 (Python-to-Python).
All other test directories (`protocol/`, `wire/`, `adversarial/`, `resilience/`) are Phase 2 (Docker required).

---

## Active Tentacles (ready to spawn)

None - all tentacles merged for Phase 1.

## Pending Tentacles

| ID | Description | Blocked By |
|----|-------------|------------|
| t4-extensions | Extension mechanism | Phase 2 validation |

## Completed Tentacles

| ID | Merged | Phase 1 | Phase 2 | Notes |
|----|--------|---------|---------|-------|
| t5-docker | b9c97e7 | ✅ | N/A | Docker infrastructure, 10 tests passing |
| t6-vectors | 9eba181 | ✅ | N/A | Reference codec (NomadCodec), 35 tests, sync_vectors.json5 |
| t1-security | 3f13c52 | ✅ | 🔲 | Security layer, 246 tests (AEAD, nonce, handshake, rekey, replay) |
| t3-sync | 07c6893 | ✅ | 🔲 | Sync layer, 158 tests (diff encode/decode/apply, convergence, flow) |
| t2-transport | b3c79c6 | ✅ | 🔲 | Transport layer, 163 tests (frame format, session, wire E2E) |
| t7-resilience | 118fa14 | N/A | 🔲 | Network resilience, E2E only (chaos, latency, packet loss) |
| t8-adversarial | b91c742 | N/A | 🔲 | Security adversarial, E2E only (replay attacks, session isolation) |

---

## Infrastructure Updates

- [x] Test keypairs updated in `tests/lib/containers.py` to match Rust implementation
- [x] Crash handling added: `ContainerCrashError`, `check_container_health()`
- [x] All worktrees synced with complete `tests/lib/` (containers, reference, chaos, attacker, network)

## Lib Files (tests/lib/)

| File | Owner | Purpose |
|------|-------|---------|
| `containers.py` | t5-docker | Docker container management, crash detection |
| `reference.py` | t6-vectors | Python reference codec (NomadCodec) |
| `chaos.py` | t7-resilience | Network chaos injection (pumba/netem) |
| `attacker.py` | t8-adversarial | MITM attack toolkit (scapy) |
| `network.py` | t2-transport | Packet capture helpers |
