# Master Todo - Nomad Conformance Suite

## Test Phases

> **Phase 1:** Unit tests against Python reference codec (NO DOCKER)
> **Phase 2:** E2E tests against real implementations in Docker containers

All `tests/unit/` tests are Phase 1 (Python-to-Python).
All other test directories (`protocol/`, `wire/`, `adversarial/`, `resilience/`) are Phase 2 (Docker required).

---

## Active Tentacles (ready to spawn)

| ID | Description | Scope | Worktree | Phase 1 | Phase 2 |
|----|-------------|-------|----------|---------|---------|
| t2-transport | Transport layer spec + tests | specs/2-TRANSPORT.md, tests/unit/test_frame* | .worktrees/t2-transport | ✅ | 🔲 |
| t7-resilience | Network stress testing | tests/resilience/*, tests/lib/chaos.py | .worktrees/t7-resilience | N/A | 🔲 |
| t8-adversarial | Security red team testing | tests/adversarial/*, tests/lib/attacker.py | .worktrees/t8-adversarial | N/A | 🔲 |

## Pending Tentacles

| ID | Description | Blocked By |
|----|-------------|------------|
| t4-extensions | Extension mechanism | t2 |

## Completed Tentacles

| ID | Merged | Phase 1 | Phase 2 | Notes |
|----|--------|---------|---------|-------|
| t5-docker | b9c97e7 | ✅ | N/A | Docker infrastructure, 10 tests passing |
| t6-vectors | 9eba181 | ✅ | N/A | Reference codec (NomadCodec), 35 tests, sync_vectors.json5 |
| t1-security | 3f13c52 | ✅ | 🔲 | Security layer, 246 tests (AEAD, nonce, handshake, rekey, replay) |
| t3-sync | 07c6893 | ✅ | 🔲 | Sync layer, 158 tests (diff encode/decode/apply, convergence, flow) |

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
