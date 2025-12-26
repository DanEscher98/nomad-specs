# Master Todo - Nomad Conformance Suite

## Test Naming Convention

Tests are named by **infrastructure required** (prefix), not by what they test (directory):

| Prefix | Meaning | Dependencies | Run Command |
|--------|---------|--------------|-------------|
| `test_spec_*` | Python reference codec only | None | `just test-spec` |
| `test_server_*` | Python client → Docker server | Server container | `just test-server` |
| `test_e2e_*` | Docker client ↔ Docker server + capture | Both containers | `just test-e2e` |

**Directories** describe the property/area being tested:
- `unit/` - Codec internals (all spec tests)
- `protocol/` - Protocol behavior (mix)
- `wire/` - Byte-level format (mix)
- `adversarial/` - Security attacks (mix)
- `resilience/` - Network chaos (all E2E)

---

## Active Tentacles

| ID | Branch | Worktree | Description |
|----|--------|----------|-------------|
| t6-vectors | tentacle/t6-vectors | .worktrees/t6-vectors | **Phase 2: PCS fix test vectors** |
| t10-launch | tentacle/t10-launch | .worktrees/t10-launch | Launch coordination & outreach |

## Pending Tentacles

None.

## Critical Tasks (from t11-formal PCS finding)

| Task | Owner | Priority | Status |
|------|-------|----------|--------|
| Update test vectors with `rekey_auth_key` KDF | **t6-vectors** | HIGH | 🔲 Assigned |
| Update Rust implementation with new KDF | External (nomad-rs) | HIGH | 🔲 |
| Add formal verification section to paper | t9-paper | HIGH | ✅ Done |
| Document PCS finding as key contribution | t9-paper | HIGH | ✅ Done |

## Completed Tentacles

| ID | Merged | Spec | Server | E2E | Notes |
|----|--------|------|--------|-----|-------|
| t5-docker | b9c97e7 | ✅ | N/A | N/A | Docker infrastructure |
| t6-vectors | 9eba181 | ✅ | N/A | N/A | Reference codec (NomadCodec), sync_vectors.json5 |
| t1-security | 3f13c52 | ✅ | ✅ | 🔲 | Security layer, handshake/rekey/replay |
| t3-sync | 07c6893 | ✅ | 🔲 | 🔲 | Sync layer, diff encode/decode/apply, convergence |
| t2-transport | b3c79c6 | ✅ | ✅ | 🔲 | Transport layer, wire/keepalive/roaming |
| t7-resilience | 118fa14 | N/A | N/A | 🔲 | Network resilience (chaos, latency, packet loss) |
| t8-adversarial | b91c742 | ✅ | ✅ | N/A | Security adversarial, replay attacks |
| t4-extensions | 42128a9 | ✅ | N/A | N/A | Extension mechanism, TLV encoding, compression (83 tests) |
| t11-formal | 51c3cf8 | ✅ | N/A | N/A | ProVerif + TLA+ formal verification, **PCS fix** |
| t9-paper | 30827ed | ✅ | N/A | N/A | arXiv paper (7 pages), formal verification section |

---

## Server Test Suite

Run with: `just test-server` (requires `docker-up` first)

| Test File | Tests | Status | Description |
|-----------|-------|--------|-------------|
| `protocol/test_server_handshake.py` | 5 | ✅ | Noise_IK handshake, session ID, data exchange |
| `protocol/test_server_rekey.py` | 10 | ✅ | Session longevity, rekey frames, forward secrecy |
| `protocol/test_server_keepalive.py` | 12 | ✅ | Keepalive frames, session liveness, timestamps |
| `protocol/test_server_roaming.py` | 10 | ✅ | Port change, migration, anti-amplification |
| `adversarial/test_server_replay.py` | 6 | ✅ | Replay attacks, nonce reuse, session isolation |
| `wire/test_server_wire.py` | 17 | ✅ | Wire format, malformed packets, session ID |
| **Total** | **60** | ✅ | All passing (1 skipped - slow test) |

## E2E Test Suite (Full Docker)

Run with: `just test-e2e` (requires `docker-up-capture` first)

| Test File | Tests | Status | Description |
|-----------|-------|--------|-------------|
| `protocol/test_e2e_keepalive.py` | TBD | 🔲 | Full keepalive with packet capture |
| `protocol/test_e2e_roaming.py` | TBD | 🔲 | Full roaming with packet capture |
| `wire/test_e2e_wire_format.py` | TBD | 🔲 | Wire format with packet capture |
| `wire/test_e2e_wire_malformed.py` | TBD | 🔲 | Malformed packets with capture |
| `resilience/test_e2e_*.py` | 7 files | 🔲 | Network chaos tests |

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
