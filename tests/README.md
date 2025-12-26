# NOMAD Protocol Conformance Test Suite

This directory contains the conformance test suite for validating NOMAD protocol implementations.

## Test Phases

| Phase | Location | Docker Required | Purpose |
|-------|----------|-----------------|---------|
| **Phase 1** | `unit/` | NO | Validate Python reference codec against test vectors |
| **Phase 2** | `protocol/`, `wire/`, `adversarial/`, `resilience/` | YES | Validate real implementations in Docker containers |

> **Current Status:** Phase 1 complete (291 tests). Phase 2 in progress.

## Test Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Test Categories                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    unit/    │  │  protocol/  │  │adversarial/ │  │ resilience/ │   │
│  │             │  │             │  │             │  │             │   │
│  │  Reference  │  │  Protocol   │  │  Security   │  │  Network    │   │
│  │   Codec     │  │   Logic     │  │   Attacks   │  │   Chaos     │   │
│  │             │  │             │  │             │  │             │   │
│  │ NO DOCKER   │  │ NO DOCKER   │  │ NO DOCKER   │  │  DOCKER     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│         │                │                │                │           │
│         ▼                ▼                ▼                ▼           │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │              lib/reference.py (Python Reference Codec)          │  │
│  │              tests/vectors/*.json5 (Test Vectors)               │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐                                      │
│  │   wire/     │  │  interop/   │                                      │
│  │             │  │             │                                      │
│  │ Byte-level  │  │   Cross-    │                                      │
│  │ Validation  │  │   Impl      │                                      │
│  │             │  │             │                                      │
│  │  DOCKER     │  │  DOCKER     │                                      │
│  └─────────────┘  └─────────────┘                                      │
│         │                │                                              │
│         ▼                ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │              Docker Containers (Rust/Go/etc implementations)     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
tests/
├── README.md              # This file
├── pyproject.toml         # Python dependencies
├── conftest.py            # pytest fixtures
│
├── vectors/               # Test vectors (JSON5, generated)
│   ├── aead_vectors.json5
│   ├── frame_vectors.json5
│   ├── handshake_vectors.json5
│   ├── nonce_vectors.json5
│   └── sync_vectors.json5
│
├── lib/                   # Test utilities
│   ├── reference.py       # Python reference codec (SOURCE OF TRUTH)
│   ├── containers.py      # Docker container management + crash detection
│   ├── chaos.py           # Network chaos injection (pumba/netem)
│   ├── attacker.py        # MITM attack toolkit (scapy)
│   └── network.py         # Packet capture helpers
│
├── unit/                  # Unit tests (NO DOCKER)
├── protocol/              # Protocol logic tests (NO DOCKER)
├── adversarial/           # Security tests (NO DOCKER)
├── resilience/            # Network stress tests (DOCKER)
├── wire/                  # Byte-level tests (DOCKER)
├── interop/               # Cross-implementation tests (DOCKER)
└── terminal/              # Terminal-specific tests (DOCKER, optional)
```

---

## Test Categories

### 1. `unit/` - Reference Codec Unit Tests

**Docker required:** NO
**Tests against:** `lib/reference.py` + `vectors/*.json5`

Pure unit tests that validate the Python reference codec against test vectors. These tests ensure the reference implementation correctly encodes/decodes the protocol.

| File | Purpose | Spec Reference |
|------|---------|----------------|
| `test_infrastructure.py` | Test framework smoke tests | - |
| `test_reference.py` | Reference codec roundtrips | All specs |
| `test_crypto_aead.py` | XChaCha20-Poly1305 AEAD | 1-SECURITY.md §AEAD |
| `test_crypto_nonce.py` | Nonce construction | 1-SECURITY.md §Nonce |
| `test_crypto_handshake.py` | Keypair generation, X25519 | 1-SECURITY.md §Handshake |

**Run:** `uv run pytest unit/ -v`

---

### 2. `protocol/` - Protocol Logic Tests

**Docker required:** NO
**Tests against:** `lib/reference.py` (simulated protocol flows)

Tests protocol state machines and logic using the reference codec. These simulate protocol flows (handshake, sync, rekey) without needing running containers.

| File | Purpose | Spec Reference |
|------|---------|----------------|
| `test_handshake_flow.py` | Noise_IK handshake state machine | 1-SECURITY.md §Handshake |
| `test_handshake_rekey.py` | Session rekeying logic | 1-SECURITY.md §Rekeying |
| `test_sync_*.py` | State synchronization | 3-SYNC.md (planned) |

**Run:** `uv run pytest protocol/ -v`

---

### 3. `adversarial/` - Security Tests

**Docker required:** NO (unit-level) / YES (E2E attacks)
**Tests against:** Reference codec + attack simulations

Tests security properties and attack resistance. Currently tests protocol-level security using the reference codec. E2E attack tests (MITM, injection) require Docker.

| File | Purpose | Spec Reference |
|------|---------|----------------|
| `test_replay_attack.py` | Sliding window replay protection | 1-SECURITY.md §Anti-Replay |
| `test_key_compromise.py` | Forward secrecy validation | 1-SECURITY.md §Rekeying |
| `test_tamper_detection.py` | AEAD tampering detection | 1-SECURITY.md §AEAD (planned) |
| `test_mitm_injection.py` | Packet injection attacks | (planned, requires Docker) |
| `test_timing_analysis.py` | Keystroke timing leakage | (planned, requires Docker) |

**Current tests (NO DOCKER):** `uv run pytest adversarial/ -v`
**E2E attacks (DOCKER):** Planned

---

### 4. `resilience/` - Network Stress Tests

**Docker required:** YES
**Tests against:** Running Docker containers with network chaos

Tests protocol resilience under adverse network conditions using Docker containers with pumba/netem for chaos injection.

| File | Purpose | Success Criteria |
|------|---------|------------------|
| `test_packet_loss.py` | Packet loss recovery | 50% loss, converge <10s |
| `test_latency.py` | High latency handling | 500ms stable |
| `test_jitter.py` | Variable timing | No duplicates |
| `test_reordering.py` | Out-of-order packets | Idempotent handling |
| `test_partition.py` | Network partitions | 5s partition recovery |
| `test_roaming.py` | IP migration | No data loss |

**Status:** Planned
**Run:** `uv run pytest resilience/ -v --docker`

---

### 5. `wire/` - Byte-Level Wire Tests

**Docker required:** YES
**Tests against:** Running containers via packet capture

Tests byte-level protocol compliance by capturing and inspecting actual network traffic between containers using scapy/tcpdump.

| File | Purpose | Spec Reference |
|------|---------|----------------|
| `test_wire_format.py` | Field offsets, endianness | 2-TRANSPORT.md |
| `test_wire_malformed.py` | Malformed packet handling | 2-TRANSPORT.md |

**Status:** Planned
**Run:** `uv run pytest wire/ -v --docker`

---

### 6. `interop/` - Cross-Implementation Tests

**Docker required:** YES
**Tests against:** Multiple implementation containers

Tests interoperability between different implementations (Rust, Go, etc.) by running them in Docker and validating they can communicate.

| Scenario | Description |
|----------|-------------|
| Rust client ↔ Rust server | Same implementation |
| Rust client ↔ Go server | Cross-implementation |
| Go client ↔ Rust server | Cross-implementation |

**Status:** Planned
**Run:** `uv run pytest interop/ -v --docker`

---

### 7. `terminal/` - Terminal-Specific Tests

**Docker required:** YES
**Tests against:** Terminal state implementations only

Tests terminal-specific features (scrollback, prediction) that only apply to terminal-type implementations like MoshiMoshi.

**Status:** Planned
**Run:** `uv run pytest terminal/ -v --docker`

---

## Test Markers

```python
@pytest.mark.container    # Requires Docker
@pytest.mark.slow         # Long-running test
@pytest.mark.adversarial  # Security/attack test
@pytest.mark.resilience   # Network chaos test
@pytest.mark.interop      # Cross-implementation test
```

---

## Environment Setup

All Docker-based tests require environment variables. **Tests will fail with clear error messages if required variables are missing.**

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `NOMAD_TEST_NETWORK` | Docker network name | `nomad-conformance-net` |
| `NOMAD_TEST_SUBNET` | Network CIDR | `172.31.0.0/16` |
| `NOMAD_TEST_SERVER_IP` | Server IP in test network | `172.31.0.10` |
| `NOMAD_TEST_CLIENT_IP` | Client IP in test network | `172.31.0.20` |
| `NOMAD_TEST_INTERFACE` | Network interface for capture | `eth0` |
| `NOMAD_PORT` | UDP port for protocol | `19999` |
| `NOMAD_STATE_TYPE` | State type identifier | `nomad.echo.v1` |
| `NOMAD_LOG_LEVEL` | Container log verbosity | `debug` |
| `NOMAD_SERVER_CONTAINER` | Server container name | `nomad-test-server` |
| `NOMAD_CLIENT_CONTAINER` | Client container name | `nomad-test-client` |
| `NOMAD_TCPDUMP_CONTAINER` | Packet capture container name | `nomad-test-tcpdump` |

### Setup Steps

```bash
# 1. Copy the example environment file
cp docker/.env.example docker/.env

# 2. Edit docker/.env to configure your implementation
#    - Set SERVER_CONTEXT/CLIENT_CONTEXT to your implementation path
#    - Set SERVER_DOCKERFILE/CLIENT_DOCKERFILE to your Dockerfiles
#    - Optionally update SERVER_PRIVATE_KEY/SERVER_PUBLIC_KEY

# 3. Source the environment before running tests
source docker/.env
```

> **Note:** The `.env.example` contains working defaults for the reference test keypairs. Each implementation should create its own `.env` with appropriate Dockerfile paths.

---

## Running Tests

### Quick Start (No Docker)

```bash
cd tests
uv run pytest                    # All non-Docker tests
uv run pytest unit/ -v           # Unit tests only
uv run pytest adversarial/ -v    # Security tests only
```

### With Docker Containers

```bash
# 1. Setup environment (one-time)
cd docker
cp .env.example .env
# Edit .env to point to your implementation

# 2. Source environment and start containers
source .env
docker compose up -d

# 3. Run E2E tests
cd ../tests
source ../docker/.env  # Ensure env vars are available
uv run pytest wire/ resilience/ -v -m container

# 4. Cleanup
docker compose down
```

**Error handling:** If any required environment variable is missing, tests will fail immediately with a clear error message indicating which variable needs to be set.

## Test Vector Strategy

Test vectors in `vectors/*.json5` are the **single source of truth** for wire format:

- Generated by `specs/generate_vectors.py` using reference libraries
- JSON5 format allows inline comments explaining each field
- Idempotent: regenerating produces identical output
- Every value traceable to spec + reference library (no magic numbers)

```bash
# Regenerate vectors
cd ../specs
python generate_vectors.py
```

---

## Coverage Summary

| Category | Tests | Docker | Status |
|----------|-------|--------|--------|
| Unit (reference codec) | 80 | No | ✅ Complete |
| Protocol (handshake, rekey) | 107 | No | ✅ Complete |
| Adversarial (replay, forward secrecy) | 36 | No | ✅ Complete |
| Adversarial (MITM, timing) | - | Yes | 🔲 Planned |
| Resilience (chaos) | - | Yes | 🔲 Planned |
| Wire (byte-level) | - | Yes | 🔲 Planned |
| Interop (cross-impl) | - | Yes | 🔲 Planned |

**Total current:** 291 tests passing
**Total planned:** ~400+ tests
