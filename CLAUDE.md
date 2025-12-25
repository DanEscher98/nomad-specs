# Roam Protocol Specs

## Overview

This repository contains **specifications only** for the Roam Protocol, a secure UDP-based state synchronization protocol inspired by Mosh. No actual implementations live here.

**This repo contains:**
- Formal protocol specifications (refined from brainstorm/)
- E2E conformance test suite (Python)
- Test vectors (JSON)
- Docker infrastructure for testing implementations

**This repo does NOT contain:**
- Rust/Go/etc implementations (separate repos)
- MoshiMoshi app (separate repo)
- Terminal state type implementation

## Architecture Layers

```
┌─────────────────────────────────────────────────┐
│ EXTENSIONS (compression, scrollback, etc.)      │
├─────────────────────────────────────────────────┤
│ STATE LAYER (application-specific, e.g. Term)   │
├─────────────────────────────────────────────────┤
│ SYNC LAYER - versioning, diffs, convergence     │
├─────────────────────────────────────────────────┤
│ TRANSPORT LAYER - UDP, framing, migration       │
├─────────────────────────────────────────────────┤
│ SECURITY LAYER - Noise_IK, XChaCha20-Poly1305   │
└─────────────────────────────────────────────────┘
```

## Directory Structure

```
roam-specs/
├── specs/                    # Formal specifications
│   ├── PROTOCOL.md           # Core protocol spec
│   ├── SECURITY.md           # Security layer spec
│   ├── TRANSPORT.md          # Transport layer spec
│   ├── SYNC.md               # Sync layer spec
│   └── EXTENSIONS.md         # Extension mechanism
│
├── tests/                    # E2E conformance suite (Python)
│   ├── pyproject.toml
│   ├── conftest.py           # pytest fixtures
│   │
│   ├── vectors/              # Static test vectors (JSON)
│   │   ├── handshake_vectors.json
│   │   ├── frame_vectors.json
│   │   └── sync_vectors.json
│   │
│   ├── unit/                 # Pure logic tests
│   ├── protocol/             # Protocol behavior tests
│   ├── wire/                 # Byte-level validation
│   ├── interop/              # Cross-implementation tests
│   ├── adversarial/          # Security tests
│   │
│   └── lib/                  # Test utilities
│       ├── containers.py     # Docker management
│       ├── network.py        # scapy helpers
│       ├── generators.py     # hypothesis strategies
│       └── reference.py      # Python reference encoder/decoder
│
├── docker/                   # Docker infrastructure
│   ├── docker-compose.yml
│   └── Dockerfile.stub       # Minimal stub for spec testing
│
├── brainstorm/               # Original brainstorm docs (reference)
│
└── .octopus/                 # Parallel dev coordination
```

## Tech Stack

- **Specs**: Markdown with ASCII diagrams
- **Test Suite**: Python 3.11+
  - pytest (test runner)
  - hypothesis (property-based testing)
  - scapy (packet inspection)
  - docker (container orchestration)
- **Dependency Management**: uv
- **Containers**: Docker Compose

## Octopus Tentacle Breakdown

| ID | Scope | Description |
|----|-------|-------------|
| t1-security | specs/SECURITY.md, tests/unit/test_crypto*, tests/protocol/test_handshake* | Security layer spec + tests |
| t2-transport | specs/TRANSPORT.md, tests/unit/test_frame*, tests/wire/* | Transport layer spec + tests |
| t3-sync | specs/SYNC.md, tests/protocol/test_sync*, tests/unit/test_diff* | Sync layer spec + tests |
| t4-extensions | specs/EXTENSIONS.md, tests/protocol/test_extension* | Extension mechanism spec + tests |
| t5-docker | docker/*, tests/lib/containers.py, tests/conftest.py | Docker orchestration, plug & play infrastructure |
| t6-vectors | tests/vectors/*, tests/lib/reference.py | Test vectors generation, Python reference codec |

## Conventions

- Specs must be **isomorphic to tests**: each spec section maps to test cases
- Test vectors are the **single source of truth** for byte formats
- All packet formats use **little-endian** unless specified
- Use **hypothesis** for property-based tests (edge cases)
- Docker containers must implement a standard interface (see CONFORMANCE.md)
- brainstorm/ is kept as historical reference; specs/ is canonical

## Test Vector Strategy

Vectors are **generated using reference libraries**, not hand-crafted:

```
specs/
├── PROTOCOL.md              # Human-readable spec
└── generate_vectors.py      # Executable spec

tests/vectors/
├── handshake_vectors.json   # Generated from snow + test keypairs
├── frame_vectors.json       # Generated from cryptography lib
└── README.md                # Documents derivation of each vector
```

- Use `snow` (Noise protocol) and `cryptography` (XChaCha20-Poly1305) as reference
- Generation scripts are idempotent (regenerating produces identical output)
- Each vector includes metadata explaining its derivation
- No magic numbers: every value traceable to spec + reference lib

## Commands

```bash
# Run tests (once tests/ is set up)
just test

# Run specific test category
just test-unit
just test-protocol
just test-wire

# Start docker containers
just docker-up

# Generate test vectors from specs
just gen-vectors
```

## Plug & Play Architecture

Implementations are tested by:
1. Building their server/client as Docker images
2. Pointing docker-compose to those images
3. Running the conformance test suite

The test suite doesn't know or care what language the implementation uses.
