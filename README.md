# NOMAD Protocol Specification

> **NOMAD** - **N**etwork-**O**ptimized **M**obile **A**pplication **D**atagram

A secure, UDP-based state synchronization protocol designed for real-time applications over unreliable networks. Inspired by [Mosh](https://mosh.org/), but a new protocol with different design choices.

## Quick Start

```bash
# Install test dependencies
just install

# Run spec tests (no Docker required)
just test-spec

# Run server tests (requires Docker)
just docker-up
just test-server

# Run transport attack tests (requires test-runner container)
just docker-up-runner
just docker-test-runner adversarial/test_server_transport_attacks.py -v

# Stop containers
just docker-down
```

## Features

- **Secure**: End-to-end authenticated encryption using Noise_IK + XChaCha20-Poly1305
- **Mobile**: Seamless roaming across IP address changes
- **Fast**: Sub-100ms reconnection, optional client-side prediction
- **Simple**: Fixed cryptographic suite, no negotiation
- **Generic**: State-agnostic synchronization framework

## Test Suite

The conformance test suite validates implementations against the protocol specification.

### Test Categories

| Prefix | Description | Requirements | Command |
|--------|-------------|--------------|---------|
| `test_spec_*` | Python reference codec tests | None | `just test-spec` |
| `test_server_*` | Python client → Docker server | Server container | `just test-server` |
| `test_e2e_*` | Docker client ↔ Docker server | Both containers | `just test-e2e` |

### Test Directories

| Directory | Description |
|-----------|-------------|
| `tests/unit/` | Codec internals (encoding, crypto) |
| `tests/protocol/` | Protocol behavior (handshake, sync, rekey) |
| `tests/wire/` | Byte-level format compliance |
| `tests/adversarial/` | Security tests (replay, injection, timing) |
| `tests/resilience/` | Network chaos tests (loss, latency, reorder) |
| `tests/interop/` | Cross-implementation tests |

### Running Tests

```bash
# Spec tests - no Docker needed
just test-spec                    # All spec tests
just test-unit                    # Unit directory only

# Server tests - requires server container
just docker-up                    # Start server
just test-server                  # Run server tests

# Transport attack tests - requires test-runner container
just docker-up-runner             # Start server + test-runner
just docker-test-runner adversarial/test_server_transport_attacks.py -v

# E2E tests - requires both containers + packet capture
just docker-up-capture            # Start with tcpdump
just test-e2e                     # Run E2E tests

# Resilience tests - requires chaos profiles
just docker-up-chaos              # Start with network chaos
just test-resilience              # Run resilience tests

# Quick workflows
just quick-server                 # up → test → down
just quick-e2e                    # up-capture → test → down
```

### Special Test Markers

Some tests require special capabilities and are skipped by default:

| Marker | Description | How to Run |
|--------|-------------|------------|
| `scapy_attack` | Tests requiring raw sockets (NET_RAW) | `just docker-test-runner -m scapy_attack adversarial/` |
| `container` | Tests requiring Docker access | Automatic with `just test-server` |
| `slow` | Long-running tests | Included by default |

## Docker Infrastructure

### Container Images

Build images from the Rust implementation:

```bash
cd ../nomad-rs
just docker-server    # Builds nomad-echo-server
just docker-client    # Builds nomad-client-arm (ARM64/QEMU)
```

### Services

| Service | Image | Purpose |
|---------|-------|---------|
| `nomad-server` | `nomad-echo-server` | Echo server for testing |
| `nomad-client` | `nomad-client-arm` | ARM64 client via QEMU |
| `test-runner` | `python:3.13-slim` | Scapy-based attack tests |
| `tcpdump` | `nicolaka/netshoot` | Packet capture |
| `chaos-*` | `gaiaadm/pumba` | Network chaos injection |

### Environment Variables

Configure in `docker/.env`:

```bash
SERVER_IMAGE=nomad-echo-server
CLIENT_IMAGE=nomad-client-arm
SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=
LOG_LEVEL=debug
```

### Network

All containers run on `nomad-net` (172.28.0.0/16):

| Container | IP Address |
|-----------|------------|
| nomad-server | 172.28.0.10 |
| nomad-client | 172.28.0.20 |
| test-runner | 172.28.0.100 |

## Specifications

| Document | Description |
|----------|-------------|
| [0-PROTOCOL.md](specs/0-PROTOCOL.md) | Protocol overview, terminology, constants |
| [1-SECURITY.md](specs/1-SECURITY.md) | Noise_IK handshake, AEAD, rekeying |
| [2-TRANSPORT.md](specs/2-TRANSPORT.md) | Framing, RTT estimation, roaming |
| [3-SYNC.md](specs/3-SYNC.md) | State versioning, idempotent diffs |
| [4-EXTENSIONS.md](specs/4-EXTENSIONS.md) | Compression, scrollback, prediction |

## Test Vectors

Canonical test vectors for implementation validation:

```
tests/vectors/
├── aead_vectors.json5      # XChaCha20-Poly1305 encryption
├── nonce_vectors.json5     # Nonce construction
├── frame_vectors.json5     # Frame encoding
└── handshake_vectors.json5 # Handshake structure
```

Regenerate with:
```bash
cd specs && python generate_vectors.py
```

## Cryptographic Suite

Fixed suite with no negotiation:

| Purpose | Algorithm |
|---------|-----------|
| Key Exchange | X25519 |
| AEAD Cipher | XChaCha20-Poly1305 |
| Hash Function | BLAKE2s-256 |
| Key Derivation | HKDF-BLAKE2s |

## Protocol Layers

```
┌─────────────────────────────────────────────────────────┐
│ EXTENSIONS: compression (zstd), scrollback, prediction  │
├─────────────────────────────────────────────────────────┤
│ STATE LAYER: Application-defined SyncState              │
├─────────────────────────────────────────────────────────┤
│ SYNC LAYER: versioning, idempotent diffs, convergence   │
├─────────────────────────────────────────────────────────┤
│ TRANSPORT: frames, session ID, nonce, keepalive         │
├─────────────────────────────────────────────────────────┤
│ SECURITY: Noise_IK, XChaCha20-Poly1305, BLAKE2s         │
├─────────────────────────────────────────────────────────┤
│ UDP: unreliable datagrams                               │
└─────────────────────────────────────────────────────────┘
```

## Key Timing Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `REKEY_AFTER_TIME` | 120s | Initiate rekeying |
| `KEEPALIVE_INTERVAL` | 25s | Send keepalive if idle |
| `DEAD_INTERVAL` | 60s | Connection timeout |
| `MIN_FRAME_INTERVAL` | SRTT/2 or 20ms | Minimum between frames |
| `MAX_FRAME_RATE` | 50 Hz | Hard cap on frame rate |

## Implementation Guide

See [brainstorm/crate_structure.md](brainstorm/crate_structure.md) for Rust implementation guidance including:
- Crate organization mapping to protocol layers
- How to use JSON5 test vectors
- Performance targets

## Conformance Testing

See [CONFORMANCE.md](CONFORMANCE.md) for the conformance test suite structure.

## References

1. Winstein, K., & Balakrishnan, H. (2012). Mosh: An Interactive Remote Shell for Mobile Clients. USENIX ATC.
2. Perrin, T. (2018). The Noise Protocol Framework. noiseprotocol.org
3. Donenfeld, J. A. (2017). WireGuard: Next Generation Kernel Network Tunnel. NDSS.
4. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols

## License

Specifications released under CC BY 4.0.
