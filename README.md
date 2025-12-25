# NOMAD Protocol Specification

> **NOMAD** - **N**etwork-**O**ptimized **M**obile **A**pplication **D**atagram

A secure, UDP-based state synchronization protocol designed for real-time applications over unreliable networks. Inspired by [Mosh](https://mosh.org/), but a new protocol with different design choices.

## Features

- **Secure**: End-to-end authenticated encryption using Noise_IK + XChaCha20-Poly1305
- **Mobile**: Seamless roaming across IP address changes
- **Fast**: Sub-100ms reconnection, optional client-side prediction
- **Simple**: Fixed cryptographic suite, no negotiation
- **Generic**: State-agnostic synchronization framework

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
