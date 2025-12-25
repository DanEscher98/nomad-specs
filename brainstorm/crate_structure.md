# NOMAD Protocol - Rust Implementation Guide

> **NOMAD** - **N**etwork-**O**ptimized **M**obile **A**pplication **D**atagram

This document provides the crate structure and implementation guide for a Rust implementation of the NOMAD protocol. The canonical specification lives in `nomad-specs/specs/`.

---

## Protocol Layers → Crates Mapping

```
┌─────────────────────────────────────────────────────────────┐
│  APPLICATION     MoshiMoshi, Custom Apps                    │  → nomad-terminal, your-app
├─────────────────────────────────────────────────────────────┤
│  STATE LAYER     impl SyncState for YourType                │  → nomad-core (traits)
├─────────────────────────────────────────────────────────────┤
│  EXTENSIONS      compression (zstd) • scrollback • predict  │  → nomad-extensions
├─────────────────────────────────────────────────────────────┤
│  SYNC LAYER      versioning • idempotent diffs • convergence│  → nomad-sync
├─────────────────────────────────────────────────────────────┤
│  TRANSPORT       frames • session ID • RTT • keepalive      │  → nomad-transport
├─────────────────────────────────────────────────────────────┤
│  SECURITY        Noise_IK • XChaCha20-Poly1305 • BLAKE2s    │  → nomad-crypto
├─────────────────────────────────────────────────────────────┤
│  UDP             tokio::net::UdpSocket                      │  → (stdlib/tokio)
└─────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
nomad/                                 # Implementation monorepo
├── Cargo.toml                         # Workspace
├── README.md
├── CHANGELOG.md
│
├── vectors/                           # Test vectors (from nomad-specs)
│   ├── aead_vectors.json5             # XChaCha20-Poly1305 test cases
│   ├── nonce_vectors.json5            # Nonce construction test cases
│   ├── frame_vectors.json5            # Frame encoding test cases
│   └── handshake_vectors.json5        # Handshake structure test cases
│
├── crates/
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │              CORE PROTOCOL CRATES                   │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── nomad-core/                    # Traits + shared types (no I/O)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── traits.rs              # SyncState, Predictable traits
│   │   │   ├── version.rs             # State versioning (u64)
│   │   │   ├── error.rs               # Common error types
│   │   │   └── constants.rs           # Protocol constants from spec
│   │   └── Cargo.toml                 # deps: thiserror only
│   │
│   ├── nomad-crypto/                  # Security layer (1-SECURITY.md)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── noise.rs               # Noise_IK handshake (snow crate)
│   │   │   ├── aead.rs                # XChaCha20-Poly1305 (NO negotiation)
│   │   │   ├── nonce.rs               # Nonce construction (epoch|dir|counter)
│   │   │   ├── keys.rs                # Key types with Zeroize
│   │   │   ├── session.rs             # Session state, epoch tracking
│   │   │   └── rekey.rs               # Rekeying logic
│   │   ├── tests/
│   │   │   └── vectors.rs             # Tests against JSON5 vectors
│   │   └── Cargo.toml                 # deps: snow, chacha20poly1305, zeroize, blake2
│   │
│   ├── nomad-transport/               # Transport layer (2-TRANSPORT.md)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── frame.rs               # Frame encoding/decoding
│   │   │   ├── connection.rs          # Connection state machine
│   │   │   ├── migration.rs           # IP roaming, anti-amplification
│   │   │   ├── timing.rs              # RTT estimation (RFC 6298)
│   │   │   ├── pacing.rs              # Frame rate limiting
│   │   │   └── socket.rs              # Async UDP wrapper
│   │   ├── tests/
│   │   │   └── vectors.rs             # Tests against JSON5 vectors
│   │   └── Cargo.toml                 # deps: nomad-crypto, tokio
│   │
│   ├── nomad-sync/                    # Sync layer (3-SYNC.md)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── engine.rs              # Sync engine (generic over SyncState)
│   │   │   ├── tracker.rs             # SyncTracker state
│   │   │   ├── sender.rs              # Outbound state management
│   │   │   ├── receiver.rs            # Inbound diff application
│   │   │   ├── message.rs             # Sync message encoding
│   │   │   └── ack.rs                 # Acknowledgment tracking
│   │   ├── tests/
│   │   │   └── vectors.rs             # Tests against JSON5 vectors
│   │   └── Cargo.toml                 # deps: nomad-core, nomad-transport
│   │
│   ├── nomad-extensions/              # Extensions (4-EXTENSIONS.md)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── compression.rs         # zstd compression (ext 0x0001)
│   │   │   ├── scrollback.rs          # Scrollback sync (ext 0x0002)
│   │   │   └── prediction.rs          # Client prediction (ext 0x0003)
│   │   └── Cargo.toml                 # deps: zstd (optional)
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │          DOMAIN-SPECIFIC STATE TYPES                │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── nomad-terminal/                # Terminal state (for MoshiMoshi)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── state.rs               # impl SyncState for TerminalState
│   │   │   ├── framebuffer.rs         # Cell grid
│   │   │   ├── cursor.rs              # Cursor state
│   │   │   ├── diff.rs                # Terminal-specific diff encoding
│   │   │   ├── prediction.rs          # impl Predictable for TerminalState
│   │   │   └── parser.rs              # VT sequences (vte crate)
│   │   └── Cargo.toml                 # deps: nomad-core, vte
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │              HIGH-LEVEL API                         │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── nomad-client/                  # Client library
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── client.rs              # High-level Client<S: SyncState>
│   │   │   └── bootstrap.rs           # Key exchange bootstrap
│   │   └── Cargo.toml                 # deps: nomad-sync, nomad-transport
│   │
│   └── nomad-server/                  # Server library
│       ├── src/
│       │   ├── lib.rs
│       │   ├── server.rs              # High-level Server<S: SyncState>
│       │   └── session.rs             # Session management
│       └── Cargo.toml                 # deps: nomad-sync, nomad-transport
│
├── examples/
│   ├── echo/                          # Simplest: echo state (nomad.echo.v1)
│   ├── terminal/                      # Terminal client/server
│   └── counter/                       # Synchronized counter
│
└── tools/
    ├── nomad-cli/                     # CLI for testing
    └── nomad-bench/                   # Performance benchmarks
```

---

## Using Test Vectors

The canonical test vectors are generated by `nomad-specs/specs/generate_vectors.py` and stored as JSON5 files. Copy them to your implementation's `vectors/` directory.

### Loading Vectors in Rust

```rust
// In Cargo.toml:
// [dev-dependencies]
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"  # json5 crate for JSON5, or strip comments first

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AeadVector {
    name: String,
    key: String,           // hex
    nonce: String,         // hex
    plaintext: String,     // hex
    aad: String,           // hex
    ciphertext: String,    // hex (includes tag)
}

#[derive(Debug, Deserialize)]
struct AeadVectors {
    vectors: Vec<AeadVector>,
}

#[test]
fn test_aead_vectors() {
    // Strip JSON5 comments or use json5 crate
    let json = include_str!("../../vectors/aead_vectors.json5");
    let json = strip_json5_comments(json);
    let vectors: AeadVectors = serde_json::from_str(&json).unwrap();

    for v in vectors.vectors {
        let key = hex::decode(&v.key).unwrap();
        let nonce = hex::decode(&v.nonce).unwrap();
        let plaintext = hex::decode(&v.plaintext).unwrap();
        let aad = hex::decode(&v.aad).unwrap();
        let expected = hex::decode(&v.ciphertext).unwrap();

        let result = xchacha20poly1305_encrypt(&key, &nonce, &plaintext, &aad);
        assert_eq!(result, expected, "Vector '{}' failed", v.name);
    }
}

fn strip_json5_comments(input: &str) -> String {
    input.lines()
        .filter(|line| !line.trim().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
```

### Vector Files Reference

| File | Purpose | Key Tests |
|------|---------|-----------|
| `aead_vectors.json5` | XChaCha20-Poly1305 | encrypt/decrypt, empty plaintext, high counter |
| `nonce_vectors.json5` | Nonce construction | epoch, direction, counter → 24 bytes |
| `frame_vectors.json5` | Frame encoding | data frame header, sync message format |
| `handshake_vectors.json5` | Handshake structure | keypairs, frame layouts |

**If your implementation doesn't match these vectors, your implementation is wrong.**

---

## Core Traits

```rust
// nomad-core/src/traits.rs

/// Core trait for any state that can be synchronized.
/// Implements 3-SYNC.md state type interface.
pub trait SyncState: Clone + Send + Sync + 'static {
    /// Diff representation (must be idempotent when applied)
    type Diff: Clone + Send + Sync;

    /// Unique type identifier (e.g., "nomad.terminal.v1")
    const STATE_TYPE_ID: &'static str;

    /// Create diff from old_state to self.
    /// MUST be idempotent: applying twice has no additional effect.
    fn diff_from(&self, old: &Self) -> Self::Diff;

    /// Apply diff to produce new state.
    /// MUST handle repeated application (idempotent).
    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError>;

    /// Serialize diff for wire transmission.
    fn encode_diff(diff: &Self::Diff) -> Vec<u8>;

    /// Deserialize diff from wire format.
    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError>;

    /// Check if diff is empty (optimization for ack-only).
    fn is_diff_empty(diff: &Self::Diff) -> bool { false }
}

/// Optional trait for states that support client-side prediction.
/// See 4-EXTENSIONS.md §Prediction.
pub trait Predictable: SyncState {
    /// User input type (e.g., keystrokes)
    type Input;

    /// Apply speculative input locally
    fn predict(&mut self, input: &Self::Input);

    /// Reconcile with authoritative server state
    fn reconcile(&mut self, authoritative: &Self);
}
```

---

## Dependency Graph

```
                    ┌─────────────┐
                    │ nomad-core  │  ← Only thiserror
                    │  (traits)   │     #![no_std] compatible
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
   │nomad-crypto │  │nomad-terminal│  │ your-state   │
   │             │  │              │  │ (custom)     │
   │ snow        │  │ vte          │  │              │
   │ chacha20    │  │ impl Sync    │  │ impl Sync    │
   │ blake2      │  │ State        │  │ State        │
   │ zeroize     │  └──────┬───────┘  └──────┬───────┘
   └──────┬──────┘         │                 │
          │                │                 │
          ▼                │                 │
   ┌──────────────┐        │                 │
   │nomad-transport        │                 │
   │              │        │                 │
   │ tokio        │        │                 │
   │ frame encode │        │                 │
   │ RTT/pacing   │        │                 │
   └──────┬───────┘        │                 │
          │                │                 │
          ▼                │                 │
   ┌─────────────┐         │                 │
   │ nomad-sync  │◄────────┴─────────────────┘
   │             │
   │ Generic over│
   │ SyncState   │
   └──────┬──────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌────────┐  ┌────────┐
│ client │  │ server │
└────────┘  └────────┘
```

---

## Key Implementation Notes

### Cryptography (nomad-crypto)

**Fixed suite, NO negotiation:**
- Handshake: Noise_IK (use `snow` crate)
- AEAD: XChaCha20-Poly1305 (use `chacha20poly1305` crate)
- Hash: BLAKE2s-256 (use `blake2` crate)
- KDF: HKDF-BLAKE2s (via Noise)

```rust
// Nonce construction (24 bytes for XChaCha20)
fn construct_nonce(epoch: u32, direction: u8, counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..4].copy_from_slice(&epoch.to_le_bytes());
    nonce[4] = direction;  // 0x00 = initiator→responder, 0x01 = reverse
    // nonce[5..16] = zeros
    nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    nonce
}
```

### Transport (nomad-transport)

**Critical timing from 2-TRANSPORT.md:**

```rust
// RTT estimation (RFC 6298)
struct RttEstimator {
    srtt: f64,      // Smoothed RTT
    rttvar: f64,    // RTT variance
    rto: Duration,  // Retransmission timeout
}

impl RttEstimator {
    fn update(&mut self, sample: Duration) {
        if self.srtt == 0.0 {
            self.srtt = sample.as_secs_f64() * 1000.0;
            self.rttvar = self.srtt / 2.0;
        } else {
            let sample_ms = sample.as_secs_f64() * 1000.0;
            self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - sample_ms).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * sample_ms;
        }
        let rto_ms = self.srtt + f64::max(100.0, 4.0 * self.rttvar);
        self.rto = Duration::from_millis(rto_ms.min(60000.0) as u64);
    }
}

// Frame pacing
const MIN_FRAME_INTERVAL_MS: u64 = 20;  // or SRTT/2, whichever is greater
const COLLECTION_INTERVAL_MS: u64 = 8;  // Batch rapid state changes
const MAX_FRAME_RATE_HZ: u32 = 50;      // Hard cap
```

### Security Limits (nomad-crypto)

**CRITICAL - Prevent nonce reuse:**

```rust
const REKEY_AFTER_MESSAGES: u64 = 1 << 60;      // Soft limit
const REJECT_AFTER_MESSAGES: u64 = u64::MAX;    // Hard limit - terminate session!

fn send_frame(&mut self, ...) -> Result<(), Error> {
    if self.send_nonce >= REJECT_AFTER_MESSAGES {
        return Err(Error::CounterExhaustion);
    }
    // ...
}
```

---

## Running Conformance Tests

The `nomad-specs` repo contains a Docker-based test suite. To validate your implementation:

```bash
# Build your implementation as a Docker image
docker build -t my-nomad-impl .

# Run conformance tests from nomad-specs
cd nomad-specs
just test-impl my-nomad-impl
```

See `nomad-specs/CONFORMANCE.md` for the required container interface.

---

## Spec Files Reference

| Spec | Crate | Key Content |
|------|-------|-------------|
| `0-PROTOCOL.md` | - | Overview, terminology, constants |
| `1-SECURITY.md` | `nomad-crypto` | Noise_IK, AEAD, rekeying, anti-replay |
| `2-TRANSPORT.md` | `nomad-transport` | Frames, RTT, pacing, migration |
| `3-SYNC.md` | `nomad-sync` | State versioning, idempotent diffs |
| `4-EXTENSIONS.md` | `nomad-extensions` | Compression, scrollback, prediction |

---

## Performance Targets

With proper implementation of the spec (especially RTT-based timing), expect:

| Metric | Target | Notes |
|--------|--------|-------|
| Handshake | < 1 RTT | Noise_IK is 1-RTT |
| Reconnection | < 100ms | No handshake needed (roaming) |
| Keystroke latency | < 50ms | Local prediction + async send |
| Frame rate | 50 Hz max | Human perception threshold |
| Throughput | > 10 MB/s | Limited by crypto, not protocol |

NOMAD should match or beat Mosh latency when properly implemented.
