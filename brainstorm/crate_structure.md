```txt
roam/                              # Protocol monorepo
├── Cargo.toml                     # Workspace
├── PROTOCOL.md                    # Human-readable spec
├── spec/
│   ├── 00-introduction.md         # Goals, non-goals
│   ├── 01-transport.md            # UDP framing, connection ID
│   ├── 02-security.md             # Key exchange, AEAD
│   ├── 03-synchronization.md      # State sync algorithm
│   ├── 04-terminal.md             # Framebuffer encoding
│   ├── 05-extensions.md           # Capability negotiation
│   └── 99-wire-format.md          # Byte-level specification
├── docs/
│   ├── architecture.md            # Crate organization
│   ├── implementing-client.md     # How to build a client
│   ├── implementing-server.md     # How to build a server
│   └── comparison-mosh.md         # Explicit differences from SSP
│
├── crates/
│   ├── roam-core/                 # Shared types, no I/O
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── state.rs           # State<T>, versioning
│   │   │   ├── diff.rs            # Diff trait, encoding
│   │   │   ├── frame.rs           # Wire format
│   │   │   └── capability.rs      # Extension negotiation
│   │   └── Cargo.toml
│   │
│   ├── roam-crypto/               # AEAD implementations
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── chacha.rs          # ChaCha20-Poly1305
│   │   │   ├── ocb.rs             # AES-128-OCB3 (optional)
│   │   │   ├── aegis.rs           # AEGIS-128L (optional, ARM)
│   │   │   └── negotiation.rs     # Cipher suite selection
│   │   └── Cargo.toml
│   │
│   ├── roam-terminal/             # Terminal state machine
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── cell.rs
│   │   │   ├── framebuffer.rs
│   │   │   ├── scrollback.rs      # NEW: Scrollback buffer
│   │   │   ├── diff.rs            # Implements Diff for Framebuffer
│   │   │   └── parser.rs          # VT sequences (uses vte)
│   │   └── Cargo.toml
│   │
│   ├── roam-transport/            # Async networking
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── connection.rs      # UDP socket, reconnection
│   │   │   ├── timing.rs          # RTT, adaptive intervals
│   │   │   └── migration.rs       # IP change handling
│   │   └── Cargo.toml
│   │
│   ├── roam-sync/                 # State synchronization engine
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── sender.rs          # Outgoing state management
│   │   │   ├── receiver.rs        # Incoming diff application
│   │   │   └── prediction.rs      # Local echo prediction
│   │   └── Cargo.toml
│   │
│   ├── roam-client/               # Client library (for apps)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── client.rs          # High-level API
│   │   │   ├── bootstrap.rs       # SSH key exchange
│   │   │   └── reconnect.rs       # Token-based reconnection
│   │   └── Cargo.toml
│   │
│   └── roam-server/               # Server library + binary
│       ├── src/
│       │   ├── lib.rs             # Library for embedding
│       │   ├── main.rs            # Standalone server binary
│       │   ├── session.rs         # PTY + state management
│       │   ├── auth.rs            # SSH bootstrap, tokens
│       │   └── config.rs
│       └── Cargo.toml
│
└── tools/
    ├── roam-cli/                  # CLI client for testing
    └── roam-bench/                # Performance benchmarks
```

```rust
// roam-sync/src/traits.rs

/// Core trait for any state that can be synchronized
/// This is the extension point for all applications
pub trait SyncState: Clone + Send + Sync + 'static {
    /// The diff representation (can be same as Self for simple states)
    type Diff: Clone + Send + Sync;

    /// Unique type identifier for protocol negotiation
    const STATE_TYPE_ID: &'static str;

    /// Compute minimal diff from old state to self
    fn diff_from(&self, old: &Self) -> Self::Diff;

    /// Apply diff to produce new state
    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError>;

    /// Serialize diff for wire transmission
    fn encode_diff(diff: &Self::Diff) -> Vec<u8>;

    /// Deserialize diff from wire format
    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError>;

    /// Optional: Check if diff is empty (optimization)
    fn is_diff_empty(diff: &Self::Diff) -> bool { false }
}

/// Optional trait for states that support prediction
pub trait Predictable: SyncState {
    /// User input type
    type Input;

    /// Apply speculative input locally
    fn predict(&mut self, input: &Self::Input);

    /// Called when server confirms/corrects prediction
    fn reconcile(&mut self, authoritative: &Self);
}

/// Optional trait for states that need custom serialization
pub trait WireFormat: SyncState {
    /// Override default encoding (e.g., use protobuf, msgpack)
    fn wire_encode(&self) -> Vec<u8>;
    fn wire_decode(data: &[u8]) -> Result<Self, DecodeError>;
}
```

---

## Crate Architecture (Refined)

```
roam/
├── crates/
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │           CORE PROTOCOL (transport-agnostic)        │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── roam-core/              # Traits + shared types only
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── traits.rs       # SyncState, Predictable, WireFormat
│   │   │   ├── version.rs      # State versioning primitives
│   │   │   ├── error.rs        # Common error types
│   │   │   └── capability.rs   # Extension negotiation types
│   │   └── Cargo.toml          # ZERO dependencies (maybe just thiserror)
│   │
│   ├── roam-crypto/            # Security layer
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── noise.rs        # Noise_IK via snow
│   │   │   ├── aead.rs         # XChaCha20-Poly1305
│   │   │   ├── keys.rs         # Key types with Zeroize
│   │   │   └── session.rs      # Session key management, rekeying
│   │   └── Cargo.toml          # deps: snow, chacha20poly1305, zeroize
│   │
│   ├── roam-transport/         # UDP + connection management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── socket.rs       # Async UDP wrapper
│   │   │   ├── connection.rs   # Connection state machine
│   │   │   ├── migration.rs    # IP roaming logic
│   │   │   ├── frame.rs        # Packet framing
│   │   │   └── timing.rs       # RTT, keepalive
│   │   └── Cargo.toml          # deps: roam-crypto, tokio
│   │
│   ├── roam-sync/              # State synchronization engine
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── engine.rs       # Sync engine (generic over SyncState)
│   │   │   ├── sender.rs       # Outbound state management
│   │   │   ├── receiver.rs     # Inbound diff application
│   │   │   ├── prediction.rs   # Prediction engine (generic)
│   │   │   └── ack.rs          # Acknowledgment tracking
│   │   └── Cargo.toml          # deps: roam-core, roam-transport
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │           DOMAIN-SPECIFIC STATE IMPLEMENTATIONS     │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── roam-terminal/          # Terminal state (for MoshiMoshi)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── state.rs        # impl SyncState for TerminalState
│   │   │   ├── framebuffer.rs  # Cell grid
│   │   │   ├── cursor.rs
│   │   │   ├── diff.rs         # Terminal-specific diff encoding
│   │   │   ├── prediction.rs   # impl Predictable for TerminalState
│   │   │   └── parser.rs       # VT sequences (uses vte crate)
│   │   └── Cargo.toml          # deps: roam-core, vte
│   │
│   │  ┌─────────────────────────────────────────────────────┐
│   │  │           HIGH-LEVEL CLIENT/SERVER                  │
│   │  └─────────────────────────────────────────────────────┘
│   │
│   ├── roam-client/            # Generic client library
│   │   └── Cargo.toml          # deps: roam-sync, roam-transport
│   │
│   └── roam-server/            # Generic server library
│       └── Cargo.toml          # deps: roam-sync, roam-transport
│
└── examples/
    ├── terminal/               # MoshiMoshi-style terminal
    ├── counter/                # Simplest possible: sync a number
    ├── canvas/                 # Collaborative whiteboard
    └── chat/                   # Encrypted chat over roam
```

---

## Dependency Graph (What Depends on What)

```
                    ┌─────────────┐
                    │  roam-core  │  ← ZERO external deps
                    │  (traits)   │     Pure Rust, no-std compatible
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
   │roam-crypto  │  │roam-terminal│  │ roam-canvas  │
   │             │  │             │  │ (example)    │
   │ snow        │  │ vte         │  │              │
   │ chacha20    │  │ impl Sync   │  │ impl Sync    │
   │ zeroize     │  │ State for   │  │ State for    │
   └──────┬──────┘  │ Terminal    │  │ Canvas       │
          │         └──────┬──────┘  └──────┬───────┘
          │                │                │
          ▼                │                │
   ┌─────────────┐         │                │
   │roam-transport         │                │
   │             │         │                │
   │ tokio       │         │                │
   │ UDP sockets │         │                │
   └──────┬──────┘         │                │
          │                │                │
          ▼                │                │
   ┌─────────────┐         │                │
   │  roam-sync  │◄────────┴────────────────┘
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
