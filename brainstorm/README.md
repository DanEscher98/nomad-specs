# Roam Protocol

A modern state-synchronization protocol for resilient remote terminals.

## Acknowledgments

Roam is inspired by [Mosh](https://mosh.org/) and its State Synchronization
Protocol (SSP), developed by Keith Winstein and colleagues at MIT. We are
grateful for their pioneering work on UDP-based terminal protocols with
predictive local echo.

Roam is a new protocol implementation that is **not compatible** with Mosh.
It draws on the same principles but makes different design choices for
modern use cases. If you need Mosh compatibility, use the original
[mosh client](https://mosh.org/).

Key differences from Mosh/SSP:

- Scrollback synchronization support
- Modern cipher options (ChaCha20-Poly1305)
- Documented specification
- Standalone Rust library
- Extension negotiation for future features

## Applications for roam-protocol

| Application              | Why `roam` fits                              | Existing Solution's Problems     |
| :----------------------- | :------------------------------------------- | :------------------------------- |
| Collaborative Whiteboard | State=canvas, survives WiFi drops            | WebSocket dies on network change |
| Mobile Game State        | Authoritative server, client prediction      | TCP adds 100ms+ on cell networks |
| Live Dashboards          | Metrics state synce to table                 | WebSocket reconnection jank      |
| IoT Device Control       | Thermostat state, survives poor connectivity | MQTT doesn't do state sync       |
| Music Collaboration      | DAW state sync, latency-critical             | Nothing exists for mobile        |
| Pair Programming         | Cursor + selection state                     | VS Code LiveShare is TCP-bound   |
| Remote Desktop (lite)    | Screen regions as state                      | Full protocols too heavy         |

```
roam-transport  = UDP + encryption + connection management
roam-sync       = State synchronization logic (transport-agnostic!)
```

## Summary: What to Build First

```
Phase 1: Foundation (roam-core + roam-crypto)
├── Define SyncState trait
├── Implement Noise_IK handshake
├── XChaCha20-Poly1305 AEAD
└── Session key management

Phase 2: Transport (roam-transport)
├── UDP socket abstraction
├── Connection state machine
├── IP migration
└── Packet framing

Phase 3: Sync Engine (roam-sync)
├── Generic sync engine
├── Diff/ack tracking
├── Prediction framework
└── Integration tests with Counter example

Phase 4: Terminal (roam-terminal)
├── impl SyncState for TerminalState
├── Framebuffer + diff encoding
├── Local echo prediction
└── VT parser integration

Phase 5: MoshiMoshi
├── Tauri app using roam-client + roam-terminal
├── Touch UI
└── Everything else
```

## Hybrid approach (like WireGuard + Mosh)

- Protocol layer: Fixed binary format with explicit byte layouts (auditable, no dependencies)
- State payloads: Application-defined (recommend Protobuf)

| Layer         | Format           | Rationale                                     |
| ------------- | ---------------- | --------------------------------------------- |
| Frame headers | Fixed binary     | Auditable, no dependencies, security-critical |
| Sync messages | Fixed binary     | Version/ack numbers need exact byte layout    |
| State diffs   | Protocol Buffers | Cross-language, schema evolution, faimilar    |

```
PROTOCOL.md          ← Core protocol (language-agnostic)
├── Security layer   ← Noise_IK + XChaCha20
├── Transport layer  ← UDP framing, roaming
├── Sync layer       ← State versioning, acks
└── Extensions       ← Compression, scrollback, etc.

TERMINAL.md          ← Terminal state type
├── State structure  ← Framebuffer, cursor, modes
├── Diff encoding    ← Protobuf schema
├── Prediction       ← Local echo algorithm
└── Security notes   ← Password detection
```

### Why Protobuf for State Diffs

- Cross-language codegen: protoc generates Rust, Go, Python, TypeScript
- Schema evolution: Add fields without breaking old clients
- Well-known: Contributors already know it
- Compact: Varint encoding, optional fields skip zeros
- Mosh precedent: Proven for terminal state
