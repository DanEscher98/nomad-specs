```txt
┌────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │
│  │  MoshiMoshi   │  │  Future App   │  │  Future App   │   │
│  │  (Terminal)   │  │  (Whiteboard) │  │  (Game State) │   │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘   │
│          │                  │                  │           │
├──────────┼──────────────────┼──────────────────┼───────────┤
│          │      STATE LAYER (Domain-specific)  │           │
│  ┌───────▼───────┐  ┌───────▼───────┐  ┌───────▼───────┐   │
│  │ roam-terminal │  │ roam-canvas   │  │ roam-gamestate│   │
│  │               │  │               │  │               │   │
│  │ impl State    │  │ impl State    │  │ impl State    │   │
│  │ for Terminal  │  │ for Canvas    │  │ for GameWorld │   │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘   │
│          │                  │                  │           │
├──────────┴──────────────────┴──────────────────┴───────────┤
│                    SYNC LAYER (roam-sync)                  │
│  • State versioning         • Diff generation              │
│  • Ack tracking             • Prediction engine (optional) │
│  • Convergence guarantees   • Implements SyncState trait   │
└─────────────────────────────────┬──────────────────────────┘
                                  │
┌─────────────────────────────────┴──────────────────────────┐
│                    TRANSPORT LAYER (roam-transport)        │
│  • UDP socket management    • Connection migration         │
│  • Packet framing           • Keepalive / heartbeat        │
│  • Reliability (optional)   • Congestion hints             │
└─────────────────────────────────┬──────────────────────────┘
                                  │
┌─────────────────────────────────┴──────────────────────────┐
│                    SECURITY LAYER (roam-crypto)            │
│  • Noise_IK handshake       • Session key derivation       │
│  • XChaCha20-Poly1305       • Rekeying                     │
│  • Nonce management         • Key zeroization              │
└────────────────────────────────────────────────────────────┘
```
