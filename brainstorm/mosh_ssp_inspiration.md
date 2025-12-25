## Keep from Mosh/SSP

- ✅ State Synchronization model (not byte streams)
- ✅ UDP-based transport
- ✅ Predictive local echo
- ✅ Idempotent state updates
- ✅ Diff-based synchronization
- ✅ Server-authoritative state

## Change/Improve

- CRYPTO: AES-128-OCB3 → ChaCha20-Poly1305 (or both, negotiated)
  - Better Rust support, modern standard
  - Optional: AEGIS-128L for ARM NEON (blazing fast on mobile)

- FRAMING: Protobuf → MessagePack or custom binary
  - Protobuf is fine, but consider lighter options
  - Or keep protobuf, it works

- SCROLLBACK: Add scrollback synchronization
  - SSP's biggest missing feature
  - Optional server-side scrollback buffer

- AUTH: Standalone auth layer (not SSH-dependent)
  - SSH for bootstrap (like mosh), OR
  - Token-based reconnection auth
  - Allows direct UDP connection after initial auth

- EXTENSIBILITY: Version negotiation + extensions
  - Future-proof from day 1
  - Client/server capability advertisement

- COMPRESSION: Optional zstd compression
  - For large outputs (builds, logs)
