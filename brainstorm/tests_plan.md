- `hypothesis`: Property-based: "for all valid inputs, X holds". Finds edge cases humans miss (nonce overflow, malformed UTF-8)
- `scapy`: Packet capture/injection on docker network
- pytest: Fixtures for container lifecycle, parametrized tests
- docker: Any language compiles to container, same test interface

```
roam-specs/
├── tests/                          # THE CONFORMANCE SUITE
│   ├── pyproject.toml              # uv config
│   ├── conftest.py                 # pytest fixtures (container management)
│   │
│   ├── vectors/                    # Static test vectors (JSON)
│   │   ├── handshake_vectors.json
│   │   ├── frame_vectors.json
│   │   ├── sync_vectors.json
│   │   └── terminal_diff_vectors.json
│   │
│   ├── unit/                       # Pure logic tests (no containers)
│   │   ├── test_frame_encoding.py
│   │   ├── test_nonce_generation.py
│   │   ├── test_diff_encoding.py
│   │   └── test_crypto_primitives.py
│   │
│   ├── protocol/                   # Protocol behavior tests
│   │   ├── test_handshake.py       # Noise_IK exchange
│   │   ├── test_rekeying.py        # Session key rotation
│   │   ├── test_roaming.py         # IP migration
│   │   ├── test_replay_rejection.py
│   │   ├── test_sync_convergence.py
│   │   └── test_timeout_handling.py
│   │
│   ├── wire/                       # Network-level tests (packet inspection)
│   │   ├── test_wire_format.py     # Byte-level validation
│   │   ├── test_packet_sizes.py    # MTU compliance
│   │   └── test_encryption.py      # Ciphertext randomness
│   │
│   ├── interop/                    # Cross-implementation tests
│   │   ├── test_rust_client_rust_server.py
│   │   ├── test_go_client_rust_server.py
│   │   ├── test_rust_client_go_server.py
│   │   └── matrix.py               # Generate all combinations
│   │
│   ├── adversarial/                # Security tests
│   │   ├── test_malformed_packets.py
│   │   ├── test_replay_attacks.py
│   │   ├── test_truncated_frames.py
│   │   └── test_invalid_auth.py
│   │
│   ├── lib/                        # Test utilities
│   │   ├── __init__.py
│   │   ├── containers.py           # Docker management
│   │   ├── network.py              # scapy helpers
│   │   ├── generators.py           # hypothesis strategies
│   │   └── reference.py            # Python reference encoder/decoder
│   │
│   └── docker/
│       ├── docker-compose.yaml
│       ├── docker-compose.interop.yaml
│       └── network-simulation/
│           └── tc-netem.sh         # Traffic control for lossy networks
│
└── implementations/
    ├── rust/                       # Reference implementation
    ├── go/
    └── CONFORMANCE.md              # How to plug your implementation
```
