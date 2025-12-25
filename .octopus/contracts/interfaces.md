# Contracts - Shared Interfaces

## Container Interface (t5-docker defines, others consume)

Implementations must expose:

```yaml
# Environment variables
ROAM_SERVER_PRIVATE_KEY: base64  # Server's static private key
ROAM_SERVER_PUBLIC_KEY: base64   # Server's static public key
ROAM_STATE_TYPE: string          # e.g., "roam.echo.v1"
ROAM_LOG_LEVEL: debug|info|warn

# Ports
19999/udp: Roam protocol
8080/tcp:  Health check endpoint

# Health check
GET /health -> 200 OK
```

## Reference Codec Interface (t6-vectors defines, tests consume)

```python
# tests/lib/reference.py

class RoamCodec:
    """Full protocol reference implementation."""

    # Handshake
    def create_handshake_init(self, initiator_static, responder_static_pub, state_type) -> bytes
    def parse_handshake_init(self, data: bytes) -> HandshakeInit
    def create_handshake_response(self, session_id, responder_ephemeral) -> bytes
    def parse_handshake_response(self, data: bytes) -> HandshakeResponse

    # Frames
    def create_data_frame(self, session_id, nonce, payload, key) -> bytes
    def parse_data_frame(self, data: bytes, key) -> DataFrame

    # Sync messages
    def create_sync_message(self, sender_num, acked_num, base_num, diff) -> bytes
    def parse_sync_message(self, data: bytes) -> SyncMessage
```

## Test Vector Format (t6-vectors defines, all tests consume)

```json5
{
  // Metadata
  "_generator": "specs/generate_vectors.py",
  "_version": "1.0",
  "_generated_at": "2025-01-XX",

  "handshake_vectors": [
    {
      // Human-readable description
      "description": "Valid Noise_IK handshake with test keypairs",

      // Inputs (what goes into the function)
      "initiator_static_private": "base64...",
      "initiator_ephemeral_private": "base64...",  // Fixed for reproducibility
      "responder_static_public": "base64...",

      // Expected outputs
      "expected_init_message": "hex...",
      "expected_session_keys": {
        "initiator_send": "base64...",
        "initiator_recv": "base64..."
      }
    }
  ]
}
```

## pytest Fixtures (t5-docker defines, all tests consume)

```python
# tests/conftest.py

@pytest.fixture
def server_container() -> Container:
    """Running server container with health check passed."""

@pytest.fixture
def client_container() -> Container:
    """Running client container connected to server."""

@pytest.fixture
def packet_capture() -> PacketCapture:
    """Scapy capture on the docker network."""

@pytest.fixture
def test_keypairs() -> KeyPairs:
    """Deterministic keypairs for reproducible tests."""
```
