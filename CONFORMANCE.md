# Roam Protocol Conformance Testing

This document describes how to test your Roam Protocol implementation against the conformance test suite.

## Overview

The conformance suite validates that your implementation correctly follows the Roam Protocol specification. It tests:

- **Handshake**: Noise_IK key exchange
- **Transport**: Frame encoding, nonce management, anti-replay
- **Sync**: State versioning, diff encoding, convergence
- **Security**: Replay rejection, malformed packet handling
- **Wire format**: Byte-level protocol compliance

## Quick Start

### 1. Implement the Container Interface

Your implementation must be packaged as a Docker image with the following interface:

```yaml
# Environment variables your container must accept:
ROAM_MODE: server | client
ROAM_SERVER_PRIVATE_KEY: base64  # Server only
ROAM_SERVER_PUBLIC_KEY: base64   # Both
ROAM_STATE_TYPE: string          # e.g., "roam.echo.v1"
ROAM_LOG_LEVEL: debug | info | warn | error
ROAM_BIND_ADDR: host:port        # Server only, default 0.0.0.0:19999
ROAM_SERVER_HOST: hostname       # Client only
ROAM_SERVER_PORT: port           # Client only

# Ports your server must expose:
19999/udp: Roam protocol
8080/tcp:  Health check endpoint

# Health check endpoint:
GET /health -> 200 OK (when ready to accept connections)
GET /status -> 200 JSON (optional, for debugging)
GET /ready  -> 200 OK (optional, when fully initialized)
```

### 2. Create a Multi-Target Dockerfile

Your Dockerfile should support both `server` and `client` build targets:

```dockerfile
# Example structure
FROM your-base AS base
# ... install dependencies ...

FROM base AS server
EXPOSE 19999/udp
EXPOSE 8080/tcp
CMD ["your-server-binary"]

FROM base AS client
CMD ["your-client-binary"]
```

### 3. Run the Conformance Suite

```bash
# Clone the specs repo
git clone https://github.com/your-org/roam-specs.git
cd roam-specs

# Point to your implementation
export SERVER_CONTEXT=/path/to/your/implementation
export SERVER_DOCKERFILE=Dockerfile
export CLIENT_CONTEXT=/path/to/your/implementation
export CLIENT_DOCKERFILE=Dockerfile

# Run tests
just test
```

## Detailed Requirements

### Server Requirements

#### Health Check Endpoint

Your server MUST expose an HTTP health check endpoint on port 8080:

```
GET /health
Response: 200 OK (text/plain)
Body: OK
```

The health endpoint SHOULD return 200 only when:
1. The UDP socket is bound and listening
2. The server is ready to accept handshakes
3. All initialization is complete

#### UDP Protocol Port

The server MUST listen on UDP port 19999 for Roam protocol traffic.

#### Logging

When `ROAM_LOG_LEVEL=debug`, log:
- All received packets (hex dump first 32 bytes)
- All sent packets (hex dump first 32 bytes)
- Handshake progress
- State sync events
- Errors with full context

### Client Requirements

#### Server Connection

The client MUST:
1. Read `ROAM_SERVER_HOST` and `ROAM_SERVER_PORT` from environment
2. Use `ROAM_SERVER_PUBLIC_KEY` for handshake
3. Initiate Noise_IK handshake on startup

### State Type: roam.echo.v1

For conformance testing, implement the `roam.echo.v1` state type:

```
State: UTF-8 string (max 1024 bytes)
Diff: Full state replacement (no delta encoding)

Server behavior:
- Echo back any received state
- Prepend "Echo: " to received content

Client behavior:
- Send user input as state
- Display received state
```

This simple state type allows testing the sync layer without complex application logic.

## Test Categories

### Unit Tests (`tests/unit/`)

Pure logic tests that don't require containers:
- Frame encoding/decoding
- Nonce generation
- Crypto primitives (against test vectors)

Run with: `just test-unit`

### Protocol Tests (`tests/protocol/`)

Behavioral tests using containers:
- Handshake establishment
- State synchronization
- Rekeying
- Roaming (IP change)

Run with: `just test-protocol`

### Wire Tests (`tests/wire/`)

Byte-level validation using packet capture:
- Frame format compliance
- Packet size limits
- Encryption verification

Run with: `just test-wire`

### Adversarial Tests (`tests/adversarial/`)

Security tests:
- Replay attack rejection
- Malformed packet handling
- Invalid authentication

Run with: `just test-adversarial`

### Interop Tests (`tests/interop/`)

Cross-implementation testing:
- Rust client ↔ Go server
- Go client ↔ Rust server
- All pairwise combinations

Run with: `just test-interop`

## Test Vectors

Test vectors are provided in `tests/vectors/`:

```
tests/vectors/
├── handshake_vectors.json5   # Noise_IK test cases
├── frame_vectors.json5       # Frame encoding test cases
└── sync_vectors.json5        # Sync message test cases
```

Each vector includes:
- Input values
- Expected output
- Description of what's being tested
- Reference to spec section

Use these vectors to validate your implementation before running the full suite.

## Running Specific Tests

```bash
# Run all tests
just test

# Run specific category
just test-unit
just test-protocol
just test-wire

# Run with pytest options
uv run pytest tests/protocol/test_handshake.py -v

# Run with coverage
uv run pytest --cov=lib tests/

# Run in parallel
uv run pytest -n auto tests/
```

## Debugging Failed Tests

### Container Logs

```bash
# Get server logs
docker logs roam-test-server

# Get client logs
docker logs roam-test-client
```

### Packet Capture

Enable packet capture in tests:

```python
def test_with_capture(packet_capture, server_container):
    with packet_capture.capture() as pcap_file:
        # ... test code ...

    # Analyze with wireshark or scapy
    packets = rdpcap(pcap_file)
```

### Interactive Debugging

```bash
# Start containers manually
docker compose -f docker/docker-compose.yml up -d

# Exec into server
docker exec -it roam-server /bin/sh

# Watch traffic
docker exec roam-tcpdump tcpdump -i eth0 -X udp port 19999
```

## Common Issues

### Health Check Timeout

**Symptom**: Tests fail waiting for server health check

**Causes**:
1. Server not binding to 0.0.0.0 (binding to 127.0.0.1)
2. Health endpoint not on port 8080
3. Initialization taking too long

**Fix**: Ensure server binds to `0.0.0.0:8080` for health checks.

### Connection Refused

**Symptom**: Client can't connect to server

**Causes**:
1. Server not listening on UDP 19999
2. Network misconfiguration
3. Firewall blocking

**Fix**: Verify UDP socket is bound before health check returns 200.

### Handshake Failure

**Symptom**: Handshake doesn't complete

**Causes**:
1. Wrong public key
2. Protocol version mismatch
3. Byte order issues (must be little-endian)

**Fix**: Compare handshake bytes against test vectors.

## Submitting Compliance Results

After passing the conformance suite:

1. Run the full suite with verbose output:
   ```bash
   just test 2>&1 | tee conformance-results.txt
   ```

2. Include in your documentation:
   - Implementation language/version
   - Test suite version (git commit)
   - Any skipped tests with justification
   - Performance notes (optional)

## Version Compatibility

| Spec Version | Test Suite Version | Notes |
|--------------|-------------------|-------|
| 1.0-draft    | v0.1.x            | Initial release |

## Contributing

Found a bug in the test suite? Please open an issue with:
- Test name
- Expected behavior
- Actual behavior
- Your implementation details

## License

The conformance suite is released under MIT license.
