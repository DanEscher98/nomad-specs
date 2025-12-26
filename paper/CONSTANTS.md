# NOMAD Protocol Constants Reference

This document maps all protocol constants to their rationale and external references, prepared for technical review and scrutiny.

---

## Cryptographic Constants

### Key and Tag Sizes

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `PUBLIC_KEY_SIZE` | 32 bytes | X25519 public key size, standard for Curve25519 | [RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748#section-5) |
| `PRIVATE_KEY_SIZE` | 32 bytes | X25519 private key (scalar) size | [RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748#section-5) |
| `AEAD_TAG_SIZE` | 16 bytes | Poly1305 authentication tag, provides 128-bit security | [RFC 8439 §2.5](https://www.rfc-editor.org/rfc/rfc8439#section-2.5) |
| `AEAD_NONCE_SIZE` | 24 bytes | XChaCha20 extended nonce, allows random generation without birthday-bound concerns | [XChaCha draft §2.1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.1) |
| `HASH_SIZE` | 32 bytes | BLAKE2s-256 output, used in Noise for chaining key derivation | [RFC 7693 §1](https://www.rfc-editor.org/rfc/rfc7693#section-1) |

### Why These Choices

**XChaCha20-Poly1305 over AES-GCM:**
- Software-only implementations without timing side channels
- 24-byte nonce eliminates nonce management complexity (random nonces safe)
- Mosh used AES-OCB which is less common; ChaCha20 is now IETF standard

**BLAKE2s over SHA-256:**
- Faster in software
- Required by Noise Protocol Framework for 32-byte hash functions
- Same security level (128-bit)

**X25519 over ECDH-P256:**
- Simpler, constant-time implementations
- No patents
- Standard choice in Noise, WireGuard, Signal

---

## Session Constants

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `SESSION_ID_SIZE` | 6 bytes (48 bits) | Balance between collision resistance and header overhead. Birthday paradox gives ~50% collision at 2^24 (~16M) sessions. Acceptable for single-server deployment. | NOMAD design choice; WireGuard uses 4 bytes |
| `PROTOCOL_VERSION` | `0x0001` | Version 1.0, allows future incompatible changes | NOMAD spec |

### Session ID Collision Analysis

With 48-bit session IDs:
- 50% collision probability after ~16 million concurrent sessions
- 1% collision probability after ~330,000 concurrent sessions
- Responders MUST track active IDs and reject collisions
- Retry up to 3 times on collision

---

## Timing Constants - Security Layer

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `REKEY_AFTER_TIME` | 120 seconds (2 min) | Forward secrecy window; compromise of current keys reveals max 2 min of traffic | WireGuard uses same value ([WireGuard §5.4](https://www.wireguard.com/papers/wireguard.pdf)) |
| `REJECT_AFTER_TIME` | 180 seconds (3 min) | Hard limit; MUST rekey before this or session terminates | WireGuard uses same value |
| `REKEY_AFTER_MESSAGES` | 2^60 | Soft limit before nonce exhaustion; triggers proactive rekey | WireGuard uses 2^60 |
| `REJECT_AFTER_MESSAGES` | 2^64 - 1 | Hard limit; nonce space exhausted, MUST terminate | XChaCha20 nonce counter is 64-bit |
| `OLD_KEY_RETENTION` | 5 seconds | Grace period for in-flight packets during rekey transition | NOMAD design; based on typical RTT + jitter |
| `HANDSHAKE_TIMEOUT` | 1000 ms (1 sec) | Initial retransmit timeout for handshake packets | Similar to TCP initial RTO |
| `HANDSHAKE_MAX_RETRIES` | 5 | Max attempts before giving up; 5 retries with backoff = ~31s total | Standard practice |
| `HANDSHAKE_BACKOFF` | 2x | Exponential backoff multiplier | RFC 6298 recommendation |

### Forward Secrecy Rationale

The 2-minute rekey interval means:
- Attacker who compromises session keys can decrypt max 2 minutes of past traffic
- Fresh ephemeral DH on each rekey provides post-compromise security
- Same interval as WireGuard, proven in practice

### Nonce Exhaustion Protection

With 64-bit counters and 2-minute rekeying:
- At 50 Hz frame rate: 6,000 frames per epoch
- At max theoretical: 2^64 frames would take ~584 billion years at 1 Gbps
- Soft limit at 2^60 provides 16x safety margin

---

## Timing Constants - Transport Layer

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `INITIAL_RTO` | 1000 ms (1 sec) | Conservative initial timeout before RTT measurement | [RFC 6298 §2.1](https://www.rfc-editor.org/rfc/rfc6298#section-2.1) |
| `MIN_RTO` | 100 ms | Floor prevents excessive retransmission on fast networks | RFC 6298 recommends 1s; we use 100ms for interactive apps |
| `MAX_RTO` | 60000 ms (60 sec) | Cap prevents unbounded backoff | Standard practice |
| `KEEPALIVE_INTERVAL` | 25 seconds | Send keepalive if idle; keeps NAT mappings alive (typical NAT timeout 30-60s) | Mosh uses 3s; we use 25s to reduce overhead |
| `DEAD_INTERVAL` | 60 seconds | Connection timeout if no authenticated frames received | 2x typical NAT timeout |
| `MIN_FRAME_INTERVAL` | max(SRTT/2, 20ms) | Pacing to prevent congestion; roughly one frame in flight | Mosh design principle |
| `COLLECTION_INTERVAL` | 8 ms | Batch rapid state changes (e.g., fast typing) into single frame | Slightly above typical key repeat rate |
| `DELAYED_ACK_TIMEOUT` | 100 ms | Max delay for ack-only frame; allows piggybacking on data | Similar to TCP delayed ACK |
| `MAX_FRAME_RATE` | 50 Hz | Human perception threshold; faster updates waste bandwidth | Mosh observation: 50Hz sufficient for smooth UI |

### RTT Estimation (RFC 6298)

```
SRTT = 0.875 * SRTT + 0.125 * sample    (α = 1/8)
RTTVAR = 0.75 * RTTVAR + 0.25 * |SRTT - sample|    (β = 1/4)
RTO = SRTT + max(100ms, 4 * RTTVAR)
```

These smoothing factors are from RFC 6298 and proven over decades of TCP deployment.

### Frame Pacing Rationale

- **SRTT/2 interval**: Ensures roughly one frame in flight, preventing queue buildup
- **8ms collection**: At 125 chars/sec typing, batches ~1 char per frame
- **50 Hz cap**: Studies show 20-30ms update latency is imperceptible

---

## Timing Constants - Retransmission

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `MAX_RETRANSMITS` | 10 | Give up after 10 retries; with backoff, total wait ~34 minutes | Standard practice |
| `RETRANSMIT_BACKOFF` | 2x | Exponential backoff on timeout | RFC 6298 |

---

## Anti-Replay Constants

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `REPLAY_WINDOW_SIZE` | 2048 bits minimum | Sliding window for nonce tracking; handles reordering up to 2048 packets | WireGuard uses 2048; IPsec minimum is 32 |

### Window Size Justification

- 2048-bit window handles severe reordering scenarios
- At 50 Hz, covers ~41 seconds of out-of-order delivery
- Memory cost: 256 bytes per direction
- WireGuard uses identical window size

---

## Extension Constants

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `MIN_COMPRESS_SIZE` | 64 bytes | Don't compress small payloads; zstd overhead may exceed savings | Empirical; typical zstd header is ~10 bytes |
| `COMPRESSION_LEVEL_DEFAULT` | 3 | Balance between ratio and CPU; zstd level 3 is fast mode | [zstd documentation](https://github.com/facebook/zstd) |
| `COMPRESSION_LEVEL_MAX` | 22 | zstd maximum level | zstd specification |

---

## MTU Constants

| Constant | Value | Rationale | Reference |
|----------|-------|-----------|-----------|
| `DEFAULT_MAX_PAYLOAD` | 1200 bytes | Conservative for all networks including IPv6 minimum MTU | IPv6 minimum MTU is 1280; 1200 leaves room for headers |
| `ETHERNET_MAX_PAYLOAD` | 1400 bytes | For known Ethernet networks (1500 MTU - IP/UDP headers) | Standard Ethernet |

---

## Frame Type Values

| Type | Value | Description |
|------|-------|-------------|
| `HandshakeInit` | `0x01` | Initiate Noise_IK handshake |
| `HandshakeResp` | `0x02` | Handshake response |
| `Data` | `0x03` | Encrypted data frame |
| `Rekey` | `0x04` | Initiate rekeying |
| `Close` | `0x05` | Graceful termination |

---

## Extension Type Values

| Type | Value | Scope | Description |
|------|-------|-------|-------------|
| `Compression` | `0x0001` | Core | zstd payload compression |
| `Scrollback` | `0x0002` | Terminal | Scrollback buffer sync |
| `Prediction` | `0x0003` | Terminal | Client-side keystroke prediction |
| `Multiplex` | `0x0004` | Future | Multiple state streams |
| `PostQuantum` | `0x0005` | Future | Hybrid X25519+ML-KEM |

---

## External References Summary

| Component | Specification | Why We Use It |
|-----------|---------------|---------------|
| **Noise_IK** | [Noise Protocol Framework](https://noiseprotocol.org/noise.html) | 1-RTT mutual authentication with identity hiding |
| **X25519** | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) | Fast, constant-time ECDH |
| **XChaCha20-Poly1305** | [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) | AEAD with extended nonce |
| **ChaCha20-Poly1305** | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) | Base AEAD construction |
| **BLAKE2s** | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) | Fast hash for Noise |
| **RTT estimation** | [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298) | Proven TCP algorithm |
| **zstd** | [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878) | Fast compression |

---

## Comparison with Related Protocols

| Constant | NOMAD | Mosh | WireGuard |
|----------|-------|------|-----------|
| Rekey interval | 120s | N/A (no rekey) | 120s |
| Session ID | 48 bits | N/A | 32 bits |
| AEAD | XChaCha20-Poly1305 | AES-128-OCB | ChaCha20-Poly1305 |
| Nonce size | 24 bytes | 8 bytes | 12 bytes |
| Replay window | 2048 | N/A | 2048 |
| Keepalive | 25s | 3s | 25s |

---

*Document prepared for arXiv submission review - December 2025*
