# Roam Protocol Specification

**Version:** 1.0-draft  
**Status:** Draft  
**Last Updated:** 2025-01-XX

---

## Abstract

Roam is a secure, UDP-based state synchronization protocol designed for real-time applications over unreliable networks. It provides authenticated encryption, seamless connection migration across IP address changes, and a generic state synchronization framework with optional client-side prediction.

Roam is inspired by [Mosh](https://mosh.org/) (Mobile Shell) and its State Synchronization Protocol, but is a new protocol with different design choices. **Roam is not compatible with Mosh.**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Overview](#3-protocol-overview)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Handshake Protocol](#5-handshake-protocol)
6. [Transport Layer](#6-transport-layer)
7. [Packet Format](#7-packet-format)
8. [State Synchronization](#8-state-synchronization)
9. [Session Management](#9-session-management)
10. [Extension Mechanism](#10-extension-mechanism)
11. [Security Considerations](#11-security-considerations)
12. [State Type Registry](#12-state-type-registry)
13. [Reference Implementation Notes](#13-reference-implementation-notes)

---

## 1. Introduction

### 1.1 Design Goals

1. **Security**: End-to-end authenticated encryption with forward secrecy
2. **Mobility**: Seamless operation across IP address changes (roaming)
3. **Latency**: Sub-100ms reconnection, optional client-side prediction
4. **Simplicity**: Fixed cryptographic suite, no negotiation
5. **Generality**: State-agnostic synchronization framework

### 1.2 Non-Goals

- Backward compatibility with Mosh/SSP
- Cipher suite negotiation
- Reliable ordered delivery (applications handle this via state sync)
- Multiplexing multiple state types in one session

### 1.3 Acknowledgments

Roam draws inspiration from:

- **Mosh** by Keith Winstein et al. — State synchronization model
- **WireGuard** by Jason Donenfeld — Security architecture
- **Noise Protocol Framework** by Trevor Perrin — Key exchange

---

## 2. Terminology

| Term          | Definition                                                       |
| ------------- | ---------------------------------------------------------------- |
| **Initiator** | The party that starts the connection (typically the client)      |
| **Responder** | The party that accepts connections (typically the server)        |
| **Session**   | A cryptographic context between two parties, survives IP changes |
| **Epoch**     | A period using a single set of session keys (until rekey)        |
| **State**     | Application-specific data being synchronized                     |
| **Diff**      | A delta representing changes between two state versions          |
| **Frame**     | A single encrypted UDP datagram                                  |
| **Handshake** | The Noise_IK key exchange establishing a session                 |

### 2.1 Notation

```
||      Concatenation
len(x)  Length of x in bytes
LE32    32-bit little-endian unsigned integer
LE64    64-bit little-endian unsigned integer
[n]     Array of n bytes
```

---

## 3. Protocol Overview

### 3.1 Layer Architecture

```
┌─────────────────────────────────────────────────────┐
│              APPLICATION LAYER                      │
│   (Terminal, Whiteboard, Game, etc.)                │
│   Implements: StateType trait                       │
├─────────────────────────────────────────────────────┤
│              SYNC LAYER                             │
│   State versioning, diff generation, ack tracking   │
│   Optional: Prediction engine                       │
├─────────────────────────────────────────────────────┤
│              TRANSPORT LAYER                        │
│   Frame construction, sequence numbers              │
│   Connection migration, keepalive                   │
├─────────────────────────────────────────────────────┤
│              SECURITY LAYER                         │
│   Noise_IK handshake, XChaCha20-Poly1305 AEAD       │
│   Session key derivation, rekeying                  │
├─────────────────────────────────────────────────────┤
│              UDP                                    │
└─────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│                    ROAM PROTOCOL v1                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LAYER 1: TRANSPORT                                         │
│  ├── UDP datagrams                                          │
│  ├── Connection ID (survives IP changes)                    │
│  ├── Sequence numbers + ack                                 │
│  └── Keepalive / heartbeat                                  │
│                                                             │
│  LAYER 2: SECURITY                                          │
│  ├── Key exchange via SSH (initial) or Token (reconnect)    │
│  ├── ChaCha20-Poly1305 AEAD (primary)                       │
│  ├── AES-128-OCB3 AEAD (optional, for mosh research compat) │
│  └── Nonce: connection_id + sequence_number                 │
│                                                             │
│  LAYER 3: SYNCHRONIZATION                                   │
│  ├── State versioning (monotonic)                           │
│  ├── Diff encoding (server → client)                        │
│  ├── Input encoding (client → server)                       │
│  └── Acknowledgment (bidirectional)                         │
│                                                             │
│  LAYER 4: TERMINAL                                          │
│  ├── Framebuffer state (cells, attributes, cursor)          │
│  ├── Scrollback buffer (optional extension)                 │
│  ├── Window size                                            │
│  └── Terminal modes                                         │
│                                                             │
│  LAYER 5: EXTENSIONS                                        │
│  ├── Capability negotiation                                 │
│  ├── Compression (zstd)                                     │
│  ├── File transfer (future)                                 │
│  └── Multiplexing (future)                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Connection Lifecycle

```
1. BOOTSTRAP
   Initiator obtains Responder's static public key via:
   - SSH connection (like Mosh)
   - HTTPS endpoint
   - QR code / manual entry
   - Pre-shared configuration

2. HANDSHAKE (1-RTT)
   Noise_IK pattern establishes session keys

3. DATA TRANSPORT
   Encrypted frames carry state diffs and acks

4. REKEYING (every 2 minutes)
   New handshake over existing transport

5. ROAMING
   Endpoint updated when authenticated frame arrives from new IP

6. TERMINATION
   Explicit close or timeout (default: 60 seconds no activity)
```

---

## 4. Cryptographic Primitives

Roam uses a fixed cryptographic suite with no negotiation. If vulnerabilities are discovered, a new protocol version is released.

### 4.1 Algorithms

| Purpose        | Algorithm          | Reference               |
| -------------- | ------------------ | ----------------------- |
| Key Exchange   | X25519             | RFC 7748                |
| AEAD Cipher    | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha |
| Hash Function  | BLAKE2s-256        | RFC 7693                |
| Key Derivation | HKDF-BLAKE2s       | Noise specification     |

### 4.2 Constants

```
AEAD_TAG_SIZE     = 16 bytes
AEAD_NONCE_SIZE   = 24 bytes (XChaCha20)
PUBLIC_KEY_SIZE   = 32 bytes
PRIVATE_KEY_SIZE  = 32 bytes
HASH_SIZE         = 32 bytes
```

### 4.3 Key Derivation

All key derivation follows the Noise Protocol Framework specification using BLAKE2s as the hash function.

```
HKDF-Extract(salt, ikm) → prk
HKDF-Expand(prk, info, length) → okm
```

### 4.4 Why These Choices

- **X25519**: Fast, constant-time, no weak keys, widely implemented
- **XChaCha20-Poly1305**: Safe with random nonces (192-bit), fast on mobile without AES-NI
- **BLAKE2s**: Faster than SHA-256, designed for 32-bit platforms (mobile)

---

## 5. Handshake Protocol

Roam uses the **Noise_IK** pattern for mutual authentication with identity hiding for the initiator.

### 5.1 Prerequisites

- Initiator MUST know Responder's static public key (`Rs`) beforehand
- Initiator MUST have a static keypair (`Ie`, `Is`)
- Responder MUST have a static keypair (`Re`, `Rs`)

### 5.2 Handshake Pattern

```
Noise_IK(s, rs):
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

Where:

- `e` = ephemeral public key
- `s` = static public key (encrypted)
- `es`, `ss`, `ee`, `se` = DH operations mixed into symmetric state

### 5.3 Message Formats

#### 5.3.1 Handshake Initiation (Initiator → Responder)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type (1)   |   Reserved    |         Protocol Version      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                Initiator Ephemeral Public Key                 |
|                          (32 bytes)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Encrypted Initiator Static Key                   |
|                    (32 + 16 bytes AEAD)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Encrypted Payload                           |
|              (State Type ID + Extensions)                     |
|                    (variable + 16 bytes AEAD)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total minimum size: 1 + 1 + 2 + 32 + 48 + 16 = 100 bytes
```

Fields:

- **Type**: `0x01` (Handshake Initiation)
- **Reserved**: `0x00`
- **Protocol Version**: `0x0001` for version 1.0
- **Initiator Ephemeral Public Key**: 32 bytes, unencrypted
- **Encrypted Initiator Static Key**: 32-byte key + 16-byte AEAD tag
- **Encrypted Payload**: Contains `StateTypeId` and optional extensions

#### 5.3.2 Handshake Response (Responder → Initiator)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type (2)   |   Reserved    |         Session ID            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Session ID (cont.)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                Responder Ephemeral Public Key                 |
|                          (32 bytes)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Encrypted Payload                           |
|              (Ack + Extensions + variable)                    |
|                    (variable + 16 bytes AEAD)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total minimum size: 1 + 1 + 6 + 32 + 16 = 56 bytes
```

Fields:

- **Type**: `0x02` (Handshake Response)
- **Session ID**: 48-bit random identifier for this session
- **Responder Ephemeral Public Key**: 32 bytes, unencrypted
- **Encrypted Payload**: Acknowledgment and negotiated extensions

### 5.4 Post-Handshake Keys

After successful handshake, both parties derive:

```
(initiator_key, responder_key) = HKDF-Expand(
    handshake_hash,
    "roam v1 session keys",
    64
)
```

- Initiator uses `initiator_key` for sending, `responder_key` for receiving
- Responder uses `responder_key` for sending, `initiator_key` for receiving

---

## 6. Transport Layer

### 6.1 Connection State

Each endpoint maintains:

```
struct ConnectionState {
    session_id: [u8; 6],           // From handshake
    send_key: [u8; 32],            // Current sending key
    recv_key: [u8; 32],            // Current receiving key
    send_nonce: u64,               // Monotonically increasing
    recv_nonce_window: BitField,   // Anti-replay window
    remote_endpoint: SocketAddr,   // Last known peer address
    last_received: Timestamp,      // For timeout detection
    epoch: u32,                    // Increments on rekey
}
```

### 6.2 Nonce Management

- **Send nonce**: 64-bit counter, starts at 0, increments per frame
- **XChaCha20 nonce construction** (24 bytes):
  ```
  nonce = epoch (4 bytes) || direction (1 byte) || zeros (11 bytes) || counter (8 bytes)
  ```
- **Direction byte**: `0x00` for Initiator→Responder, `0x01` for Responder→Initiator
- Counter MUST NOT wrap. Rekey before reaching 2^64-1 (effectively infinite).

### 6.3 Anti-Replay

Implementations MUST maintain a sliding window of received nonce values:

- Window size: RECOMMENDED 2048 bits minimum
- Frames with nonce below (highest_seen - window_size) MUST be rejected
- Frames with previously seen nonce MUST be rejected
- Frames with nonce above highest_seen update the window

### 6.4 Connection Migration (Roaming)

When an authenticated frame arrives from a different source address:

1. Verify AEAD tag with current session keys
2. If valid, update `remote_endpoint` to new address
3. Continue sending to new address immediately
4. No handshake required

This allows seamless transition between WiFi and cellular networks.

### 6.5 Keepalive

- Send keepalive frame if no data sent for `KEEPALIVE_INTERVAL` (default: 25 seconds)
- Consider connection dead if no frames received for `DEAD_INTERVAL` (default: 60 seconds)
- Keepalive frames are empty data frames (zero-length payload)

---

## 7. Packet Format

### 7.1 Frame Types

| Type          | Value | Description                  |
| ------------- | ----- | ---------------------------- |
| HandshakeInit | 0x01  | Initiate handshake           |
| HandshakeResp | 0x02  | Handshake response           |
| Data          | 0x03  | Encrypted data frame         |
| Rekey         | 0x04  | Initiate rekeying            |
| Close         | 0x05  | Graceful session termination |

### 7.2 Data Frame Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type (3)   |    Flags      |         Session ID            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Session ID (cont.)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Nonce Counter                         |
|                          (8 bytes)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Encrypted Payload                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Authentication Tag                         |
|                        (16 bytes)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Header: 16 bytes (unencrypted, authenticated)
Payload: variable (encrypted)
Tag: 16 bytes
```

Flags byte:

```
Bit 0: ACK_ONLY - Frame contains only acknowledgment, no state diff
Bit 1: HAS_EXTENSION - Extension data follows payload
Bit 2-7: Reserved (must be 0)
```

### 7.3 Encrypted Payload Structure

After decryption, the payload contains:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Header                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Sync Message                             |
|                        (variable)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Payload Header (8 bytes):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Timestamp (ms)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Timestamp**: Milliseconds since epoch start (for RTT measurement)
- **Payload Length**: Length of Sync Message in bytes

---

## 8. State Synchronization

The sync layer is transport-agnostic and can synchronize any state type that implements the required operations.

### 8.1 State Type Requirements

A valid Roam state type MUST provide:

```
interface StateType {
    // Unique identifier (e.g., "roam.terminal.v1")
    const STATE_TYPE_ID: string;

    // Create diff from old_state to new_state
    diff(old_state, new_state) -> Diff;

    // Apply diff to state, producing new state
    apply(state, diff) -> State;

    // Serialize diff for transmission
    encode_diff(diff) -> bytes;

    // Deserialize diff from bytes
    decode_diff(bytes) -> Diff;
}
```

### 8.2 Sync Message Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sender State Num                        |
|                          (8 bytes)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Acked State Num                         |
|                          (8 bytes)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Base State Num                          |
|                          (8 bytes)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Diff Length                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Diff Payload                              |
|                (application-defined format)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields:

- **Sender State Num**: Version number of sender's current state
- **Acked State Num**: Highest state version received from peer
- **Base State Num**: State version this diff applies to (for receiver)
- **Diff Length**: Length of diff payload in bytes (0 for ack-only)
- **Diff Payload**: Application-specific diff encoding

### 8.3 Synchronization Algorithm

Both parties maintain:

```
struct SyncState {
    current: State,              // Current local state
    current_num: u64,            // Version of current state

    last_sent: State,            // Last state we sent diff for
    last_sent_num: u64,          // Version of last sent state

    last_acked: u64,             // Highest version acked by peer
    peer_acked: u64,             // Highest version we acked to peer
}
```

#### Sender Logic (on state change or timer):

```python
def send_sync():
    if current_num > last_sent_num or should_retransmit():
        diff = state_type.diff(last_sent, current)
        send(SyncMessage(
            sender_state_num = current_num,
            acked_state_num = peer_state_num,  # what we've received
            base_state_num = last_sent_num,
            diff = state_type.encode_diff(diff)
        ))
        last_sent = current
        last_sent_num = current_num
```

#### Receiver Logic (on message receipt):

```python
def receive_sync(msg):
    # Update ack tracking
    if msg.acked_state_num > last_acked:
        last_acked = msg.acked_state_num

    # Apply diff if newer
    if msg.sender_state_num > peer_state_num:
        diff = state_type.decode_diff(msg.diff)
        peer_state = state_type.apply(peer_state, diff)
        peer_state_num = msg.sender_state_num
```

### 8.4 Convergence Guarantees

The sync algorithm guarantees **eventual consistency**:

1. All state updates are idempotent (applying same diff twice has no additional effect)
2. Diffs are computed from a known base state
3. Out-of-order delivery is handled via state numbers
4. No message is required to be delivered (UDP); state converges when any message gets through

### 8.5 Diff Payload Encoding

The diff payload format is **application-defined**. Recommendations:

- **Protocol Buffers**: Good cross-language support, schema evolution
- **MessagePack**: Simple, compact, schemaless
- **Custom binary**: Maximum control, but document thoroughly

The diff payload is opaque to the Roam transport layer.

---

## 9. Session Management

### 9.1 Rekeying

Sessions MUST rekey periodically to provide forward secrecy.

**Timing:**

- `REKEY_AFTER_TIME`: 120 seconds (2 minutes)
- `REKEY_AFTER_MESSAGES`: 2^60 messages (effectively infinite)
- `REJECT_AFTER_TIME`: 180 seconds (3 minutes, hard limit)

**Rekeying procedure:**

1. Initiating party sends `Rekey` frame containing new ephemeral public key
2. Responding party sends `Rekey` response with their ephemeral
3. Both derive new keys from fresh DH
4. New epoch begins; old keys are zeroed immediately

Rekeying uses the same Noise_IK pattern but over the existing encrypted channel:

```
Rekey frame (encrypted with current session key):
  - New ephemeral public key
  - Current timestamp

Response (encrypted with current session key):
  - Responder ephemeral public key
  - Acknowledgment
```

After rekeying:

- `epoch` counter increments
- All nonce counters reset to 0
- Old keys MUST be zeroed from memory

### 9.2 Session Termination

**Graceful close:**

1. Send `Close` frame with final ack
2. Zero all key material
3. Close socket

**Timeout:**

- If no authenticated frame received for `DEAD_INTERVAL` (60s), consider session dead
- Zero all key material
- May attempt reconnection with new handshake

### 9.3 Error Handling

| Error                 | Response                        |
| --------------------- | ------------------------------- |
| Invalid AEAD tag      | Silently drop frame             |
| Unknown session ID    | Silently drop frame             |
| Nonce replay detected | Silently drop frame             |
| Handshake failed      | May retry, backoff recommended  |
| Unsupported version   | Send error response if possible |

**Silent drops** prevent confirmation of session existence to attackers.

---

## 10. Extension Mechanism

Roam supports optional extensions negotiated during handshake.

### 10.1 Extension Format

Extensions are TLV (Type-Length-Value) encoded:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Extension Type        |         Extension Length      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                       Extension Data                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 10.2 Defined Extensions

| Type   | Name        | Description                       |
| ------ | ----------- | --------------------------------- |
| 0x0001 | Compression | Payload compression (zstd)        |
| 0x0002 | Prediction  | Client-side prediction enabled    |
| 0x0003 | Scrollback  | Scrollback buffer synchronization |
| 0x0004 | Multiplex   | Multiple state streams (future)   |
| 0x0005 | PostQuantum | Hybrid X25519+ML-KEM key exchange |

### 10.3 Extension Negotiation

1. Initiator includes desired extensions in handshake
2. Responder replies with supported subset
3. Only mutually supported extensions are active

Unknown extensions MUST be ignored (forward compatibility).

---

## 11. Security Considerations

### 11.1 Threat Model

Roam assumes:

- Attacker controls the network (can read, modify, inject, drop packets)
- Attacker does NOT have access to endpoint private keys
- Attacker does NOT have access to endpoint memory

### 11.2 Security Properties

| Property                    | Provided | Mechanism                                  |
| --------------------------- | -------- | ------------------------------------------ |
| Confidentiality             | ✅       | XChaCha20-Poly1305 AEAD                    |
| Integrity                   | ✅       | Poly1305 authentication tag                |
| Authenticity                | ✅       | Noise_IK mutual authentication             |
| Forward secrecy             | ✅       | Ephemeral keys + 2-minute rekeying         |
| Replay protection           | ✅       | Nonce counter + sliding window             |
| Identity hiding (initiator) | ✅       | Static key encrypted under responder's key |
| Identity hiding (responder) | ❌       | Responder's public key must be known       |

### 11.3 Implementation Requirements

Implementations MUST:

1. **Constant-time comparison** for all secret-dependent operations
2. **Zero memory** containing keys when no longer needed
3. **Use cryptographically secure RNG** for all random values
4. **Validate all input lengths** before processing
5. **Reject frames with invalid AEAD tags** without timing differences

Implementations SHOULD:

1. Add random delays (0-50ms) to keystroke-like input to resist timing analysis
2. Pad frames to fixed sizes when traffic analysis is a concern
3. Implement rate limiting on handshake attempts
4. Log security-relevant events (failed auth, unusual patterns)

### 11.4 Key Storage

- Private keys SHOULD be stored encrypted at rest
- Private keys SHOULD NOT be logged or included in error messages
- Session keys MUST NOT be stored persistently
- Responder public keys MAY be stored (Trust On First Use model)

### 11.5 Denial of Service

The protocol includes some DoS resistance:

- Handshake requires knowledge of responder public key (not publicly discoverable)
- Invalid frames are silently dropped (no amplification)
- Session ID prevents blind injection

Additional measures (implementation-level):

- Rate limit new handshakes per IP
- Proof-of-work for handshake initiation (optional extension)
- Cookie mechanism similar to WireGuard (future extension)

---

## 12. State Type Registry

### 12.1 Identifier Format

State Type IDs use reverse-domain notation:

```
<domain>.<type>.<version>

Examples:
  roam.terminal.v1
  roam.canvas.v1
  com.example.gamestate.v2
```

### 12.2 Standard State Types

| ID                 | Description             | Specification         |
| ------------------ | ----------------------- | --------------------- |
| `roam.terminal.v1` | Terminal emulator state | See TERMINAL.md       |
| `roam.echo.v1`     | Simple echo (testing)   | Payload is UTF-8 text |

### 12.3 Registering Custom Types

Third-party state types:

- Use your own domain prefix
- Document the diff format thoroughly
- Version explicitly (breaking changes = new version)

---

## 13. Reference Implementation Notes

### 13.1 Recommended Libraries

| Language   | Noise            | AEAD                           | Async UDP |
| ---------- | ---------------- | ------------------------------ | --------- |
| Rust       | `snow`           | `chacha20poly1305`             | `tokio`   |
| Go         | `flynn/noise`    | `x/crypto/chacha20poly1305`    | stdlib    |
| Python     | `noiseprotocol`  | `cryptography`                 | `asyncio` |
| TypeScript | `noise-protocol` | `@stablelib/xchacha20poly1305` | -         |

### 13.2 Test Vectors

See `test-vectors/` directory in reference implementation for:

- Handshake message byte sequences
- Key derivation test cases
- AEAD encryption test cases
- Sync message encoding examples

### 13.3 Interoperability Testing

Implementations SHOULD pass the Roam conformance test suite:

1. Complete handshake with reference implementation
2. Exchange sync messages with known content
3. Handle rekeying correctly
4. Survive simulated roaming (IP change)
5. Reject invalid/replayed frames

---

## Appendix A: Diff Encoding Recommendations

For state types using Protocol Buffers, recommended message structure:

```protobuf
syntax = "proto3";

package roam.sync;

// Generic diff wrapper
message DiffEnvelope {
    // Identifies the state type for validation
    string state_type_id = 1;

    // Application-specific diff
    bytes diff_payload = 2;

    // Optional: compressed payload
    bytes compressed_payload = 3;

    // Compression algorithm (0 = none, 1 = zstd)
    uint32 compression = 4;
}
```

For terminal state specifically, see `TERMINAL.md`.

---

## Appendix B: Comparison with Mosh/SSP

| Aspect          | Mosh/SSP              | Roam                                  |
| --------------- | --------------------- | ------------------------------------- |
| Key exchange    | SSH-dependent         | Noise_IK (SSH optional for bootstrap) |
| Cipher          | AES-128-OCB3          | XChaCha20-Poly1305                    |
| Forward secrecy | None during session   | 2-minute rekeying                     |
| Scrollback      | Not synchronized      | Extension supported                   |
| State types     | Terminal only         | Pluggable                             |
| Specification   | Academic paper + code | This document                         |
| Nonce           | 64-bit counter        | 64-bit counter + epoch                |
| Session resume  | Via SSH               | Direct (stored public key)            |

---

## Appendix C: Changelog

### Version 1.0-draft

- Initial specification draft

---

## References

1. Winstein, K., & Balakrishnan, H. (2012). Mosh: An Interactive Remote Shell for Mobile Clients. USENIX ATC.
2. Perrin, T. (2018). The Noise Protocol Framework. noiseprotocol.org
3. Donenfeld, J. A. (2017). WireGuard: Next Generation Kernel Network Tunnel. NDSS.
4. Nir, Y., & Langley, A. (2018). ChaCha20 and Poly1305 for IETF Protocols. RFC 8439.
5. Bernstein, D. J. (2006). Curve25519: New Diffie-Hellman Speed Records. PKC.

---

_This specification is released under CC BY 4.0. Contributions welcome._
