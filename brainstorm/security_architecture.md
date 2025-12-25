# Security architecture for Roam: a modern UDP terminal protocol

**Roam can achieve both robust security and developer ergonomics by adopting WireGuard's Noise_IK pattern with ChaCha20-Poly1305, eliminating Mosh's SSH dependency for reconnection while maintaining cryptographic verification of server identity.** This architecture provides forward secrecy through ephemeral key exchange, survives network transitions seamlessly, and leverages battle-tested Rust cryptographic libraries. The key insight from analyzing Mosh, SSH, and WireGuard is that security and usability are complementary—the most ergonomic protocols are those that make security invisible by handling key management automatically.

---

## Mosh's security model reveals both strengths and limitations

Mosh demonstrates that UDP-based terminal protocols can be secure, but its architecture has constraints worth understanding before designing Roam. The **key exchange depends entirely on SSH**—mosh-server generates a random 128-bit AES key, transmits it via the SSH connection as `MOSH CONNECT <port> <base64-key>`, then immediately terminates SSH. This creates an elegant bootstrap but permanently couples the protocol to SSH infrastructure.

The **AES-128-OCB3 cipher** was a forward-thinking choice in 2012. OCB3 provides single-pass authenticated encryption with ~0.2 cycles/byte overhead versus ~2 cycles/byte for GCM on x86 with AES-NI. The mode is now patent-free (2021) after Phillip Rogaway abandoned all related patents. However, OCB3 lacks the ecosystem adoption of ChaCha20-Poly1305 and AES-GCM, which have become the de facto standards in TLS 1.3 and WireGuard.

Mosh's **nonce handling is elegant**: a 63-bit sequence number plus 1-bit direction flag ensures uniqueness. The protocol's key innovation is treating every datagram as an **idempotent operation**—replaying packets has no effect because each message transforms state n to state m via a diff. This eliminates the need for replay caches entirely, dramatically simplifying implementation.

The **security track record is excellent**: no major vulnerabilities since 2012, only one minor DoS CVE (CVE-2012-2385). However, several limitations constrain Mosh's use cases:

- Single long-lived session key with no forward secrecy during the session
- No port forwarding, agent forwarding, or X11 (by design—SSP synchronizes screen state, not byte streams)
- Server cannot roam (only client can change IP addresses)
- Inherits SSH authentication vulnerabilities during bootstrap

---

## WireGuard's design philosophy should guide Roam's architecture

WireGuard achieved what many considered impossible: **~4,000 lines of code** providing security that formal verification proved correct, while OpenVPN requires 100,000+ lines. The key design decisions that enabled this simplicity are directly applicable to Roam.

**Cryptographic versioning eliminates negotiation attacks.** WireGuard uses a fixed cipher suite (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) compiled into the protocol. If vulnerabilities are found, a new protocol version is released rather than negotiating weaker algorithms. This eliminates entire classes of downgrade attacks that have plagued TLS and SSH.

**The Noise_IK pattern provides 1-RTT mutual authentication.** In Noise_IK, the responder's (server's) static public key is known beforehand, and the initiator (client) transmits its identity encrypted in the first message:

```
← s (server public key known to client)
...
→ e, es, s, ss (client ephemeral + encrypted client identity)
← e, ee, se (server ephemeral, completing key agreement)
```

This provides forward secrecy through four Diffie-Hellman operations mixing ephemeral and static keys, identity hiding for the client (encrypted under the server's key), and mutual authentication completed in one round trip.

WireGuard's **formal verification** is exceptionally thorough. The Tamarin symbolic prover and CryptoVerif computational model verified: correctness, key agreement, KCI resistance, unknown key-share resistance, key secrecy, forward secrecy, session uniqueness, identity hiding, replay resistance, and mutual authentication. INRIA researchers produced machine-checked proofs of the entire protocol.

---

## ChaCha20-Poly1305 is the optimal cipher choice for mobile terminals

The cipher comparison reveals ChaCha20-Poly1305 as the clear winner for a protocol targeting mobile devices on untrusted networks.

| Criterion               | ChaCha20-Poly1305                  | AES-GCM                 | AES-OCB3     | AEGIS             |
| ----------------------- | ---------------------------------- | ----------------------- | ------------ | ----------------- |
| ARM without crypto ext  | **Fastest**                        | Slow, timing-vulnerable | Good         | Slow              |
| ARM with crypto ext     | Good                               | Fast                    | Fast         | **Fastest**       |
| Side-channel resistance | **Best** (constant-time by design) | Requires hardware       | Good         | Requires hardware |
| Nonce misuse impact     | Catastrophic                       | Catastrophic            | Catastrophic | Catastrophic      |
| Standardization         | TLS 1.3, WireGuard, SSH            | TLS 1.3, NIST           | RFC 7253     | RFC 9512 (new)    |
| Rust ecosystem          | **Excellent** (audited)            | **Excellent** (audited) | Limited      | Growing           |

**ChaCha20-Poly1305 is 3-4x faster than AES-GCM on ARM devices without hardware acceleration**, which still includes many budget Android phones and embedded devices. Even on modern phones with ARMv8 crypto extensions, ChaCha20 remains competitive while using significantly less power—**~7µW vs ~27µW** for 50-byte encryption on tested platforms.

Google adopted ChaCha20-Poly1305 for Chrome/Android TLS precisely because mobile devices lacked AES-NI in 2013-2014. The cipher is now standardized in RFC 8439, mandated in TLS 1.3, and battle-tested across billions of devices. For Roam, **XChaCha20-Poly1305** (192-bit nonce variant) enables safe random nonce generation for long-lived keys—the larger nonce space eliminates birthday-bound concerns.

---

## Session management should follow WireGuard's ephemeral model

The comparison of session models across protocols yields clear recommendations:

**Rekey every 2-3 minutes** following WireGuard's REKEY_AFTER_TIME constant. This provides rolling forward secrecy—even if an attacker compromises a session key, they gain access to at most ~3 minutes of traffic. The 2-minute interval is short enough for meaningful security but long enough to avoid handshake overhead dominating terminal latency.

**Avoid 0-RTT for sensitive operations.** While 0-RTT (zero round-trip time) resumption saves ~100-300ms of latency, it fundamentally cannot be replay-protected because the server hasn't contributed randomness. TLS 1.3's experience shows 0-RTT should be limited to idempotent operations. For terminal input containing credentials, **1-RTT is the minimum safe option**.

**Delete ephemeral keys immediately after deriving shared secrets.** WireGuard zeroes all ephemeral key material after REJECT_AFTER_TIME × 3. This should be implemented using the `zeroize` crate in Rust to prevent compiler optimization from eliminating the memory clearing.

**Handle IP roaming via authenticated packets, not connection state.** Like both Mosh and WireGuard, Roam should update the client's endpoint address when an authenticated packet arrives from a new source. The authentication tag proves the packet came from the legitimate client—no TCP connection state needed.

---

## Noise_IK enables SSH-free reconnection with security guarantees

The most significant architectural improvement over Mosh is **eliminating SSH dependency for session resumption**. Here's how:

**Initial authentication via SSH or native mechanism:**

1. First connection can use SSH (like Mosh) for familiar UX
2. Server generates ephemeral keypair and returns public key to client
3. Client stores server's public key locally (Trust On First Use)
4. All subsequent connections use Noise_IK directly

**Reconnection flow (no SSH required):**

1. Client initiates Noise_IK handshake to known server public key
2. Server authenticates client via stored public key (or certificate)
3. 1-RTT completion establishes new session keys
4. Terminal state synchronized via Mosh-like SSP layer

This architecture provides **sub-second reconnection** across IP changes while maintaining cryptographic authentication of both parties. The server public key can be verified via:

- SSH host key comparison (for users with existing SSH access)
- QR code scanning (for mobile-first setup)
- DNS (SSHFP-like record with server's Noise public key)
- Certificate chain (for enterprise deployment)

---

## The threat model demands specific defenses

Terminal protocols face unique threats that Roam must address:

**Keystroke timing attacks** are well-documented against SSH. Research by Song, Wagner, and Tian demonstrated that inter-keystroke timing leaks ~1 bit per keystroke pair—enough to speed up password cracking by 50x. OpenSSH added chaff packet countermeasures in 2023, but recent research shows these can be bypassed. Roam should implement:

- Random delays (0-50ms) between keystroke packet transmission
- Constant-rate padding during active input
- Batched input mode for password entry

**Nation-state adversaries** routinely practice "harvest now, decrypt later"—storing encrypted traffic for future cryptanalysis. This makes forward secrecy non-negotiable. With 2-minute rekeying and ephemeral key destruction, even a quantum computer would only decrypt small traffic windows, not entire sessions.

**The specific attacks on untrusted networks** (MITM, ARP spoofing, evil twin, DNS hijacking) are all defeated by the same defense: **end-to-end authenticated encryption with server identity pinned by cryptographic key**. Unlike certificate-based systems vulnerable to CA compromise, Roam's public key model has no trusted third parties beyond initial TOFU.

| Attack           | Defense                                          |
| ---------------- | ------------------------------------------------ |
| MITM             | Server public key pinning (like SSH known_hosts) |
| Packet injection | AEAD authentication tag verification             |
| Replay           | Nonce/sequence number monotonicity               |
| Traffic analysis | Padding, timing obfuscation (partial mitigation) |
| IP spoofing      | Crypto binding of packets to session keys        |

---

## Rust crypto ecosystem is mature for production use

The research identifies a clear recommended stack for implementing Roam:

**Primary: aws-lc-rs for core cryptographic primitives.** This library is now rustls's default backend (replacing ring), has FIPS 140-3 certification, and includes post-quantum X25519+ML-KEM-768 hybrid key exchange. It's actively maintained by AWS's cryptography team with excellent ARM (Graviton) optimization.

**For Noise Protocol: snow crate.** With 17.5M+ downloads, snow is the mature Noise implementation in Rust. It supports pluggable crypto backends (can use aws-lc-rs or ring) and implements all standard patterns including IK. Important caveat: snow has not been formally audited—this should be factored into a security review.

**Audited RustCrypto crates for supplementary needs:**

- `chacha20poly1305` - NCC Group audited, no vulnerabilities found
- `aes-gcm` - NCC Group audited
- `x25519-dalek` / `ed25519-dalek` - Quarkslab reviewed

**Secret management stack:**

```rust
use secrecy::Secret;  // Prevents accidental logging, Debug shows "[REDACTED]"
use zeroize::Zeroize;  // Securely zeros memory on drop
use subtle::ConstantTimeEq;  // Prevents timing side-channels
```

The decision between ring, aws-lc-rs, and pure RustCrypto depends on constraints:

| Requirement           | Recommendation                   |
| --------------------- | -------------------------------- |
| FIPS compliance       | aws-lc-rs (certified)            |
| Pure Rust / WASM      | RustCrypto                       |
| Maximum compatibility | ring (broadest platform support) |
| Active maintenance    | aws-lc-rs (AWS-backed)           |
| Post-quantum ready    | aws-lc-rs (X25519+ML-KEM-768)    |

---

## Security ergonomics make or break adoption

The research on Tailscale and Signal reveals that **the best security is invisible security**. Users who never see security UI can't make security mistakes. Specific lessons for Roam:

**Tailscale's "it just works" model:**

- Keys generated automatically on device setup
- Key rotation handled transparently
- NAT traversal works without configuration
- Authentication via existing identity providers (Google, GitHub)

**Signal's safety number design:**

- Per-conversation verification (not per-user)
- Non-blocking warnings for key changes (most are benign)
- QR code ceremony reduced from two scans to one
- Optional manual approval for verified contacts

**SSH's known_hosts problems to avoid:**

- The "REMOTE HOST IDENTIFICATION HAS CHANGED" warning has a near-100% false positive rate
- Users delete known_hosts entirely rather than investigating
- Almost no one verifies fingerprints on first connection

**Recommended UX for Roam:**

| Scenario                         | User Experience                                                                                                                 |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| First connection (new server)    | Show server key fingerprint, recommend verification, allow proceeding                                                           |
| Reconnection (key matches)       | Completely silent, < 100ms latency                                                                                              |
| Server key changed               | Warning with context: "Server key changed since last connection. This is normal after server reinstall." Prominent safe action. |
| Network change (WiFi → cellular) | Seamless, no user notification                                                                                                  |
| Connection restored after sleep  | Automatic, < 500ms total latency                                                                                                |

Trust On First Use is acceptable for most users when combined with:

- Optional upgrade to certificate-based or key-pinned authentication
- Server key displayed in terminal connection banner for verification
- Key history tracking (alert if key changes within short window of first use)

---

## Recommended security architecture for Roam

Based on this comprehensive analysis, here is the proposed security model:

### Cryptographic foundation

- **Key exchange:** X25519 (with X25519+ML-KEM-768 hybrid as future option)
- **AEAD cipher:** XChaCha20-Poly1305 (192-bit nonce for random generation safety)
- **Hash:** BLAKE2s (following WireGuard's choices)
- **Protocol framework:** Noise_IKpsk2 pattern

### Connection lifecycle

```
1. INITIAL SETUP (once per server)
   - Bootstrap via SSH OR native HTTPS-based registration
   - Server returns: public key, UDP port, session token
   - Client stores server public key (TOFU)

2. CONNECTION (every session)
   - Client → Server: Noise_IK initiator message (e, es, s, ss)
   - Server → Client: Noise_IK responder message (e, ee, se)
   - Result: Forward-secret session keys, 1-RTT completion

3. DATA TRANSPORT
   - XChaCha20-Poly1305 authenticated encryption
   - 64-bit sequence numbers (never reused)
   - SSP-like state synchronization for terminal

4. REKEYING (every 2 minutes)
   - New Noise handshake using existing transport
   - Old keys zeroed immediately
   - No traffic interruption

5. ROAMING (automatic)
   - Client IP changes detected via authenticated packets
   - Server updates client endpoint atomically
   - Sub-second recovery
```

### Implementation recommendations

- Use `aws-lc-rs` as primary crypto backend (FIPS-ready, actively maintained)
- Use `snow` for Noise protocol implementation
- Wrap all secrets in `secrecy::Secret<T>`
- Implement `Zeroize` on all key-containing structs
- Add 10-50ms random delays to keystroke packets
- Support graceful degradation: if Noise fails, fall back to SSH-bootstrapped mode

### What to avoid

- Cipher suite negotiation (use cryptographic versioning instead)
- Long-lived session keys without rekeying
- 0-RTT resumption for non-idempotent operations
- Storing private keys on servers
- Custom cryptographic primitives

---

## Conclusion

Roam can surpass Mosh's security properties while improving ergonomics by adopting WireGuard's proven architecture. The combination of Noise_IK for key exchange, XChaCha20-Poly1305 for encryption, and 2-minute rekeying provides forward secrecy, mutual authentication, and seamless roaming—all without SSH dependency for reconnection.

The critical insight is that **security and usability are not in tension**. Mosh succeeded because it made roaming invisible; WireGuard succeeded because it made VPN configuration trivial. Roam should make secure terminal connections so seamless that users forget they're on an untrusted network.

The Rust cryptographic ecosystem is mature enough for production use, with audited implementations of all required primitives. The main engineering work is integrating these components correctly—not inventing new cryptography. By standing on the shoulders of WireGuard's formal verification and SSH's 25 years of hardening lessons, Roam can achieve security properties that would otherwise require years of adversarial testing to validate.
