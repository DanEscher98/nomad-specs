# Security Threats and Benchmarking Strategy for NOMAD Protocol

NOMAD Protocol's security architecture—combining Noise_IK key exchange, XChaCha20-Poly1305 encryption, and 2-minute rekeying—**successfully addresses every major cryptographic attack class** while fixing Mosh's most significant limitation: lack of forward secrecy during sessions. The protocol must still implement several UDP-specific mitigations (cookie-based anti-amplification, path validation for roaming) and state synchronization protections (monotonic versioning, bounded state sizes). For benchmarking, the **tc/netem tool** with containerized test environments provides the most robust methodology, measuring keystroke-to-display latency, reconnection time, and bandwidth overhead under simulated mobile network conditions (packet loss up to 30%, latency spikes to 500ms, IP address changes).

---

## Cryptographic attack resistance through modern primitives

NOMAD's cryptographic design resists all classical attacks through deliberate architectural choices. **Replay attacks** are defeated by combining AEAD nonce uniqueness with monotonically increasing sequence numbers tracked via sliding window—the same approach WireGuard uses. Because XChaCha20-Poly1305 authenticates every packet, attackers cannot inject or replay datagrams without detection. The **192-bit extended nonce** is critical for UDP's stateless nature: random nonce generation becomes safe, with collision probability remaining negligible even after **2^80 messages** (effectively zero for any realistic terminal session).

**Chosen-ciphertext and padding oracle attacks** are structurally eliminated by the AEAD construction. XChaCha20 is a stream cipher requiring no block padding, and Poly1305 authentication occurs before any plaintext is revealed. This contrasts with older CBC-mode ciphers where padding validation could leak information. The **timing attack** resistance of ChaCha20 stems from its exclusive use of additions, XORs, and fixed rotations—no data-dependent branches or lookup tables that could leak secrets through cache timing.

Noise_IK provides robust **MITM resistance** through its dual DH authentication: the initiator encrypts to the responder's known static key (es), both static keys contribute to session derivation (ss), and ephemeral keys add forward secrecy (ee). Any handshake tampering causes key derivation to fail, as the transcript hash binds all messages. **Key Compromise Impersonation (KCI)** attacks are defeated because the ephemeral-ephemeral DH ensures attackers cannot impersonate third parties even with one party's static key. **Unknown Key-Share (UKS)** attacks require binding identities in Noise's prologue—include server hostname and client identity to ensure both parties agree on session participants.

The fixed cipher suite (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) eliminates **downgrade attacks** entirely. The protocol name is hashed into session keys during initialization, making any cipher modification detectable.

---

## UDP vulnerabilities require protocol-level defenses

UDP's stateless, connectionless nature creates attack vectors absent in TCP-based protocols. **IP spoofing** enables reflection and amplification attacks because UDP accepts packets without source verification—the foundation of major DDoS events including the **22.2 Tbps Cloudflare attack** in September 2025. NOMAD must implement **cookie-based address validation** before committing server state, following QUIC's model: send a cryptographic Retry token that clients must echo, proving address ownership. Until validated, servers should limit responses to at most **3× the bytes received** (QUIC's amplification limit).

**Connection hijacking** without TCP sequence numbers requires authenticating every datagram. Mosh achieves this through AES-OCB—NOMAD inherits the same guarantee with XChaCha20-Poly1305. The critical principle is **never processing unauthenticated data**, including headers that might influence routing or state changes.

**NAT traversal** introduces additional risks. STUN servers have been exploited for 2.32× amplification attacks, with approximately 75,000 abusable servers discovered in the wild. If NOMAD uses STUN/TURN for NAT traversal, it must rate-limit unauthenticated requests and validate that relay usage requires proper authentication. **NAT rebinding attacks**—where attackers cause NAT mappings to redirect traffic—require path validation before accepting address changes, discussed below in roaming security.

| Attack Vector | Amplification Factor | NOMAD Mitigation |
|--------------|---------------------|-----------------|
| Memcached | 10,000-51,000× | N/A (not applicable) |
| NTP monlist | 556× | N/A |
| DNS | 28-54× | N/A |
| Generic UDP | Up to request size | Cookie validation + 3× limit |

---

## State synchronization threats unique to terminal protocols

Beyond transport-layer attacks, NOMAD's state synchronization layer faces **state manipulation**, **desynchronization**, and **rollback attacks**. An attacker injecting malicious state diffs could corrupt terminal display or inject commands—prevented entirely by per-packet AEAD authentication. However, authenticated attackers (compromised clients) could still attempt **desynchronization** by manipulating protocol state machines.

**Rollback attacks** on state versions pose the most subtle threat: replaying old state diffs to expose previously-typed passwords. Prevention requires **monotonically increasing state version numbers** where the receiver rejects anything ≤ current version. Combined with 2-minute rekeying, old keys cannot decrypt new state, and old state cannot be replayed with current keys.

**Resource exhaustion** via malformed diffs was Mosh's only CVE (**CVE-2012-2385**, May 2012): escape sequences with large repeat counts caused excessive CPU consumption. NOMAD must implement strict bounds on all parameters—maximum scrollback size, maximum diff size, maximum nesting depth for any structured data. The fix is simple but essential: **cap all user-controlled size values** at protocol level before any processing.

State size explosion attacks—where malicious input causes unbounded memory growth—require hard limits on total state size with oldest-data eviction. For scrollback synchronization specifically, define a maximum buffer size (perhaps configurable, with a reasonable default like 100KB) and compress or evict older content when approached.

---

## Mosh limitations that NOMAD addresses

Mosh has an **exceptional security track record**: only CVE-2012-2385 in over a decade, with the official security statement noting "no security vulnerabilities of any kind (major or minor) have been reported" since that fix. However, its cryptographic design has inherent limitations that NOMAD improves upon.

**No forward secrecy during sessions** is Mosh's most significant limitation. The `mosh-server` generates a single AES-128 session key at startup, passed via SSH to the client, and used for the entire session—potentially days or weeks. If that key is compromised (memory dump, side-channel attack), **all past and future traffic for that session can be decrypted**. NOMAD's 2-minute rekeying provides bounded exposure: even with key compromise, only ~2 minutes of traffic is vulnerable. Noise's `REKEY()` function is a one-way operation—knowing the new key doesn't reveal the old key.

**SSH dependency for key exchange** means Mosh inherits all SSH vulnerabilities during setup. If SSH is misconfigured or the network is compromised during the brief initial connection, the Mosh session key is exposed. NOMAD's Noise_IK performs authenticated key exchange directly, requiring only that the client knows the server's static public key in advance (similar to SSH known_hosts, but without depending on SSH transport).

**AES-128 vs XChaCha20-256** presents both security and performance tradeoffs. Mosh's authors explicitly chose AES-128 based on the OCB FAQ recommendation and Schneier's comments about AES-256's "lousy" key schedule. For a session key, 128 bits is cryptographically adequate. However, **XChaCha20 performs better in software** on devices without AES-NI hardware (mobile phones, IoT devices), and its **192-bit nonce** eliminates the nonce management complexity that 96-bit nonces require.

---

## Noise_IK security properties and their limits

The IK pattern provides **zero-RTT encrypted payload** in the first message while achieving mutual authentication after the second message. Security properties escalate through the handshake:

- **First message (→)**: Encrypted to known recipient but sender unauthenticated; vulnerable to active attacker with responder's static key
- **Second message (←)**: Sender authenticated, KCI-resistant; weak forward secrecy (active attacker who compromised static keys during handshake could decrypt)
- **Transport messages**: Strong forward secrecy via ephemeral-ephemeral DH; resistant to future static key compromise

**Identity hiding limitations** in IK are important to document: the responder's static key is transmitted as a pre-message (known to initiator in advance), so it's never hidden. The initiator's static key is encrypted in the first message but would be visible to an active attacker possessing the responder's static key. For terminal connections where server identity is public and client identity exposure to compromised servers is acceptable, this is typically adequate.

**What Noise_IK does NOT protect against:**

- Post-compromise security (if session keys extracted from memory)
- Traffic analysis (packet timing and sizes leak information)
- Compromised endpoints (malicious server/client software)
- Denial of service before handshake completion

The XX pattern would provide better identity hiding (both parties' static keys encrypted to ephemeral keys) but adds a round-trip. For latency-sensitive terminal connections with known servers, IK's tradeoff favors lower latency.

---

## Network simulation tools for benchmarking

**tc/netem** is the primary recommendation for UDP protocol testing—Linux's kernel-level network emulation provides the most comprehensive and realistic packet manipulation. Key capabilities include:

```bash
# Mobile 4G simulation: 50ms delay, 20ms jitter, 0.5% loss
tc qdisc add dev eth0 root netem delay 50ms 20ms distribution normal loss 0.5%

# Severe degradation: 200ms delay, 30% loss with burst correlation
tc qdisc add dev eth0 root netem delay 200ms 50ms loss 30% 25%

# WiFi→cellular handoff simulation (scripted)
tc qdisc add dev eth0 root netem delay 10ms loss 0.1%    # Good WiFi
sleep 10
tc qdisc change dev eth0 root netem delay 50ms loss 5%    # Degrading
sleep 3
tc qdisc change dev eth0 root netem loss 50%              # Handoff gap
sleep 2
tc qdisc change dev eth0 root netem delay 100ms loss 1%   # Cellular
```

**Pumba** wraps tc/netem with Docker awareness, enabling container-level chaos testing integrated into CI/CD pipelines. For Kubernetes environments, **Chaos Mesh** provides NetworkChaos resources for automated resilience testing. **Toxiproxy** from Shopify offers excellent TCP fault injection with REST API control, though its UDP support is limited.

For research-grade simulation, **Mahimahi** (from Mosh's authors at MIT) provides composable UNIX shell containers with trace-replay capability—recording real cellular network conditions and replaying them deterministically for reproducible benchmarks.

---

## Test scenarios for mobile and roaming connections

NOMAD's core value proposition—maintaining connections across network changes—requires rigorous testing under realistic mobile conditions:

**WiFi-to-cellular handoff** simulation should model three phases: WiFi degradation (increasing latency and loss over 3-5 seconds), handoff gap (near-complete packet loss for 1-3 seconds), and cellular establishment (higher but stable latency). The critical metric is **session continuity**—whether the connection recovers automatically without user intervention.

**IP address change** during active session tests NOMAD's roaming capability directly. QUIC's **PATH_CHALLENGE/PATH_RESPONSE** mechanism provides the template: when packets arrive from a new address, send an 8-byte random challenge that must be echoed before migrating session state to the new address. This prevents attackers from hijacking sessions by spoofing source addresses.

**Specific test matrix:**

| Condition | Parameters | Success Criteria |
|-----------|------------|------------------|
| High packet loss | 10%, 30%, 50% random loss | Session remains interactive |
| Latency variation | 50ms→500ms oscillation | Keystroke echo ≤100ms via prediction |
| Network partition | 30s complete blackout | Automatic recovery within 1s of restoration |
| IP address change | Mid-session address swap | Session continues without re-authentication |
| MTU change | 1500→1280 bytes | No fragmentation-related failures |

---

## Performance metrics that matter

The original Mosh paper (USENIX ATC 2012) established the key metrics for terminal protocol comparison. Over Sprint 3G networks, Mosh achieved **<5ms median keystroke-to-display latency** versus SSH's 503ms—a **100× improvement** through speculative local echo that correctly predicted 70% of keystrokes.

**Primary metrics for NOMAD benchmarking:**

- **Keystroke-to-display latency**: Time from key press to character appearance; should be <5ms with local echo enabled regardless of network RTT
- **Local echo accuracy**: Percentage of correct predictions; Mosh achieved 99.1% accuracy
- **Reconnection time**: Time from network restoration to first usable byte; target <100ms
- **Bandwidth overhead**: Bytes transferred versus raw SSH for identical workload; Mosh uses frame-rate adaptation capped at 50Hz
- **Battery impact**: Critical for mobile; measure using Android's `BATTERY_PROPERTY_CURRENT_NOW` over ≥6 minute tests

**Measurement tools:**

- **sshping**: Measures character-echo latency with RFC-2822 compliant output
- **typometer**: Cross-platform keystroke-to-display measurement using native screen APIs
- **Wireshark/tcpdump**: Packet timing analysis for protocol overhead
- **Android BatteryManager API** or Monsoon Power Monitor for energy consumption

---

## Building a fair comparison framework

Comparing NOMAD against Mosh, SSH, and Eternal Terminal requires controlling for their architectural differences. Mosh uses UDP with speculative echo; ET uses TCP with byte-stream synchronization; SSH provides no resilience to network disruption.

**Comparison principles:**

1. **Identical hardware and network path**: Use emulation via tc/netem with deterministic seeds for reproducibility
2. **Same keystroke traces**: Replay recorded typing sessions (Mosh authors used 40 hours of real usage from 6 users)
3. **Matched cipher strength**: Compare protocols using equivalent security levels
4. **Disable prediction for raw protocol comparison**: Measure underlying transport performance separately from application-layer optimizations

Eternal Terminal differs significantly from Mosh: it provides **full scrollback** but no speculative local echo, uses TCP instead of UDP, and supports `tmux -CC` integration. Its reconnection mechanism (BackedReader sequence tracking) targets different use cases than Mosh's screen-state synchronization.

**Statistical rigor** requires minimum 30 trials per condition, reporting min/median/mean/p95/p99 with standard deviation. Network latency distributions are typically non-normal, so use Mann-Whitney U tests rather than t-tests for significance testing. IETF RFC 2544 and RFC 9411 provide standardized benchmarking methodology for network protocol evaluation.

---

## Conclusion

NOMAD Protocol's security architecture addresses every significant attack class through deliberate design choices: Noise_IK for authenticated key exchange with forward secrecy, XChaCha20-Poly1305 for efficient authenticated encryption with safe random nonces, and 2-minute rekeying for bounded exposure windows. The protocol must additionally implement **cookie-based anti-amplification** (limiting responses to 3× input until address validated), **PATH_CHALLENGE validation** for roaming scenarios, and **strict bounds on state sizes** to prevent resource exhaustion.

**Critical implementation requirements:**

- Monotonically increasing sequence numbers with sliding window replay detection
- Server identity bound into Noise prologue to prevent UKS attacks
- Constant-time cryptographic operations (especially tag comparison)
- Maximum parameter limits for all user-controlled values
- Rate limiting on unauthenticated handshake attempts

For proving security, establish a **benchmarking baseline against Mosh** using tc/netem containerized environments, measuring keystroke latency, reconnection time, and bandwidth overhead under degraded network conditions. The test matrix should include 30% packet loss, 500ms variable latency, IP address changes, and 30-second network partitions. Success means matching or exceeding Mosh's 5ms keystroke latency with local echo while demonstrating automatic session recovery across all roaming scenarios.

NOMAD's improvements over Mosh—forward secrecy via rekeying, independent key exchange via Noise, scrollback synchronization—come without sacrificing the resilience that made Mosh transformative for mobile terminal usage. The combination of proven cryptographic primitives, systematic threat mitigation, and rigorous benchmarking methodology positions the protocol to serve as a worthy successor.