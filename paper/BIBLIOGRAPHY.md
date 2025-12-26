# NOMAD Protocol - Annotated Bibliography

This document provides context for each reference cited in the paper, explaining why it is relevant and how to verify the citation.

---

## Primary Influences

### 1. Mosh: An Interactive Remote Shell for Mobile Clients

**Citation:** Winstein, K., & Balakrishnan, H. (2012). USENIX ATC.

**URL:** https://www.usenix.org/conference/atc12/technical-sessions/presentation/winstein

**PDF:** https://mosh.org/mosh-paper.pdf

**Why Relevant:**
- **Core inspiration** for NOMAD's state synchronization approach
- Introduced the State Synchronization Protocol (SSP) that NOMAD adapts
- Proved that idempotent state diffs work for interactive applications
- Demonstrated client-side prediction for terminal emulation
- Showed that UDP + state sync outperforms TCP for interactive latency

**What We Took:**
- Idempotent diff concept
- State skipping under congestion
- Frame pacing approach (SRTT/2)
- 50 Hz display update cap
- Delayed ACK piggybacking observation (99.9% of acks piggyback)

**What We Changed:**
- Modern crypto (AES-OCB → XChaCha20-Poly1305)
- Added forward secrecy via rekeying
- Integrated key exchange (no SSH bootstrap)
- Generic state interface (not terminal-specific)

---

### 2. The Noise Protocol Framework

**Citation:** Perrin, T. (2018). Revision 34.

**URL:** https://noiseprotocol.org/noise.html

**PDF:** https://noiseprotocol.org/noise.pdf

**Why Relevant:**
- **Foundation** for NOMAD's handshake protocol
- Provides the Noise_IK pattern we use for 1-RTT mutual authentication
- Formally analyzed security properties
- Used by Signal, WireGuard, WhatsApp

**What We Use:**
- `Noise_IK(s, rs)` handshake pattern
- HKDF-based key derivation
- Chaining key and handshake hash concepts
- Security property guarantees (identity hiding for initiator)

**Key Sections to Verify:**
- Section 7.5: IK pattern definition
- Section 5: Processing rules
- Section 9: Security considerations

---

### 3. WireGuard: Next Generation Kernel Network Tunnel

**Citation:** Donenfeld, J. A. (2017). NDSS.

**URL:** https://www.wireguard.com/papers/wireguard.pdf

**DOI:** 10.14722/ndss.2017.23160

**Why Relevant:**
- **Design philosophy** inspiration: fixed crypto, no negotiation
- Rekeying timing constants (120s soft, 180s hard)
- Anti-replay sliding window size (2048 bits)
- Same Noise_IK pattern choice
- Proved minimal VPN design works in practice

**What We Took:**
- 120-second rekey interval
- 180-second hard limit
- 2048-bit replay window
- "Cryptographic versioning" philosophy
- Session roaming approach

**Key Sections to Verify:**
- Section 5.4: Timer-based rekeying
- Section 5.1: Handshake using Noise_IK

---

## Cryptographic Standards

### 4. ChaCha20 and Poly1305 for IETF Protocols (RFC 8439)

**Citation:** Nir, Y. & Langley, A. (2018). RFC 8439.

**URL:** https://www.rfc-editor.org/rfc/rfc8439

**Why Relevant:**
- **AEAD construction** NOMAD uses
- Defines ChaCha20-Poly1305 that XChaCha20 extends
- IETF standardization of Bernstein's designs
- Specifies 16-byte tag, 12-byte nonce (we use XChaCha20's 24-byte)

**Key Sections to Verify:**
- Section 2.5: Poly1305 MAC (16-byte tag)
- Section 2.8: AEAD construction
- Test vectors in Section 2.8.2

---

### 5. XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305

**Citation:** Arciszewski, S. (2020). Internet-Draft.

**URL:** https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

**Why Relevant:**
- **Extended nonce** variant we use (24 bytes vs 12 bytes)
- Allows random nonce generation without birthday-bound concerns
- Derived from HChaCha20 construction

**Key Sections to Verify:**
- Section 2.1: XChaCha20 algorithm
- Section 2.2: AEAD_XChaCha20_Poly1305

**Note:** This is still an Internet-Draft (not RFC), but widely implemented and used by libsodium, WireGuard (for cookie encryption), etc.

---

### 6. Elliptic Curves for Security (RFC 7748)

**Citation:** Langley, A., Hamburg, M., & Turner, S. (2016). RFC 7748.

**URL:** https://www.rfc-editor.org/rfc/rfc7748

**Why Relevant:**
- **X25519 ECDH** specification we use
- Defines 32-byte public/private key sizes
- Constant-time implementation guidance

**Key Sections to Verify:**
- Section 5: Curve25519 (X25519) function
- Section 6.1: Test vectors

---

### 7. The BLAKE2 Cryptographic Hash and MAC (RFC 7693)

**Citation:** Saarinen, M-J. & Aumasson, J-P. (2015). RFC 7693.

**URL:** https://www.rfc-editor.org/rfc/rfc7693

**Why Relevant:**
- **Hash function** used in Noise for NOMAD
- BLAKE2s-256 for 32-byte output
- Faster than SHA-256 in software

**Key Sections to Verify:**
- Section 1: Overview and output sizes
- Section 2.7: BLAKE2s specification
- Appendix E: Test vectors

---

### 8. Computing TCP's Retransmission Timer (RFC 6298)

**Citation:** Paxson, V., Allman, M., Chu, J., & Sargent, M. (2011). RFC 6298.

**URL:** https://www.rfc-editor.org/rfc/rfc6298

**Why Relevant:**
- **RTT estimation algorithm** we use
- SRTT and RTTVAR calculation
- Proven over decades of TCP deployment

**Key Sections to Verify:**
- Section 2: Algorithm specification
- Smoothing factors: α=1/8, β=1/4

---

## Related Protocols

### 9. QUIC: A UDP-Based Multiplexed and Secure Transport (RFC 9000)

**Citation:** Iyengar, J. & Thomson, M. (2021). RFC 9000.

**URL:** https://www.rfc-editor.org/rfc/rfc9000

**Why Relevant:**
- **Comparison point** for related work section
- Also UDP-based with integrated crypto
- Uses connection IDs for roaming (like NOMAD's session ID)
- More complex than NOMAD (reliable delivery, multiplexing)

**Differences from NOMAD:**
- QUIC provides reliable, ordered delivery; NOMAD does not
- QUIC uses TLS 1.3; NOMAD uses Noise
- QUIC is a general transport; NOMAD is state-sync specific

---

### 10. The Secure Shell (SSH) Transport Layer Protocol (RFC 4253)

**Citation:** Ylonen, T. & Lonvick, C. (2006). RFC 4253.

**URL:** https://www.rfc-editor.org/rfc/rfc4253

**Why Relevant:**
- **Problem context**: SSH is what Mosh and NOMAD improve upon
- TCP-based, freezes on packet loss
- Requires session reestablishment on IP change
- Referenced in introduction to explain limitations

---

### 11. Curve25519: New Diffie-Hellman Speed Records

**Citation:** Bernstein, D. J. (2006). PKC.

**DOI:** 10.1007/11745853_14

**Why Relevant:**
- **Original Curve25519 paper**
- Explains why this curve was chosen (speed, security)
- Historical context for X25519

---

## Testing Tools

### 12. Hypothesis: Property-Based Testing for Python

**Citation:** MacIver, D. R. (2023).

**URL:** https://hypothesis.readthedocs.io/

**GitHub:** https://github.com/HypothesisWorks/hypothesis

**Why Relevant:**
- **Testing framework** used for conformance suite
- Property-based testing for edge case discovery
- Shrinking to minimal failing examples

**Properties We Test:**
- Idempotence: `apply(s,d) = apply(apply(s,d), d)`
- Convergence: arbitrary orderings → same state
- Roundtrip: `decode(encode(x)) = x`

---

## Verification Checklist

For each reference, verify:

- [ ] **Mosh (2012)**: Paper accessible at mosh.org, USENIX proceedings
- [ ] **Noise (2018)**: noiseprotocol.org is live, revision 34 matches
- [ ] **WireGuard (2017)**: Paper on wireguard.com, DOI resolves
- [ ] **RFC 8439**: rfc-editor.org link works
- [ ] **XChaCha draft**: datatracker.ietf.org link works
- [ ] **RFC 7748**: rfc-editor.org link works
- [ ] **RFC 7693**: rfc-editor.org link works
- [ ] **RFC 6298**: rfc-editor.org link works
- [ ] **RFC 9000**: rfc-editor.org link works
- [ ] **RFC 4253**: rfc-editor.org link works
- [ ] **Curve25519 (2006)**: DOI resolves, paper accessible
- [ ] **Hypothesis**: readthedocs.io link works

---

## BibTeX Entry Verification

Cross-reference with `references.bib`:

| Key in .bib | Matches This Entry |
|-------------|-------------------|
| `winstein2012mosh` | Mosh (2012) |
| `perrin2018noise` | Noise Protocol (2018) |
| `donenfeld2017wireguard` | WireGuard (2017) |
| `rfc8439` | ChaCha20-Poly1305 |
| `xchacha` | XChaCha draft |
| `rfc7748` | X25519 / Curve25519 |
| `rfc7693` | BLAKE2 |
| `rfc6298` | TCP RTO |
| `rfc9000` | QUIC |
| `rfc4253` | SSH |
| `bernstein2006curve25519` | Curve25519 paper |
| `hypothesis` | Hypothesis testing |

---

*Document prepared for arXiv submission review - December 2025*
