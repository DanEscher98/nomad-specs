# NOMAD Protocol Preprint: Critical Evaluation

**Document:** NOMAD: A Secure State Synchronization Protocol for Mobile Applications over UDP  
**Target:** arXiv preprint → conference CFP (RustConf, security venues)  
**Evaluation Date:** 2025-12-26  
**Status:** 🔴 Several issues requiring attention before submission

---

## Executive Summary

The paper presents solid foundational work but has **credibility gaps** that reviewers will flag. The main concerns are:

1. **Test count arithmetic doesn't add up** (claims 1,000+, table shows ~323)
2. **No performance evaluation** (only conformance testing)
3. **Session ID collision probability** unaddressed (48-bit birthday bound)
4. **Naming conflict** with HashiCorp Nomad
5. **Single author** claiming formal verification + implementation + test suite

---

## 🔴 Critical Issues (Must Fix)

### 1. Test Count Discrepancy

**Problem:** Abstract and Section 8.2 claim "over 1,000 test cases" but Table 6 shows:

| Category | Count |
|----------|-------|
| Unit | 80 |
| Protocol | 107 |
| Adversarial | 36 |
| Resilience | 60+ |
| Wire | 40+ |
| **Total** | **~323** |

**Fix:** Either:
- Add missing test categories (property-based test case count? fuzzing iterations?)
- Clarify that "1,000+" includes parameterized test instances
- Revise the claim downward

Reviewers will do this arithmetic. This is an easy rejection trigger.

---

### 2. Session ID Birthday Bound

**Problem:** 48-bit session ID (6 bytes) has collision probability:

```
P(collision) ≈ n²/2^49
At n = 2^24 sessions: P ≈ 50%
```

For a server handling many connections, this is reachable. WireGuard uses 32-bit receiver index but per-peer, not global.

**Questions reviewers will ask:**
- Is session ID globally unique or per-peer?
- What happens on collision?
- Why not 64-bit or 128-bit?

**Fix:** Add explicit discussion of:
- Session ID scope (per-keypair or global)
- Collision handling
- Justification for 48-bit choice

---

### 3. Naming Conflict: HashiCorp Nomad

**Problem:** "Nomad" is HashiCorp's widely-used workload orchestrator (11k+ GitHub stars). This will cause:
- SEO/discoverability issues
- Confusion in infrastructure communities
- Potential trademark concerns

**Fix options:**
1. Rename protocol (ROAM? DRIFT? SSP2?)
2. Add disambiguation in abstract/intro
3. At minimum, acknowledge in paper

I'd recommend renaming before publication—you're targeting infrastructure developers who definitely know HashiCorp Nomad.

---

### 4. No Performance Evaluation

**Problem:** Section 8 is titled "Evaluation" but contains only conformance testing. Missing:
- Latency measurements (keystroke-to-display)
- Bandwidth overhead vs Mosh
- CPU/memory usage
- Battery impact
- Comparison under packet loss/latency

**Reviewer reaction:** "This is a protocol paper with no performance data comparing to the protocol it claims to improve upon."

**Fix options:**
1. Add performance section with benchmarks
2. Rename section to "Conformance Testing" and add "Performance Evaluation" as explicit future work
3. Be upfront in abstract that this is spec + verification, not measurement paper

For arXiv preprint this is acceptable with proper framing. For conference submission, benchmarks are expected.

---

### 5. Single Author Scope

**Problem:** Paper claims:
- Complete protocol specification
- Rust reference implementation
- ProVerif formal model
- TLA+ formal model
- 1,000+ test conformance suite
- Vulnerability discovery and fix

This is substantial work for one person. Reviewers may be skeptical.

**Mitigations:**
- Add acknowledgments for reviewers/contributors
- Reference GitHub commit history showing work progression
- Consider adding co-authors if others contributed significantly
- Be explicit about timeline (how long did this take?)

---

## 🟡 Technical Concerns (Should Address)

### 6. Nonce Structure Waste

```
Epoch (4B) | Direction (1B) | Zeros (11B) | Counter (8B)
```

11 bytes of zeros is unusual. Reviewers will ask why not:
- Use more epoch bits for longer sessions
- Add random padding for traffic analysis resistance
- Include session ID for additional domain separation

**Fix:** Add rationale for the zero padding, or redesign.

---

### 7. HKDF-BLAKE2s Non-Standard

HKDF (RFC 5869) is defined with HMAC. "HKDF-BLAKE2s" is non-standard terminology.

**Options:**
- Use BLAKE2s's keyed mode directly (it's a MAC)
- Define explicitly: "HKDF instantiated with HMAC-BLAKE2s"
- Switch to standard HKDF-SHA256 for auditability

WireGuard uses BLAKE2s for hashing but HKDF extract/expand. Clarify your construction.

---

### 8. PCS Fix Seems Incomplete

The post-compromise security fix:

```
k_auth = HKDF(DH(s_i, S_r), "rekey auth")
(k'_i, k'_r) = HKDF(DH(e_i, e_r) || k_auth, n)
```

**Issue:** `DH(s_i, S_r)` is the static-static DH, which is already part of Noise_IK's `ss` token. If the attacker compromised the session keys, did they also get the handshake transcript? Could they derive `k_auth`?

**Clarify:**
- What exactly is compromised in the threat model?
- Why is static-static DH not already captured in session keys?
- Is `k_auth` derived during handshake and stored, or recomputed?

The fix may be correct but the explanation is hand-wavy for a security paper.

---

### 9. Replay Check Before AEAD

> "The replay check occurs *before* AEAD verification to prevent CPU exhaustion attacks"

**Problem:** This means you're trusting the plaintext nonce counter before authentication. An attacker could:
1. Observe a valid packet with nonce N
2. Forge a packet with nonce N+1000000 (invalid AEAD)
3. Cause the receiver to advance the replay window
4. Now legitimate packets with nonces in the skipped range are rejected

**Fix:** Standard approach is:
- Replay check AFTER AEAD verification
- Use rate limiting for CPU exhaustion protection
- Or: cheap MAC check before expensive operations (but this adds complexity)

This is a real vulnerability. WireGuard does replay check after decryption.

---

### 10. Convergence Algorithm Gap

```python
if msg.sender_state_num > peer_state_num:
    peer_state = apply(peer_state, msg.diff)
```

**Problem:** The diff has a `base_state_number`. What if:
- `base_state_number` doesn't match current state?
- States diverged due to concurrent mutations?

The algorithm ignores `base_state_number` entirely. Either:
- It's not needed (remove from format)
- It IS needed (algorithm is incomplete)

Mosh handles this with frame-based diffs from acknowledged state. Clarify your approach.

---

### 11. Message Counter Overflow

```
REJECT_AFTER_MESSAGES = 2^64 - 1
```

But the nonce counter is 8 bytes (64 bits). You'd overflow before reaching rejection. Either:
- Counter wraps (security issue)
- Counter saturates (needs explicit handling)
- Rekey always happens first (2^60 threshold saves you)

Clarify the behavior when counter approaches 2^64.

---

## 🟢 Minor Issues (Nice to Fix)

### 12. Missing Related Work

- **Eternal Terminal (et):** Direct Mosh competitor, SSH-based reconnection
- **DTLS:** UDP + TLS, relevant baseline
- **tmux/screen:** Often paired with Mosh, worth mentioning
- **MQTT over QUIC:** Competing in IoT space

---

### 13. Vague Key Distribution

> "obtained via SSH, QR code, or other secure channel"

For a formal protocol paper, this hand-waving is notable. Consider:
- Referencing TOFU (Trust On First Use) model
- Defining a key fingerprint format
- Specifying interaction with SSH known_hosts

---

### 14. JSON5 for Test Vectors

> "Vectors are stored in JSON5 format with inline comments"

JSON5 is non-standard. Many languages lack parsers. Consider:
- Standard JSON with separate documentation
- YAML (widely supported, allows comments)
- JSON with `_comment` fields

---

### 15. References Incomplete

The bibliography uses `\bibliography{references}` but the references file isn't included. Ensure:
- All citations resolve ([hypothesis] needs entry)
- RFC citations use proper format
- Mosh USENIX paper is correctly cited

---

### 16. Table 7 Comparison Framing

"Cipher Negotiation: No" is presented as a feature (matching WireGuard/Mosh). But the row structure implies it's a comparison point. Consider:
- Renaming to "Fixed Cipher Suite: Yes"
- Or moving to a "Design Philosophy" discussion

---

## Structural Recommendations

### For arXiv Submission

1. **Fix test count** immediately
2. **Add session ID collision discussion**
3. **Rename protocol** or acknowledge HashiCorp conflict
4. **Clarify replay check vulnerability** (or fix it)
5. Add "Limitations" subsection before Conclusion

### For Conference CFP

All above, plus:
1. **Add performance benchmarks** (keystroke latency, bandwidth, vs Mosh)
2. **Add network simulation results** (tc/netem, packet loss scenarios)
3. Consider splitting: security analysis paper vs systems paper

---

## Verification Checklist

Before submission, verify:

- [ ] GitHub repo `DanEscher98/nomad-specs` is public and matches paper
- [ ] crates.io `nomad-protocol` exists and builds
- [ ] Documentation at `danescher98.github.io/nomad-rs` is live
- [ ] Test suite actually has 1,000+ tests (or revise claim)
- [ ] ProVerif/TLA+ models are in `formal/` directory
- [ ] All references compile (`bibtex` runs clean)
- [ ] No TODO/FIXME in LaTeX source

---

## Suggested Revision Priority

| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| P0 | Test count discrepancy | Low | High (credibility) |
| P0 | Replay check vulnerability | Medium | High (security) |
| P1 | Session ID collision | Low | Medium |
| P1 | Protocol naming | Low | Medium |
| P1 | PCS fix explanation | Medium | Medium |
| P2 | Performance benchmarks | High | High (for conferences) |
| P2 | Nonce structure rationale | Low | Low |
| P3 | Related work gaps | Low | Low |

---

## Positive Notes

To balance the criticism:

- **Solid structure:** Layer separation is clean and well-motivated
- **Formal verification:** ProVerif + TLA+ combination is rigorous
- **Vulnerability disclosure:** Finding and fixing PCS issue shows maturity
- **Clear non-goals:** Explicitly scoping out features shows engineering judgment
- **WireGuard philosophy:** Fixed cipher suite is the right call
- **Test infrastructure:** Docker-based conformance testing is practical

The core protocol design appears sound. These issues are about presentation and edge cases, not fundamental flaws.

---

## Next Steps

1. Address P0 issues before any submission
2. Decide: arXiv-only vs conference target
3. If conference: add benchmarks (2-3 weeks work)
4. Get 2-3 external reviewers on the protocol (security folks)
5. Consider renaming before establishing the brand

**Recommendation:** Fix P0/P1 issues, submit to arXiv, then iterate based on feedback before conference submission.
