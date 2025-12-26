# Tentacle: t11-formal
## Formal verification - ProVerif security, TLA+ state machine

**Scope:** formal/, specs/

## Tasks

### ProVerif Security Models
- [x] Write ProVerif model for Noise_IK handshake (authentication, key secrecy)
- [x] Write ProVerif model for forward secrecy (rekey mechanism)
- [x] Write ProVerif model for replay protection

### TLA+ State Machine Specs
- [x] Write TLA+ spec for sync layer convergence
- [x] Write TLA+ spec for rekey state machine
- [x] Write TLA+ spec for roaming/migration

### Cross-Validation with Test Vectors
- [x] Extract symbolic traces from ProVerif → compare with handshake_vectors.json5
- [x] Generate TLA+ state sequences → compare with nonce/rekey vector transitions
- [x] Document any discrepancies between formal model and test vectors

### Documentation
- [x] Create formal/README.md documenting models and how to run them
- [x] Add formal verification references to specs (1-SECURITY.md, 2-TRANSPORT.md, 3-SYNC.md)
- [ ] Add "Formal Verification" section to arXiv paper (coordinate with t9-paper)

### Security Audit (elevated scope)
- [x] Run all ProVerif models and verify
- [x] Run all TLA+ models and verify
- [x] Fix model bugs (syntax errors, invariant issues)
- [x] Document PCS limitation finding (HIGH severity)
- [x] Create SECURITY_FINDINGS.md report
- [x] Add Justfile commands for formal verification
- [x] Update README with installation instructions
- [ ] Add identity hiding query to handshake (P1 future work)

## Notes
<!-- Context from brain -->
Security properties to verify (from 1-SECURITY.md):
- Confidentiality: XChaCha20-Poly1305 AEAD
- Integrity: Poly1305 authentication tag
- Authenticity: Noise_IK mutual authentication
- Forward secrecy: Ephemeral keys + 2-minute rekeying
- Replay protection: Nonce counter + sliding window
- Identity hiding (initiator): Static key encrypted

Sync properties to verify (from 3-SYNC.md):
- Idempotent diffs: Applying same diff twice is safe
- Monotonic versions: Out-of-order handled via version comparison
- Eventual consistency: State converges when any message gets through

### Files Created

**ProVerif Models:**
- `formal/proverif/nomad_handshake.pv` - Noise_IK handshake security
- `formal/proverif/nomad_rekey.pv` - Forward secrecy via rekeying
- `formal/proverif/nomad_replay.pv` - Replay protection

**TLA+ Specifications:**
- `formal/tlaplus/SyncLayer.tla` - Sync layer convergence
- `formal/tlaplus/RekeyStateMachine.tla` - Rekey state machine
- `formal/tlaplus/Roaming.tla` - Connection migration

**Documentation:**
- `formal/README.md` - Main documentation (updated with installation instructions)
- `formal/CROSS_VALIDATION.md` - Test vector correspondence
- `formal/SECURITY_FINDINGS.md` - Security audit report with PCS limitation

## Blocked

### Coordination with t9-paper
**Need:** Add "Formal Verification" section to arXiv paper
**Status:** Waiting for t9-paper tentacle to provide paper structure
**Suggested content:**
- Summary of ProVerif security proofs
- TLA+ state machine verification
- Reference to formal/ directory for full models

---

## Escalation to Brain

### [CRITICAL] PCS Fix Requires Test Vector & Implementation Updates

**Date:** 2025-12-26
**From:** t11-formal
**Priority:** HIGH

#### Summary

Formal verification found a PCS (Post-Compromise Security) vulnerability in the original rekeying design. A fix has been developed, formally verified, and the spec updated.

#### What Changed

**1. Spec Update (specs/1-SECURITY.md):**
- Added `rekey_auth_key` derivation in §Session Key Derivation
- Updated §Post-Rekey Keys to mix `rekey_auth_key` into KDF
- Added PCS to §Security Properties

**2. New Key Derivation:**
```
// During handshake:
rekey_auth_key = HKDF(static_dh_secret, "nomad v1 rekey auth", 32)

// During rekey:
new_keys = HKDF(ephemeral_dh || rekey_auth_key, "nomad v1 rekey" || epoch, 64)
```

#### Action Required

| Task | Tentacle | Priority |
|------|----------|----------|
| Update `tests/vectors/handshake_vectors.json5` with rekey_auth_key | t6-vectors | HIGH |
| Update rekey test vectors with new KDF | t6-vectors | HIGH |
| Update Rust implementation | (external) | HIGH |
| Update Go implementation | (external) | HIGH |

#### Verification

The fix is formally verified:
- `formal/proverif/nomad_rekey_fixed.pv` - Q3 (PCS) passes
- See `formal/SECURITY_FINDINGS.md` for full analysis

---
*Auto-generated from .octopus/master-todo.md*
