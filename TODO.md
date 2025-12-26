# Tentacle: t11-formal
## Formal verification - ProVerif security, TLA+ state machine

**Scope:** formal/, specs/

## Tasks

### ProVerif Security Models
- [ ] Write ProVerif model for Noise_IK handshake (authentication, key secrecy)
- [ ] Write ProVerif model for forward secrecy (rekey mechanism)
- [ ] Write ProVerif model for replay protection

### TLA+ State Machine Specs
- [ ] Write TLA+ spec for sync layer convergence
- [ ] Write TLA+ spec for rekey state machine
- [ ] Write TLA+ spec for roaming/migration

### Cross-Validation with Test Vectors
- [ ] Extract symbolic traces from ProVerif → compare with handshake_vectors.json5
- [ ] Generate TLA+ state sequences → compare with nonce/rekey vector transitions
- [ ] Document any discrepancies between formal model and test vectors

### Documentation
- [ ] Create formal/README.md documenting models and how to run them
- [ ] Add formal verification references to specs (1-SECURITY.md, 3-SYNC.md)
- [ ] Add "Formal Verification" section to arXiv paper (coordinate with t9-paper)

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

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Auto-generated from .octopus/master-todo.md*
