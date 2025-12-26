# t11-formal: Formal Verification

## Context

Formal verification of NOMAD security properties using ProVerif and TLA+.
Latest specs have been synced with clarifications from paper feedback (Round 2).

## Completed

- [x] ProVerif model for Noise_IK handshake
- [x] ProVerif model for replay protection
- [x] ProVerif model for rekey (nomad_rekey_fixed.pv with PCS fix)
- [x] TLA+ spec for rekey state machine
- [x] TLA+ spec for sync layer convergence
- [x] SECURITY_FINDINGS.md documenting PCS vulnerability and fix

## Formal Verification Transparency (TODO - Reviewer Feedback Round 2)

### ProVerif

- [x] Extract key queries to include in paper appendix (PAPER_APPENDIX_QUERIES.md)
- [x] Document adversary model assumptions in nomad_rekey_fixed.pv
- [x] Add comments mapping model to spec sections
- [x] Verify explicit PCS threat model matches spec:
  - Assumed compromised: session keys, ephemeral keys, epoch N traffic
  - Assumed uncompromised: static keys, rekey_auth_key

### TLA+

- [x] Add SyncLayer convergence proof sketch (informal)
- [x] Document fairness assumptions for liveness
- [x] Add idempotence property to SyncLayer model
- [x] Add sliding window algorithm model (verify anti-replay) - SlidingWindow.tla

### Cross-Validation

- [x] Update CROSS_VALIDATION.md with new test vector hashes
- [x] Verify formal models match updated spec constants:
  - REKEY_AFTER_TIME: 300s / 5 min (was 120s)
  - REJECT_AFTER_TIME: 360s / 6 min (REKEY + 60s grace)
  - REKEY_AFTER_MESSAGES: 2^32 (was 2^60)
  - OLD_KEY_RETENTION: adaptive max(5×SRTT, 30s)
- [x] Document model bounds and their implications - MODELING_ASSUMPTIONS.md

**NOTE**: 5-minute rekey interval chosen as middle ground:
- More practical than 2 min (Mosh) - 60% fewer rekeys
- Tighter forward secrecy than 1 hour - ≤5 min exposure window
- Matches typical interactive work unit duration

### Documentation

- [x] Add example ProVerif output to formal/README.md
- [x] Add example TLC output to formal/README.md
- [x] Create MODELING_ASSUMPTIONS.md listing all simplifications

## Updated Specs Available

The following specs have been clarified based on paper feedback (Round 2):

### specs/1-SECURITY.md (Round 2)
- PCS explicit adversary model (assumed compromised/uncompromised)
- Rekeying parameters updated (300s/5min, 2^32, adaptive OLD_KEY_RETENTION)
- Anti-replay sliding window algorithm pseudo-code
- Nonce "Reserved" field (renamed from "Zeros")

### specs/3-SYNC.md (Round 2)
- Idempotent diff formalization (formal definition, allowed types)
- CRDT references (Almeida 2018)
- Convergence theorem with proof sketch

### specs/2-TRANSPORT.md (Round 2)
- Congestion control rationale (RFC 8085 reference)
- Frame pacing limitations documented

### specs/1-SECURITY.md (Round 1)
- HKDF-BLAKE2s formal definition (keyed mode, not HMAC)
- PCS threat model with attack walkthrough
- Nonce structure rationale (24-byte for XChaCha20)
- Session ID scope (per-responder, 48-bit rationale)
- Replay check ordering (window MUST NOT advance before AEAD)

### specs/3-SYNC.md (Round 1)
- base_state_num field semantics (ignore for convergence)
- Counter overflow handling (64-bit limits)

## Optional Future Work

- [x] Verify replay check ordering property in ProVerif (Q4 in nomad_replay.pv)
- [x] Model counter exhaustion termination in TLA+ (StateNumBounded in SyncLayer.tla)
- [ ] Add machine-checked proofs for HKDF construction

## Notes

- PCS fix is the key security contribution
- Formal models in `formal/proverif/` and `formal/tlaplus/`
- Run verification: see `formal/README.md`
