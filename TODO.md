# t11-formal: Formal Verification

## Context

Formal verification of NOMAD security properties using ProVerif and TLA+.
Latest specs have been synced with clarifications from paper feedback.

## Completed

- [x] ProVerif model for Noise_IK handshake
- [x] ProVerif model for replay protection
- [x] ProVerif model for rekey (nomad_rekey_fixed.pv with PCS fix)
- [x] TLA+ spec for rekey state machine
- [x] TLA+ spec for sync layer convergence
- [x] SECURITY_FINDINGS.md documenting PCS vulnerability and fix

## Updated Specs Available

The following specs have been clarified based on paper feedback:

### specs/1-SECURITY.md
- HKDF-BLAKE2s formal definition (Extract/Expand steps)
- PCS threat model with attack walkthrough
- Nonce structure rationale (24-byte for XChaCha20)
- Session ID scope (per-responder, 48-bit rationale)
- Replay check ordering (window MUST NOT advance before AEAD)

### specs/3-SYNC.md
- base_state_num field semantics (ignore for convergence)
- Counter overflow handling (64-bit limits)

## Optional Future Work

- [ ] Verify replay check ordering property in ProVerif
- [ ] Model counter exhaustion termination in TLA+
- [ ] Add machine-checked proofs for HKDF construction

## Notes

- PCS fix is the key security contribution
- Formal models in `formal/proverif/` and `formal/tlaplus/`
- Run verification: see `formal/README.md`
