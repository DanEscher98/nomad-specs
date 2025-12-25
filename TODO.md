# Tentacle: t1-security
## Security layer spec + tests

**Scope:** specs/1-SECURITY.md, tests/unit/test_crypto*, tests/protocol/test_handshake*

**BLOCKED BY:** t6-vectors (need reference codec first)

## Tasks

### Spec Refinement
- [ ] Review/refine `specs/1-SECURITY.md` for completeness
  - [ ] Noise_IK handshake pattern documentation
  - [ ] Key derivation (HKDF) specification
  - [ ] Session key rotation / rekeying
  - [ ] Mermaid diagrams for handshake flow

### Unit Tests (tests/unit/test_crypto*.py)
- [ ] `test_crypto_aead.py` - XChaCha20-Poly1305 encrypt/decrypt
  - [ ] Test against `tests/vectors/aead_vectors.json5`
  - [ ] Property tests with hypothesis
- [ ] `test_crypto_handshake.py` - Noise IK pattern
  - [ ] Test against `tests/vectors/handshake_vectors.json5`
  - [ ] Keypair generation
  - [ ] Session key derivation
- [ ] `test_crypto_nonce.py` - Nonce construction
  - [ ] Test against `tests/vectors/nonce_vectors.json5`
  - [ ] Counter overflow handling

### Protocol Tests (tests/protocol/test_handshake*.py)
- [ ] `test_handshake_flow.py` - E2E handshake
  - [ ] Successful handshake (client → server)
  - [ ] Invalid static key rejection
  - [ ] Replay protection
- [ ] `test_handshake_rekey.py` - Session rekeying
  - [ ] Rekey after N messages
  - [ ] Rekey on timer

### Adversarial Tests (tests/adversarial/)
- [ ] `test_replay_attack.py` - Nonce reuse detection
- [ ] `test_key_compromise.py` - Forward secrecy validation

## Dependencies
- `tests/lib/reference.py` from t6-vectors
- `tests/vectors/*.json5` from t6-vectors

## Notes
- Use `cryptography` library for reference AEAD operations
- Use `snow` library for Noise protocol reference
- Spec must be isomorphic to tests (each section maps to test cases)
- Consult `brainstorm/` for original design notes

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
