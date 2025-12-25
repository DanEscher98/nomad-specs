# Tentacle: t1-security
## Security layer spec + tests

**Scope:** specs/1-SECURITY.md, tests/unit/test_crypto*, tests/protocol/test_handshake*

**BLOCKED BY:** ~~t6-vectors~~ (RESOLVED - t6-vectors merged)

## Tasks

### Spec Refinement
- [x] Review/refine `specs/1-SECURITY.md` for completeness
  - [x] Noise_IK handshake pattern documentation
  - [x] Key derivation (HKDF) specification
  - [x] Session key rotation / rekeying
  - [x] Mermaid diagrams for handshake flow

### Unit Tests (tests/unit/test_crypto*.py)
- [x] `test_crypto_aead.py` - XChaCha20-Poly1305 encrypt/decrypt
  - [x] Test against `tests/vectors/aead_vectors.json5`
  - [x] Property tests with hypothesis
- [x] `test_crypto_handshake.py` - Noise IK pattern
  - [x] Test against `tests/vectors/handshake_vectors.json5`
  - [x] Keypair generation
  - [x] Session key derivation
- [x] `test_crypto_nonce.py` - Nonce construction
  - [x] Test against `tests/vectors/nonce_vectors.json5`
  - [x] Counter overflow handling

### Protocol Tests (tests/protocol/test_handshake*.py)
- [x] `test_handshake_flow.py` - E2E handshake
  - [x] Successful handshake (client -> server)
  - [x] Invalid static key rejection
  - [x] Replay protection
- [x] `test_handshake_rekey.py` - Session rekeying
  - [x] Rekey after N messages
  - [x] Rekey on timer

### Adversarial Tests (tests/adversarial/)
- [x] `test_replay_attack.py` - Nonce reuse detection
- [x] `test_key_compromise.py` - Forward secrecy validation

## Dependencies
- `tests/lib/reference.py` from t6-vectors (AVAILABLE)
- `tests/vectors/*.json5` from t6-vectors (AVAILABLE)

## Notes
- Use `cryptography` library for reference AEAD operations
- Use `snow` library for Noise protocol reference
- Spec must be isomorphic to tests (each section maps to test cases)
- Consult `brainstorm/` for original design notes

## Blocked
<!-- No blockers - all tasks complete -->

---
*Brain: feature/epic-conformance-suite*
