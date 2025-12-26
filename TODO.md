# Tentacle: t6-vectors
## Reference codec and test vectors

**Scope:** tests/lib/reference.py, tests/vectors/*, specs/generate_vectors.py

## Phase 1 Tasks (COMPLETED)
- [x] Implement `tests/lib/reference.py` - Python reference codec (NomadCodec class)
  - [x] Frame encoding/decoding (data frames, headers)
  - [x] Nonce construction
  - [x] XChaCha20-Poly1305 AEAD
  - [x] Sync message encoding/decoding
- [x] Add `tests/vectors/sync_vectors.json5` - sync layer test vectors
- [x] Update `tests/pyproject.toml` with crypto dependencies (cryptography, pynacl)
- [x] Write unit tests for reference codec in `tests/unit/test_reference.py`
- [x] Verify vector generation is idempotent

---

## Phase 2 Tasks: PCS Fix (COMPLETED)

**Context:** Formal verification (t11-formal) found a Post-Compromise Security (PCS) vulnerability.
The fix requires a new `rekey_auth_key` derived during handshake and mixed into rekey KDF.

See: `formal/SECURITY_FINDINGS.md` for full details.

### New Key Derivation (from updated 1-SECURITY.md)

```
// During handshake, after computing session keys:
rekey_auth_key = HKDF-Expand(static_dh_secret, "nomad v1 rekey auth", 32)

// During each rekey:
(new_initiator_key, new_responder_key) = HKDF-Expand(
    ephemeral_dh || rekey_auth_key,
    "nomad v1 rekey" || LE32(epoch),
    64
)
```

### Tasks

- [x] Update `tests/lib/reference.py`:
  - [x] Add `rekey_auth_key` derivation in handshake
  - [x] Update rekey key derivation to mix `rekey_auth_key`
  - [x] Add helper function for new KDF

- [x] Update `tests/vectors/handshake_vectors.json5`:
  - [x] Add `rekey_auth_key` field to handshake test vectors
  - [x] Document the new key derivation

- [x] Create `tests/vectors/rekey_vectors.json5` (if doesn't exist):
  - [x] Add test vectors for epoch 0 → 1 transition
  - [x] Add test vectors for epoch 1 → 2 transition (PCS case)
  - [x] Include intermediate values for debugging

- [x] Update `specs/generate_vectors.py`:
  - [x] Add rekey vector generation
  - [x] Regenerate all vectors

- [x] Add/update tests:
  - [x] Test `rekey_auth_key` derivation
  - [x] Test rekey KDF with auth key mixed in
  - [x] Test PCS property (epoch N+1 keys can't be derived from epoch N compromise)

---

## Notes

- The PCS fix is **already in specs/1-SECURITY.md** (merged from t11-formal)
- Reference implementation MUST match the updated spec
- Rust/Go implementations will need same update (external to this tentacle)
- See `formal/proverif/nomad_rekey_fixed.pv` for the verified fix

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Auto-generated from .octopus/master-todo.md*
