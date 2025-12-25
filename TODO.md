# Tentacle: t6-vectors
## Reference codec and test vectors

**Scope:** tests/lib/reference.py, tests/vectors/*, specs/generate_vectors.py

## Tasks
- [x] Implement `tests/lib/reference.py` - Python reference codec (NomadCodec class)
  - [x] Frame encoding/decoding (data frames, headers)
  - [x] Nonce construction
  - [x] XChaCha20-Poly1305 AEAD
  - [x] Sync message encoding/decoding
- [x] Add `tests/vectors/sync_vectors.json5` - sync layer test vectors
- [x] Update `tests/pyproject.toml` with crypto dependencies (cryptography, pynacl)
- [x] Write unit tests for reference codec in `tests/unit/test_reference.py`
- [x] Verify vector generation is idempotent

## Notes
<!-- Context from brain -->
- Vector generator already exists at `specs/generate_vectors.py`
- Existing vectors: aead_vectors.json5, frame_vectors.json5, handshake_vectors.json5, nonce_vectors.json5
- Missing: sync_vectors.json5
- Reference codec implements NomadCodec interface per contracts/interfaces.md
- Other tentacles (t1, t2, t3) depend on this work

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Auto-generated from .octopus/master-todo.md*
