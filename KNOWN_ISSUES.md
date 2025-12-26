# Known Issues

## HKDF Hash Function Mismatch (Priority: HIGH)

**Status:** Open - requires fix before v1.0 release

### Description

The specification requires HKDF-BLAKE2s for all key derivation (per Noise_IK_25519_ChaChaPoly_BLAKE2s suite), but the Python reference codec uses SHA-256 for HKDF-Expand.

**Specification (0-PROTOCOL.md line 128):**
```
| Key Derivation | HKDF-BLAKE2s | Noise specification |
```

**Implementation (tests/lib/reference.py line 765):**
```python
hkdf = HKDFExpand(
    algorithm=hashes.SHA256(),  # Should be BLAKE2s
    ...
)
```

### Impact

- Test vectors in `tests/vectors/` are generated with SHA-256
- Implementations using BLAKE2s will fail vector validation
- Rust implementation (nomad-rs) should use BLAKE2s per spec

### Affected Functions

- `derive_session_keys()` - session key derivation
- `derive_rekey_auth_key()` - PCS rekey auth key
- `derive_rekey_keys()` - post-rekey key derivation

### Resolution Options

1. **Update implementation to BLAKE2s** (Recommended)
   - Implement HMAC-BLAKE2s in Python (cryptography lib doesn't support)
   - Regenerate all test vectors
   - Aligns with Noise specification

2. **Update spec to SHA-256**
   - Change spec to use SHA-256 for HKDF
   - Vectors already correct
   - Deviates from standard Noise suite

### Workaround

For now, implementations should:
- Use BLAKE2s (per spec) for production
- Compare against Rust implementation vectors once available
- Python reference codec is for structure testing, not crypto validation

### References

- Noise Protocol Framework: https://noiseprotocol.org/noise.html
- RFC 5869: HKDF
- Issue discovered during cross-validation 2025-12-26
