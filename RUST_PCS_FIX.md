# Rust Implementation: PCS Fix Instructions

> **Priority:** HIGH
> **Date:** 2025-12-26
> **Source:** Formal verification (ProVerif) found vulnerability
> **Status:** Spec updated, implementation needs update

---

## Executive Summary

Formal verification discovered a **Post-Compromise Security (PCS) vulnerability** in the original rekeying design. An active attacker who compromises a session key can maintain access through subsequent rekeys.

**The fix:** Derive a `rekey_auth_key` from static DH during handshake, and mix it into the rekey KDF.

---

## What Changed

### 1. New Key: `rekey_auth_key`

**During handshake**, after computing session keys, derive an additional key:

```rust
// After: DH(initiator_static, responder_static) is computed
// The "static_dh_secret" is the result of this DH

let rekey_auth_key = hkdf_expand(
    &static_dh_secret,      // 32 bytes from DH(s_i, S_r)
    b"nomad v1 rekey auth", // info string
    32                      // output length
);

// Store rekey_auth_key for session lifetime
session.rekey_auth_key = rekey_auth_key;
```

### 2. Updated Rekey KDF

**During rekeying**, mix `rekey_auth_key` into the new key derivation:

```rust
// OLD (vulnerable):
let (new_i_key, new_r_key) = hkdf_expand(
    &ephemeral_dh,
    &format!("nomad v1 rekey{}", epoch.to_le_bytes()),
    64
);

// NEW (fixed):
let mut ikm = Vec::with_capacity(64);
ikm.extend_from_slice(&ephemeral_dh);        // 32 bytes
ikm.extend_from_slice(&session.rekey_auth_key); // 32 bytes

let info = format!("nomad v1 rekey");
let mut info_bytes = info.as_bytes().to_vec();
info_bytes.extend_from_slice(&(epoch as u32).to_le_bytes()); // LE32(epoch)

let (new_i_key, new_r_key) = hkdf_expand(
    &ikm,        // ephemeral_dh || rekey_auth_key
    &info_bytes, // "nomad v1 rekey" || LE32(epoch)
    64
);
```

---

## Precise Changes

### Change 1: Session State

Add `rekey_auth_key` field to session state:

```rust
pub struct Session {
    // ... existing fields ...

    /// Key for post-compromise security during rekey.
    /// Derived from static DH during handshake.
    /// MUST be retained for session lifetime.
    rekey_auth_key: [u8; 32],
}
```

### Change 2: Handshake Completion

After computing session keys, derive `rekey_auth_key`:

```rust
impl Session {
    pub fn complete_handshake(
        handshake_hash: &[u8],
        static_dh_secret: &[u8; 32],  // DH(s_initiator, S_responder)
    ) -> Self {
        // Existing: derive session keys
        let (initiator_key, responder_key) = hkdf_expand(
            handshake_hash,
            b"nomad v1 session keys",
            64
        ).split();

        // NEW: derive rekey auth key
        let rekey_auth_key = hkdf_expand(
            static_dh_secret,
            b"nomad v1 rekey auth",
            32
        );

        Session {
            initiator_key,
            responder_key,
            rekey_auth_key,  // NEW
            epoch: 0,
            // ...
        }
    }
}
```

### Change 3: Rekey Key Derivation

Update the rekey key derivation function:

```rust
impl Session {
    pub fn derive_rekey_keys(
        &self,
        ephemeral_dh: &[u8; 32],
        new_epoch: u32,
    ) -> (Key, Key) {
        // Concatenate ephemeral_dh || rekey_auth_key
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ephemeral_dh);
        ikm[32..].copy_from_slice(&self.rekey_auth_key);

        // Build info: "nomad v1 rekey" || LE32(epoch)
        let mut info = b"nomad v1 rekey".to_vec();
        info.extend_from_slice(&new_epoch.to_le_bytes());

        // Derive new keys
        hkdf_expand(&ikm, &info, 64).split()
    }
}
```

---

## HKDF Details

If not already using HKDF-Expand with BLAKE2s:

```rust
use blake2::Blake2s256;
use hkdf::Hkdf;

fn hkdf_expand(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    // For NOMAD, we use HKDF with BLAKE2s-256
    let hk = Hkdf::<Blake2s256>::new(None, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("valid length");
    okm
}
```

---

## Constant Strings

| Purpose | String | Encoding |
|---------|--------|----------|
| Session keys | `"nomad v1 session keys"` | UTF-8 bytes |
| Rekey auth key | `"nomad v1 rekey auth"` | UTF-8 bytes |
| Rekey keys | `"nomad v1 rekey" \|\| LE32(epoch)` | UTF-8 + little-endian u32 |

---

## Why This Fix Works

The attack scenario (before fix):
1. Attacker compromises epoch N key
2. During rekey, attacker intercepts ephemeral exchange
3. Attacker injects their own ephemeral key
4. Both parties compute DH with attacker's key
5. Attacker derives epoch N+1 key

With fix:
1. Attacker compromises epoch N key
2. During rekey, attacker intercepts ephemeral exchange
3. Attacker injects their own ephemeral key
4. **Attacker cannot compute `rekey_auth_key`** (derived from static DH during handshake)
5. Attacker cannot derive epoch N+1 key

---

## Test Cases

After implementing, verify:

1. **Basic rekey works:**
   - Complete handshake
   - Trigger rekey
   - Verify new keys are different from old
   - Verify both parties derive same keys

2. **rekey_auth_key is deterministic:**
   - Same handshake → same `rekey_auth_key`
   - Different handshakes → different `rekey_auth_key`

3. **PCS property:**
   - Knowing epoch N key + ephemeral DH
   - Without `rekey_auth_key`
   - Cannot derive epoch N+1 key

---

## Files to Modify (Likely)

```
nomad-rs/
├── src/
│   ├── session.rs         # Add rekey_auth_key field
│   ├── handshake.rs       # Derive rekey_auth_key after handshake
│   ├── rekey.rs           # Update rekey KDF
│   └── crypto/
│       └── kdf.rs         # Ensure HKDF-BLAKE2s available
└── tests/
    └── rekey_test.rs      # Add PCS test cases
```

---

## Validation Against Spec

After implementation:
1. Re-run conformance tests: `just test-server`
2. Once t6-vectors updates test vectors, verify against those
3. Verify with: `formal/proverif/nomad_rekey_fixed.pv` describes your implementation

---

## Questions?

- Spec: `nomad-specs/specs/1-SECURITY.md` (§Session Key Derivation, §Post-Rekey Keys)
- Formal proof: `nomad-specs/formal/proverif/nomad_rekey_fixed.pv`
- Security finding: `nomad-specs/formal/SECURITY_FINDINGS.md`
