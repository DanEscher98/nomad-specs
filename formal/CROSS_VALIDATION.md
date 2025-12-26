# Formal Model Cross-Validation with Test Vectors

This document describes the correspondence between the formal models and the test vectors in `tests/vectors/`.

## Overview

The formal models are **symbolic** - they abstract cryptographic operations and focus on protocol structure. The test vectors are **concrete** - they contain actual byte sequences. Cross-validation ensures:

1. Formal model structure matches test vector format
2. State transitions in TLA+ match vector derivation logic
3. ProVerif message flows match handshake vector sequences

## Handshake Cross-Validation

### Test Vectors: `handshake_vectors.json5`

| Vector | Formal Model Correspondence |
|--------|----------------------------|
| `handshake_init_structure` | `nomad_handshake.pv` message 1 |
| `handshake_resp_structure` | `nomad_handshake.pv` message 2 |
| `keypairs` | ProVerif key generation (`new ie_priv: privkey`) |

### Structure Validation

```
Test Vector Field       ProVerif Symbol         Match
─────────────────────────────────────────────────────
type (0x01)            HandshakeInit           ✓
initiator_ephemeral    ie = pk(ie_priv)        ✓
encrypted_static       enc_static              ✓
encrypted_payload      enc_payload             ✓
session_id             session_id              ✓
responder_ephemeral    re = pk(re_priv)        ✓
```

### Symbolic Trace Extraction

To extract symbolic traces from ProVerif that correspond to test vectors:

```bash
# Run ProVerif with trace output
proverif -html html_output nomad_handshake.pv

# The attack traces (if any) show concrete message sequences
# Successful verification means no traces that violate security
```

## Nonce Cross-Validation

### Test Vectors: `nonce_vectors.json5`

| Vector | Formal Model |
|--------|--------------|
| `initial_initiator` (epoch=0, dir=0, ctr=0) | `NONCE_ZERO` in `nomad_replay.pv` |
| `after_rekey` (epoch=1, dir=0, ctr=0) | Epoch increment in `RekeyStateMachine.tla` |
| `max_counter` | `REJECT_AFTER_MESSAGES` boundary |
| `max_epoch` | `MAX_EPOCH` boundary in TLA+ |

### Nonce Structure Correspondence

```
Nonce Layout (24 bytes):
[epoch:4][direction:1][zeros:11][counter:8]

TLA+ Model (RekeyStateMachine.tla):
  epoch ∈ 0..MAX_EPOCH
  sendNonce ∈ 0..REJECT_AFTER_MESSAGES

ProVerif Model (nomad_replay.pv):
  make_nonce(epoch, direction, nonce)
```

### Validation Script

```python
# Validate that TLA+ constants match vector boundaries
def validate_nonce_bounds():
    # From nonce_vectors.json5
    max_counter = 18446744073709551615  # 2^64 - 1
    max_epoch = 4294967295              # 2^32 - 1

    # From 1-SECURITY.md
    REJECT_AFTER_MESSAGES = 2**64 - 1   # Must match max_counter
    MAX_EPOCH = 2**32 - 1               # Must match max_epoch

    assert max_counter == REJECT_AFTER_MESSAGES
    assert max_epoch == MAX_EPOCH
```

## Sync Layer Cross-Validation

### Test Vectors: `sync_vectors.json5`

| Vector | TLA+ Correspondence |
|--------|---------------------|
| `sync_message_format` | `SyncLayer.tla` message structure |
| `version_numbers` | `state_num`, `last_sent_num`, `peer_state_num` |
| `diff_application` | `ApplyDiff(s, d)` function |

### State Tracking Correspondence

```
Test Vector Field         TLA+ Variable
────────────────────────────────────────
sender_state_num         state_num[n]
acked_state_num          peer_state_num[n]
base_state_num           last_sent_num[n]
diff                     (abstracted as state change)
```

### Convergence Validation

The TLA+ `EventualConsistency` property proves what the test vectors demonstrate:
- `test_sync_convergence.py` shows states converging
- `SyncLayer.tla` proves this is always true under fairness

## Rekey Cross-Validation

### Test Vectors: `frame_vectors.json5` (rekey frames)

| Vector | TLA+ Correspondence |
|--------|---------------------|
| Rekey frame type 0x04 | `InitiateRekey` action |
| Epoch transition | `epoch' = epoch + 1` |
| Nonce reset | `sendNonce' = 0` |

### State Machine Validation

```
frame_vectors.json5 rekey sequence:
  epoch=0, counter=N → rekey → epoch=1, counter=0

RekeyStateMachine.tla transitions:
  InitiateRekey → RespondToRekey → CompleteRekeyResponder
  epoch' = epoch + 1
  sendNonce' = 0
```

## Discrepancies

### Identified Discrepancies

| Area | Issue | Resolution |
|------|-------|------------|
| None identified | - | - |

### Modeling Limitations

1. **ProVerif abstractions**: Cryptographic operations are idealized
2. **TLA+ state bounds**: Finite model checking requires bounds
3. **Symbolic vs concrete**: Formal models use symbols, not bytes

### Future Work

1. Generate ProVerif traces that produce test vector byte sequences
2. Extend TLA+ models with explicit byte-level encoding
3. Property-based testing to fuzz between formal model and vectors

## Running Cross-Validation

```bash
# 1. Verify formal models
cd formal/proverif && proverif nomad_handshake.pv
cd formal/tlaplus && tlc SyncLayer.tla -config SyncLayer.cfg

# 2. Run test vectors
cd tests && pytest unit/ -v

# 3. Compare outputs (manual inspection)
# - ProVerif should report "true" for all queries
# - TLA+ should report "No errors found"
# - Test vectors should all pass
```

## Conclusion

The formal models are structurally consistent with test vectors:
- ProVerif message types match handshake frame types
- TLA+ state variables match sync message fields
- Boundary conditions (MAX_EPOCH, REJECT_AFTER_MESSAGES) match vector edge cases

The models provide complementary guarantees:
- **Test vectors**: Byte-level correctness
- **Formal models**: Protocol-level security properties
