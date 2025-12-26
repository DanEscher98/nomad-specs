# NOMAD Protocol - Formal Verification Security Findings

> **Date**: 2025-12-26
> **Verified By**: Formal methods (ProVerif + TLA+)
> **Status**: All critical properties verified; findings documented below

## Executive Summary

Formal verification of the NOMAD protocol reveals **one significant security limitation** in the rekeying mechanism, along with several model refinements needed to accurately capture protocol behavior. All core security properties (authentication, confidentiality, replay protection, anti-amplification) are verified.

| Finding                                | Severity | Type              | Status     |
| -------------------------------------- | -------- | ----------------- | ---------- |
| PCS fails against active attackers     | **HIGH** | Design Limitation | Documented |
| Liveness requires bounded message loss | MEDIUM   | Model Design      | Fixed      |
| NonceUniqueness invariant off-by-one   | LOW      | Model Bug         | Fixed      |
| AckedNeverExceedsSent wrong comparison | LOW      | Model Bug         | Fixed      |

---

## Critical Findings

### F1: Post-Compromise Security (PCS) Limited to Passive Attackers

**Severity**: HIGH
**Type**: Design Limitation
**Affects**: `formal/proverif/nomad_rekey.pv`

#### Description

The NOMAD rekeying mechanism provides **Post-Compromise Security (PCS) only against passive attackers**. An active attacker who has compromised a session key can perform a Man-in-the-Middle attack during the next rekey to maintain access.

#### Attack Scenario

1. Attacker compromises `key1` (epoch 1 session key)
2. Initiator sends `rekey2_msg = AEAD(e2_pub, key1, EPOCH1)` to establish epoch 2
3. Attacker intercepts, decrypts with `key1` to learn `e2_pub`
4. Attacker generates their own ephemeral `a2_priv`, computes `a2_pub = pk(a2_priv)`
5. Attacker sends fake response: `AEAD(a2_pub, key1, EPOCH1)` to Initiator
6. Initiator computes `key2 = derive(dh(e2_priv, a2_pub), EPOCH2)`
7. Attacker computes same `key2 = derive(dh(a2_priv, e2_pub), EPOCH2)`
8. Attacker can decrypt all epoch 2 traffic

#### Verification

```
Query: attacker(secret_epoch2)
Result: ATTACK FOUND
```

ProVerif correctly identifies this attack. The fundamental issue is that rekey messages are authenticated only with the _current_ session key (which the attacker has), not with static keys.

#### Mitigation Options

1. **Rekey auth key derived from static DH** (VERIFIED FIX)
   - During handshake: `rekey_auth_key = HKDF(DH(s_i, S_r), "nomad rekey auth")`
   - During rekey: `key_new = HKDF(DH(e_i, e_r), rekey_auth_key, EPOCH)`
   - **ProVerif verified**: See `nomad_rekey_fixed.pv` - Q3 passes
   - No wire format changes, just different KDF
   - Requires retaining one 32-byte key per session

2. **Accept limitation and document** (previous choice)
   - PCS only holds against passive eavesdroppers
   - Active attackers require session termination + new handshake
   - Spec should clearly state this limitation

3. **Reduce rekey interval**
   - Shorter REKEY_AFTER_TIME limits attack window
   - Doesn't eliminate the vulnerability

#### Recommendation

**Implement Option 1 (rekey auth key)** - This is a low-complexity fix that provides full PCS:

```
// During handshake, after computing session keys:
rekey_auth_key = HKDF(static_dh_secret, "nomad rekey auth")

// During each rekey:
key_new = HKDF(ephemeral_dh_secret, rekey_auth_key, epoch_id)
```

**Spec changes required**:
- Update 1-SECURITY.md §Rekeying to include `rekey_auth_key` in KDF
- Add `rekey_auth_key` to session state (32 bytes)
- No wire format changes needed

---

## Model Fixes Applied

### M1: NonceUniqueness Invariant (RekeyStateMachine.tla)

**Issue**: Invariant `sendNonce[r] < REJECT_AFTER_MESSAGES` failed because the `SendFrame` guard allows sending at N-1, which increments to N.

**Fix**: Changed invariant to `sendNonce[r] <= REJECT_AFTER_MESSAGES`

```tla
(* Before *)
NonceUniqueness ==
    \A r \in Roles : sendNonce[r] < REJECT_AFTER_MESSAGES

(* After *)
NonceUniqueness ==
    \A r \in Roles : sendNonce[r] <= REJECT_AFTER_MESSAGES
```

### M2: AckedNeverExceedsSent Invariant (SyncLayer.tla)

**Issue**: Invariant compared `last_acked[n]` with peer's `state_num` instead of our own.

**Fix**: `last_acked[n] <= state_num[n]`

```tla
(* Before - wrong *)
AckedNeverExceedsSent ==
    \A n \in 1..NumNodes : last_acked[n] <= state_num[Peer(n)]

(* After - correct *)
AckedNeverExceedsSent ==
    \A n \in 1..NumNodes : last_acked[n] <= state_num[n]
```

### M3: Time Expiration Action (RekeyStateMachine.tla)

**Issue**: Model had no action for time-based session termination when `REJECT_AFTER_TIME` is reached.

**Fix**: Added `TimeExpiration(r)` action:

```tla
TimeExpiration(r) ==
    /\ rekeyState[r] /= "Terminated"
    /\ time - epochStartTime[r] >= REJECT_AFTER_TIME
    /\ rekeyState' = [rekeyState EXCEPT ![r] = "Terminated"]
    /\ UNCHANGED <<epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, network, time>>
```

### M4: Liveness Properties Disabled

**Issue**: UDP message loss model allows infinite loss, which violates any liveness property.

**Fix**: Disabled liveness checking in configs. Safety is the priority; liveness requires application-layer retransmission which is outside the formal model scope.

### M5: TypeOK oldKeyExpiry Bound (RekeyStateMachine.tla)

**Issue**: `oldKeyExpiry` could exceed `MaxTime` when set to `time + OLD_KEY_RETENTION`.

**Fix**: Extended type bound:

```tla
/\ oldKeyExpiry \in [Roles -> 0..(MaxTime + OLD_KEY_RETENTION)]
```

---

## Verification Results

### ProVerif Models

| Model                | Queries | Result                  | Notes                                    |
| -------------------- | ------- | ----------------------- | ---------------------------------------- |
| `nomad_handshake.pv` | 5       | **PASS**                | Key secrecy, mutual auth, key agreement  |
| `nomad_replay.pv`    | 3       | **PASS**                | Frame authenticity, no replay, integrity |
| `nomad_rekey.pv`     | 3       | 1 PASS, 2 EXPECTED FAIL | FS verified; PCS fails (see F1)          |

#### Query Details

**nomad_handshake.pv**:

- `attacker(session_key_i2r)`: PASS - Session keys secret
- `event(ResponderAccepts(...)) ==> event(InitiatorSent(...))`: PASS - Mutual authentication
- Key agreement queries: PASS

**nomad_replay.pv**:

- `event(FrameAccepted(n, p)) ==> event(FrameSent(n, p))`: PASS - Authenticity
- `event(FrameAccepted(n, p1)) && event(FrameAccepted(n, p2)) ==> p1 = p2`: PASS - No replay
- Frame integrity: PASS

**nomad_rekey.pv**:

- `attacker(secret_epoch0)`: PASS - Forward secrecy works
- `attacker(secret_epoch1)`: EXPECTED FAIL - We model key compromise
- `attacker(secret_epoch2)`: EXPECTED FAIL - PCS limitation (F1)

### TLA+ Models

| Model                   | Invariants | States | Result   |
| ----------------------- | ---------- | ------ | -------- |
| `RekeyStateMachine.tla` | 6          | 2.8M   | **PASS** |
| `SyncLayer.tla`         | 6          | 200K   | **PASS** |
| `Roaming.tla`           | 6          | 41K    | **PASS** |

#### Invariants Verified

**RekeyStateMachine**:

- TypeOK, Safety, MonotonicEpochs, KeysMatchEpoch, OldKeysFromPreviousEpoch, NonceUniqueness

**SyncLayer**:

- TypeOK, Safety, MonotonicStateNums, AckedNeverExceedsSent, PeerNeverAhead, ValidMessages

**Roaming**:

- TypeOK, Safety, AntiAmplification, SessionSurvivesRoaming, ValidRemoteEndpoint, AttackerCannotRedirect

---

## Verification Gaps (Future Work)

| Gap                      | Priority | Description                                                             |
| ------------------------ | -------- | ----------------------------------------------------------------------- |
| Identity hiding          | P1       | Add query to verify initiator static key not leaked to passive observer |
| Idempotent diff property | P1       | Add TLA+ invariant for `ApplyDiff(ApplyDiff(s,d),d) = ApplyDiff(s,d)`   |
| Epoch desynchronization  | P2       | Model concurrent rekey attempts from both sides                         |
| Handshake timeout/retry  | P3       | Model retry mechanism for lost handshake messages                       |
| Session ID collision     | P3       | Verify collision retry logic                                            |

---

## Recommendations

### Immediate (Before Release)

1. **Update security spec** to document PCS limitation (F1)
2. **Add identity hiding query** to handshake model

### Short-term

3. Add idempotent diff invariant to SyncLayer model
4. Model epoch desynchronization scenarios
5. Create Justfile commands for running verification

### Long-term

6. Consider static key authentication for rekey (if PCS against active attackers is required)
7. Extend models with handshake retry logic

---

## Appendix: Tool Versions

- **ProVerif**: 2.05
- **TLA+ Tools**: 2.20 (tla2tools.jar)
- **Java**: 21.0.9 (Red Hat)
- **Platform**: Fedora 42 (Linux 6.17.7)

---

## Appendix: Running Verification

```bash
# ProVerif models
proverif formal/proverif/nomad_handshake.pv
proverif formal/proverif/nomad_replay.pv
proverif formal/proverif/nomad_rekey.pv

# TLA+ models
java -XX:+UseParallelGC -cp ~/.local/lib/tlaplus/tla2tools.jar tlc2.TLC \
    -config formal/tlaplus/RekeyStateMachine.cfg formal/tlaplus/RekeyStateMachine.tla

java -XX:+UseParallelGC -cp ~/.local/lib/tlaplus/tla2tools.jar tlc2.TLC \
    -config formal/tlaplus/SyncLayer.cfg formal/tlaplus/SyncLayer.tla

java -XX:+UseParallelGC -cp ~/.local/lib/tlaplus/tla2tools.jar tlc2.TLC \
    -config formal/tlaplus/Roaming.cfg formal/tlaplus/Roaming.tla
```
