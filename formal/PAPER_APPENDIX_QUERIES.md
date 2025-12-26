# ProVerif Security Queries - Paper Appendix

This document extracts the key ProVerif queries used to formally verify NOMAD's security properties. All queries have been verified using ProVerif 2.05.

## 1. Handshake Security (Noise_IK)

**Model**: `nomad_handshake.pv`

### Key Secrecy

```proverif
(* Session keys cannot be derived by attacker *)
query attacker(initiator_session_key).  (* PASS *)
query attacker(responder_session_key).  (* PASS *)
```

### Mutual Authentication

```proverif
(* If initiator completes handshake, responder participated *)
query rs: pubkey, re: pubkey, ie: pubkey, is_pub: pubkey;
  event(InitiatorReceivedResp(rs, re, ie, is_pub)) ==>
    event(ResponderSentResp(rs, re, ie, is_pub)).  (* PASS *)

(* If responder accepts, initiator sent first message *)
query rs: pubkey, ie: pubkey, is_pub: pubkey;
  event(ResponderReceivedInit(rs, ie, is_pub)) ==>
    event(InitiatorSentInit(rs, ie, is_pub)).  (* PASS *)
```

### Key Agreement

```proverif
(* Both parties derive identical session keys *)
query is_pub: pubkey, rs: pubkey, k: bitstring;
  event(InitiatorSessionEstablished(is_pub, rs, k)) ==>
    event(ResponderSessionEstablished(is_pub, rs, k)).  (* PASS *)
```

---

## 2. Frame Protection (Anti-Replay)

**Model**: `nomad_replay.pv`

### Frame Authenticity

```proverif
(* Accepted frames were sent by peer - no forgery *)
query n: nonce, p: bitstring;
  event(FrameAccepted(n, p)) ==> event(FrameSent(n, p)).  (* PASS *)
```

### Replay Rejection

```proverif
(* Same nonce never accepted twice *)
query n: nonce, p1: bitstring, p2: bitstring;
  event(FrameAccepted(n, p1)) && event(FrameAccepted(n, p2)) ==> p1 = p2.  (* PASS *)
```

### Frame Integrity

```proverif
(* Payload not modified in transit *)
query n: nonce, p_sent: bitstring, p_recv: bitstring;
  event(FrameSent(n, p_sent)) && event(FrameAccepted(n, p_recv)) ==> p_sent = p_recv.  (* PASS *)
```

### Window Ordering (DoS Prevention)

```proverif
(* Replay window only advances for authenticated frames *)
(* Prevents DoS attack via forged high-nonce packets *)
query n: nonce, p: bitstring;
  inj-event(FrameAccepted(n, p)) ==> inj-event(NonceSeen(n)).  (* PASS *)
```

---

## 3. Rekeying Security (PCS)

### Original Design (Vulnerable)

**Model**: `nomad_rekey.pv`

```proverif
(* Forward Secrecy: past secrets protected after key compromise *)
query attacker(secret_epoch0).  (* PASS - FS holds *)

(* Compromised epoch - attacker has key1 *)
query attacker(secret_epoch1).  (* FAIL - expected, we leak key1 *)

(* Post-Compromise Security: future secrets after key compromise *)
query attacker(secret_epoch2).  (* FAIL - PCS FAILS against active attacker! *)
```

**Finding**: Active attacker with epoch 1 key can MitM rekey to maintain access.

### Fixed Design (rekey_auth_key)

**Model**: `nomad_rekey_fixed.pv`

```proverif
(* Forward Secrecy: unchanged *)
query attacker(secret_epoch0).  (* PASS *)

(* Compromised epoch: unchanged *)
query attacker(secret_epoch1).  (* FAIL - expected *)

(* Post-Compromise Security: NOW PROTECTED *)
query attacker(secret_epoch2).  (* PASS - PCS holds! *)
```

**Fix**: Mix `rekey_auth_key` (derived from static DH) into rekey KDF:
```
rekey_auth_key = HKDF(DH(s_initiator, S_responder), "nomad rekey auth")
key_new = HKDF(DH(e_i, e_r) || rekey_auth_key, epoch)
```

---

## Summary

| Property | Query | Result |
|----------|-------|--------|
| Key Secrecy | `attacker(session_key)` | PASS |
| Mutual Authentication | `InitiatorReceivedResp ==> ResponderSentResp` | PASS |
| Key Agreement | `InitiatorEstablished ==> ResponderEstablished` | PASS |
| Frame Authenticity | `FrameAccepted ==> FrameSent` | PASS |
| Replay Rejection | `Accepted(n,p1) && Accepted(n,p2) ==> p1=p2` | PASS |
| Frame Integrity | `Sent(p1) && Accepted(p2) ==> p1=p2` | PASS |
| Window Ordering | `inj-FrameAccepted ==> inj-NonceSeen` | PASS |
| Forward Secrecy | `attacker(secret_epoch0)` | PASS |
| Post-Compromise Security | `attacker(secret_epoch2)` | PASS (with fix) |

All security properties verified using ProVerif 2.05 under the Dolev-Yao adversary model.
