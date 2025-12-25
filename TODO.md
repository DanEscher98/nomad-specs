# Tentacle: t8-adversarial
## Security red team testing suite

**Scope:** tests/adversarial/*, tests/lib/attacker.py

---

## ⚠️ E2E Only - Docker Required

> This tentacle has **NO Phase 1 (unit tests)**.
> All tests require Docker containers with real implementations.
> Tests use `server_container`, `client_container`, `attacker`, and `packet_capture` fixtures.

**Prerequisites:**
- Docker with NET_RAW, NET_ADMIN capabilities
- scapy for packet manipulation
- Test keypairs configured in `tests/lib/containers.py`
- Use `container_manager.check_container_health()` to detect crashes

**Note:** Existing `tests/adversarial/test_replay_attack.py` and `test_key_compromise.py`
from t1-security are Phase 1 (reference codec only). This tentacle adds E2E versions
that attack real implementations.

---

## Tasks

### Infrastructure
- [x] Create `tests/lib/attacker.py` - MITM attack toolkit
  - [x] `MITMAttacker` class
  - [x] `capture_traffic() -> list[bytes]` - sniff UDP port 19999
  - [x] `replay_frame(frame: bytes)` - resend captured frame
  - [x] `inject_frame(frame: bytes)` - send forged frame
  - [x] `tamper_frame(frame, offset, byte)` - bit-flip attack
  - [x] `spoof_source(frame, new_ip)` - IP spoofing
- [x] Add scapy to pyproject.toml dependencies (already present)
- [x] Add `@pytest.fixture def attacker()` to conftest.py
- [x] Add `@pytest.mark.adversarial` marker

### Test Files (8 files - Full Red Team)
- [x] `tests/adversarial/test_replay_attacks.py`
  - [x] Replay same nonce - MUST be rejected (sliding window)
  - [x] Replay old nonce (below window) - MUST be rejected
  - [x] Replay with modified counter - AEAD fails
- [x] `tests/adversarial/test_tamper_detection.py`
  - [x] Flip bit in ciphertext - AEAD fails
  - [x] Flip bit in header (AAD) - AEAD fails
  - [x] Truncate frame - rejected
  - [x] Extend frame with garbage - AEAD fails
- [x] `tests/adversarial/test_mitm_injection.py`
  - [x] Inject forged frame (random tag) - dropped
  - [x] Inject frame with wrong session ID - dropped
  - [x] Inject valid-looking but unsigned frame - dropped
- [x] `tests/adversarial/test_amplification.py`
  - [x] Spoofed source IP - limited to 3x response
  - [x] Measure bytes sent vs received before validation
  - [x] Verify rate limiting on unvalidated addresses
- [x] `tests/adversarial/test_timing_analysis.py`
  - [x] Send keystrokes with known timing pattern
  - [x] Capture encrypted frames as attacker
  - [x] Measure inter-frame arrival times
  - [x] Calculate Pearson correlation with known timing
  - [x] **FAIL if correlation > 0.8** (per user requirement)
- [x] `tests/adversarial/test_session_hijack.py`
  - [x] Enumerate session IDs - not predictable
  - [x] Guess session ID - can't forge valid frame
  - [x] Brute force session ID space - computationally infeasible
- [x] `tests/adversarial/test_nonce_reuse.py`
  - [x] Force same nonce twice - MUST be impossible
  - [x] Verify monotonic counter increment
  - [x] Counter never wraps (terminates at limit)
- [x] `tests/adversarial/test_key_exhaustion.py`
  - [x] Send frame with nonce=2^64-1 - session terminates
  - [x] Verify no wrap to 0
  - [x] Epoch exhaustion (2^32-1) - session terminates

## Attack Implementation Details

### Scapy Usage
```python
from scapy.all import sniff, sendp, IP, UDP, Raw

def capture_nomad_frames(iface="eth0", count=10):
    return sniff(iface=iface, filter="udp port 19999", count=count)

def inject_frame(frame_bytes, dst_ip, dst_port=19999):
    pkt = IP(dst=dst_ip)/UDP(dport=dst_port)/Raw(load=frame_bytes)
    sendp(pkt, iface="eth0")
```

### Docker Network Position
- Attacker container on same bridge network (172.28.0.0/16)
- Can sniff all traffic (promiscuous mode)
- Can inject packets to any container
- For ARP spoofing: use `arpspoof` from dsniff package

## Dependencies
- scapy >= 2.5
- tests/lib/reference.py from t6 (for frame parsing)
- Docker network access (NET_RAW, NET_ADMIN capabilities)
- numpy/scipy for correlation analysis (timing tests)

## Success Criteria
- [x] All replay attacks rejected (sliding window)
- [x] All tampering detected (AEAD verification)
- [x] Packet injection fails (no valid tag)
- [x] Amplification limited to 3x (anti-DDoS)
- [x] Session hijack prevented (session ID not guessable)
- [x] Nonce reuse impossible (monotonic counter)
- [x] Session terminates at counter limits (2^64-1)
- [x] **Timing correlation < 0.8** (keystroke protection)

## Notes
- Silent drop on invalid frames (no oracle feedback)
- Constant-time comparison for all crypto operations
- All tests use @pytest.mark.adversarial marker
- Some tests may need root/NET_RAW capability

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
