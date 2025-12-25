# Tentacle: t8-adversarial
## Security red team testing suite

**Scope:** tests/adversarial/*, tests/lib/attacker.py

## Tasks

### Infrastructure
- [ ] Create `tests/lib/attacker.py` - MITM attack toolkit
  - [ ] `MITMAttacker` class
  - [ ] `capture_traffic() -> list[bytes]` - sniff UDP port 19999
  - [ ] `replay_frame(frame: bytes)` - resend captured frame
  - [ ] `inject_frame(frame: bytes)` - send forged frame
  - [ ] `tamper_frame(frame, offset, byte)` - bit-flip attack
  - [ ] `spoof_source(frame, new_ip)` - IP spoofing
- [ ] Add scapy to pyproject.toml dependencies
- [ ] Add `@pytest.fixture def attacker()` to conftest.py
- [ ] Add `@pytest.mark.adversarial` marker

### Test Files (8 files - Full Red Team)
- [ ] `tests/adversarial/test_replay_attacks.py`
  - [ ] Replay same nonce - MUST be rejected (sliding window)
  - [ ] Replay old nonce (below window) - MUST be rejected
  - [ ] Replay with modified counter - AEAD fails
- [ ] `tests/adversarial/test_tamper_detection.py`
  - [ ] Flip bit in ciphertext - AEAD fails
  - [ ] Flip bit in header (AAD) - AEAD fails
  - [ ] Truncate frame - rejected
  - [ ] Extend frame with garbage - AEAD fails
- [ ] `tests/adversarial/test_mitm_injection.py`
  - [ ] Inject forged frame (random tag) - dropped
  - [ ] Inject frame with wrong session ID - dropped
  - [ ] Inject valid-looking but unsigned frame - dropped
- [ ] `tests/adversarial/test_amplification.py`
  - [ ] Spoofed source IP - limited to 3x response
  - [ ] Measure bytes sent vs received before validation
  - [ ] Verify rate limiting on unvalidated addresses
- [ ] `tests/adversarial/test_timing_analysis.py`
  - [ ] Send keystrokes with known timing pattern
  - [ ] Capture encrypted frames as attacker
  - [ ] Measure inter-frame arrival times
  - [ ] Calculate Pearson correlation with known timing
  - [ ] **FAIL if correlation > 0.8** (per user requirement)
- [ ] `tests/adversarial/test_session_hijack.py`
  - [ ] Enumerate session IDs - not predictable
  - [ ] Guess session ID - can't forge valid frame
  - [ ] Brute force session ID space - computationally infeasible
- [ ] `tests/adversarial/test_nonce_reuse.py`
  - [ ] Force same nonce twice - MUST be impossible
  - [ ] Verify monotonic counter increment
  - [ ] Counter never wraps (terminates at limit)
- [ ] `tests/adversarial/test_key_exhaustion.py`
  - [ ] Send frame with nonce=2^64-1 - session terminates
  - [ ] Verify no wrap to 0
  - [ ] Epoch exhaustion (2^32-1) - session terminates

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
- [ ] All replay attacks rejected (sliding window)
- [ ] All tampering detected (AEAD verification)
- [ ] Packet injection fails (no valid tag)
- [ ] Amplification limited to 3x (anti-DDoS)
- [ ] Session hijack prevented (session ID not guessable)
- [ ] Nonce reuse impossible (monotonic counter)
- [ ] Session terminates at counter limits (2^64-1)
- [ ] **Timing correlation < 0.8** (keystroke protection)

## Notes
- Silent drop on invalid frames (no oracle feedback)
- Constant-time comparison for all crypto operations
- All tests use @pytest.mark.adversarial marker
- Some tests may need root/NET_RAW capability

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Brain: feature/epic-conformance-suite*
