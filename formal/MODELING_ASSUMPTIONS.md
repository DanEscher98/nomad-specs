# Formal Model Assumptions and Bounds

This document describes the assumptions, simplifications, and bounds used in the NOMAD formal verification models. Understanding these is critical for correctly interpreting verification results.

## ProVerif Assumptions

### Adversary Model (Dolev-Yao)

ProVerif uses the Dolev-Yao symbolic model where:

**Attacker Capabilities:**
- Full network control: intercept, modify, delay, replay, inject messages
- Can compute any function on known values
- Can store and correlate all observed traffic

**Attacker Limitations:**
- Cannot break cryptographic primitives (AEAD, DH, hash)
- Cannot guess random values (nonces, keys)
- Cannot invert one-way functions

### Cryptographic Idealization

| Real Primitive | ProVerif Model | Implication |
|----------------|----------------|-------------|
| XChaCha20-Poly1305 | `aead_enc(m, k, n)` | Perfect confidentiality and integrity |
| X25519 DH | `dh(priv, pub)` | No side channels, computational security |
| BLAKE2s | `hash(x)` | Perfect collision resistance |
| HKDF | `kdf(secret, info)` | Perfect key derivation |

**Implication**: Verification proves protocol-level security, not implementation security.

### Message Ordering

ProVerif explores all possible message orderings, including:
- Messages arriving out of order
- Messages being delayed indefinitely
- Messages being replayed multiple times

This is stronger than typical network behavior but catches edge cases.

### Session Modeling

Each ProVerif process models one session. The tool automatically considers:
- Unbounded concurrent sessions
- Session confusion attacks
- Cross-session key reuse vulnerabilities

## TLA+ Assumptions

### Model Bounds

TLA+ model checking requires finite state spaces. The bounds are chosen to be:
1. **Small enough** for tractable verification (completing in minutes)
2. **Large enough** to exercise all edge cases and invariants

| Model | Constant | Model Value | Spec Value | Rationale |
|-------|----------|-------------|------------|-----------|
| **RekeyStateMachine** | | | | |
| | REKEY_AFTER_TIME | 2 | 300s | Triggers rekey at t=2 |
| | REJECT_AFTER_TIME | 3 | 360s | Grace period = 1 tick |
| | OLD_KEY_RETENTION | 1 | max(5×SRTT, 30s) | Tests key overlap |
| | MAX_EPOCH | 2 | 2^32-1 | Tests epoch exhaustion |
| | REKEY_AFTER_MESSAGES | 5 | 2^32 | Triggers message-based rekey |
| | REJECT_AFTER_MESSAGES | 8 | 2^64-1 | Tests counter exhaustion |
| | MaxTime | 10 | ∞ | Bounds exploration |
| **SyncLayer** | | | | |
| | MaxStateNum | 2 | 2^64-1 | Tests counter overflow |
| | MaxDiffValue | 1 | application | Minimal diff size |
| | NumNodes | 2 | 2 | Client-server |
| **SlidingWindow** | | | | |
| | WindowSize | 3 | 2048 | Tests window mechanics |
| | MaxNonce | 5 | 2^64-1 | Bounds state space |
| | MaxFrames | 6 | ∞ | Limits exploration |

### Scale Independence

The safety properties verified are **scale-independent**:
- `MonotonicEpochs`: epochs increase regardless of MAX_EPOCH value
- `KeysMatchEpoch`: key-epoch binding is algebraic, not size-dependent
- `OnlyAuthenticatedMarkedSeen`: ordering invariant doesn't depend on window size

Liveness properties (eventual consistency, eventual rekey) are more sensitive to bounds but are disabled due to unreliable network modeling.

### Fairness Assumptions

**Weak Fairness (WF)** is assumed for certain actions:
- `WF_vars(Tick)`: Time eventually advances
- `WF_vars(ReceiveSync)`: Messages eventually delivered
- `WF_vars(SendSync)`: Pending state eventually sent

**What this means**: If an action is continuously enabled, it eventually happens.

**What this does NOT mean**: We do NOT assume strong fairness (SF). Actions that are only intermittently enabled may never happen.

### Message Loss Modeling

All TLA+ models include a `LoseMessage` action that can non-deterministically drop any in-flight message. This means:
- Liveness properties require fairness constraints
- Safety properties hold under arbitrary message loss
- The model is more adversarial than typical networks

## Simplifications

### ProVerif Simplifications

1. **Single epoch per process**: ProVerif processes model one epoch transition, not unbounded rekeying. Multiple rekeys are modeled by running verification multiple times.

2. **Abstracted timestamps**: Timestamps are modeled as symbolic values, not concrete time. Timing attacks are not captured.

3. **No state compression**: Each message includes full state, not diffs. This is conservative (more information leakage).

### TLA+ Simplifications

1. **Discrete time**: Time advances in integer ticks, not continuous. Real-time constraints are abstracted.

2. **Atomic actions**: Each TLA+ action is atomic. Race conditions within an action are not modeled.

3. **No packet fragmentation**: Messages are delivered atomically or not at all.

4. **LWW diff semantics**: The SyncLayer uses Last-Writer-Wins semantics where `ApplyDiff(s, d) = d`. This ensures idempotence but abstracts away more complex CRDT operations.

## Verification Scope

### What IS Verified

| Property | Model | Result |
|----------|-------|--------|
| Key secrecy | ProVerif handshake | ✓ |
| Authentication | ProVerif handshake | ✓ |
| Forward secrecy | ProVerif rekey | ✓ |
| Post-compromise security | ProVerif rekey | ✓ |
| Replay protection | ProVerif replay | ✓ |
| Window ordering | ProVerif replay + TLA+ sliding window | ✓ |
| Monotonic epochs | TLA+ rekey | ✓ |
| Counter exhaustion | TLA+ rekey | ✓ |
| State convergence | TLA+ sync (with fairness) | ✓ |
| Diff idempotence | TLA+ sync | ✓ |
| Anti-amplification | TLA+ roaming | ✓ |

### What is NOT Verified

1. **Implementation bugs**: Formal models abstract away code. Buffer overflows, timing attacks, etc. are not captured.

2. **Cryptographic strength**: We assume primitives are secure. Weak keys or implementation flaws are not modeled.

3. **Denial of service**: Resource exhaustion attacks are generally not modeled (except anti-amplification in roaming).

4. **Side channels**: Timing, power, cache attacks are not in scope.

5. **Concurrent implementation**: TLA+ assumes sequential consistency. Memory ordering issues in real implementations are not modeled.

## Interpreting Results

### "RESULT ... is true"

ProVerif has proven the property holds for:
- All possible message interleavings
- Unbounded concurrent sessions
- A Dolev-Yao attacker

This is a **sound** result: if it says true, the property holds (under assumptions).

### "Query ... cannot be proved"

ProVerif found a potential attack trace. This could be:
1. A real vulnerability
2. A false positive due to over-approximation
3. An expected failure (e.g., we leak keys intentionally to test compromise scenarios)

Always examine the attack trace to determine which case applies.

### "No error has been found"

TLC has exhaustively checked all reachable states within the bounds. The invariants hold for:
- All explored states
- All action orderings
- All non-deterministic choices

This does NOT guarantee correctness for larger bounds, but safety properties that are scale-independent should hold.

### State Count Implications

| States Explored | Implication |
|-----------------|-------------|
| < 10,000 | Quick verification, possibly too constrained |
| 10,000 - 1,000,000 | Reasonable exploration |
| > 1,000,000 | Thorough verification, may take minutes |
| Timeout | Bounds too large, reduce constants |

## References

- [ProVerif Manual](https://proverif.inria.fr/manual.pdf) - Sections 1-3 on adversary model
- [TLA+ Hyperbook](https://lamport.azurewebsites.net/tla/hyperbook.html) - Chapter on model checking
- [Dolev-Yao Model](https://en.wikipedia.org/wiki/Dolev%E2%80%93Yao_model) - Background on symbolic adversary
