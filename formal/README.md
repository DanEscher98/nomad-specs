# NOMAD Protocol Formal Verification

This directory contains formal models for verifying security and correctness properties of the NOMAD protocol using ProVerif (cryptographic properties) and TLA+ (state machine correctness).

> **Security Findings**: See [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) for verification results and discovered vulnerabilities.
>
> **Modeling Assumptions**: See [MODELING_ASSUMPTIONS.md](MODELING_ASSUMPTIONS.md) for bounds, simplifications, and interpretation guidance.

## Directory Structure

```
formal/
├── README.md                    # This file
├── SECURITY_FINDINGS.md         # Vulnerabilities found and fixes
├── MODELING_ASSUMPTIONS.md      # Bounds, simplifications, interpretation
├── CROSS_VALIDATION.md          # Correspondence with test vectors
├── PAPER_APPENDIX_QUERIES.md    # Key queries for paper appendix
│
├── proverif/                    # Cryptographic protocol verification
│   ├── nomad_handshake.pv       # Noise_IK handshake security
│   ├── nomad_rekey.pv           # Forward secrecy & PCS (original)
│   ├── nomad_rekey_fixed.pv     # Forward secrecy & PCS (with fix)
│   └── nomad_replay.pv          # Anti-replay & frame integrity
│
└── tlaplus/                     # State machine verification
    ├── SyncLayer.tla/.cfg       # State convergence algorithm
    ├── RekeyStateMachine.tla/.cfg # Epoch management & key rotation
    ├── SlidingWindow.tla/.cfg   # Anti-replay window algorithm
    └── Roaming.tla/.cfg         # Connection migration
```

## What Is Verified

### Algorithms Verified

| Algorithm | Model | Spec Reference |
|-----------|-------|----------------|
| **Noise_IK Handshake** | `nomad_handshake.pv` | 1-SECURITY.md §Handshake |
| **Session Rekeying** | `nomad_rekey.pv` + `RekeyStateMachine.tla` | 1-SECURITY.md §Rekeying |
| **Anti-Replay Sliding Window** | `nomad_replay.pv` + `SlidingWindow.tla` | 1-SECURITY.md §Anti-Replay |
| **State Synchronization** | `SyncLayer.tla` | 3-SYNC.md §Convergence |
| **Connection Roaming** | `Roaming.tla` | 2-TRANSPORT.md §Roaming |

### Security Properties Verified

| Property | Model | Result | Description |
|----------|-------|--------|-------------|
| **Key Secrecy** | `nomad_handshake.pv` | ✓ | Attacker cannot learn session keys |
| **Mutual Authentication** | `nomad_handshake.pv` | ✓ | Both parties verified |
| **Forward Secrecy** | `nomad_rekey.pv` | ✓ | Past sessions safe after key compromise |
| **Post-Compromise Security** | `nomad_rekey_fixed.pv` | ✓ | Future sessions safe after recovery |
| **Frame Integrity** | `nomad_replay.pv` | ✓ | Frames authenticated, unmodified |
| **Replay Protection** | `nomad_replay.pv` | ✓ | Duplicate nonces rejected |
| **Window Ordering** | `SlidingWindow.tla` | ✓ | Window advances only after AEAD |
| **DoS Resistance** | `SlidingWindow.tla` | ✓ | Forged packets can't advance window |
| **Anti-Amplification** | `Roaming.tla` | ✓ | 3x limit on unvalidated addresses |

### Correctness Properties Verified

| Property | Model | Result | Description |
|----------|-------|--------|-------------|
| **Monotonic Epochs** | `RekeyStateMachine.tla` | ✓ | Epochs only increase |
| **Keys Match Epoch** | `RekeyStateMachine.tla` | ✓ | Correct key for each epoch |
| **Nonce Uniqueness** | `RekeyStateMachine.tla` | ✓ | No nonce reuse within epoch |
| **Counter Exhaustion** | `RekeyStateMachine.tla` | ✓ | Session terminates at 2^64-1 |
| **State Convergence** | `SyncLayer.tla` | ✓ | States converge under fairness |
| **Diff Idempotence** | `SyncLayer.tla` | ✓ | Applying diff twice = applying once |
| **Version Monotonicity** | `SyncLayer.tla` | ✓ | State numbers only increase |

## Quick Start

```bash
# Install tools (one-time setup)
just formal-install

# Run all formal verification
just formal-all

# Or run separately
just formal-proverif  # Cryptographic properties (~30s)
just formal-tlaplus   # State machine correctness (~5min)
```

## ProVerif Models

ProVerif verifies cryptographic protocol security in the **Dolev-Yao symbolic model** where the attacker controls the network but cannot break cryptographic primitives.

### Models

| File | Algorithm | Properties |
|------|-----------|------------|
| `nomad_handshake.pv` | Noise_IK handshake | Key secrecy, authentication, identity hiding |
| `nomad_rekey.pv` | Session rekeying | Forward secrecy, key independence |
| `nomad_rekey_fixed.pv` | Rekeying with PCS fix | Post-compromise security via `rekey_auth_key` |
| `nomad_replay.pv` | Frame protection | Replay rejection, nonce uniqueness, integrity |

### Running

```bash
# Individual models
proverif formal/proverif/nomad_handshake.pv
proverif formal/proverif/nomad_replay.pv
proverif formal/proverif/nomad_rekey_fixed.pv

# Via justfile
just formal-proverif-handshake
just formal-proverif-replay
just formal-proverif-rekey
```

### Example Output

```
$ proverif formal/proverif/nomad_replay.pv
...
--------------------------------------------------------------
Verification summary:

Query event(FrameAccepted(n,p)) ==> event(FrameSent(n,p)) is true.
Query event(FrameAccepted(n,p1)) && event(FrameAccepted(n,p2)) ==> p1 = p2 is true.
Query event(FrameSent(n,p_sent)) && event(FrameAccepted(n,p_recv)) ==> p_sent = p_recv is true.
Query inj-event(FrameAccepted(n,p)) ==> inj-event(NonceSeen(n)) is true.
--------------------------------------------------------------
```

### Detailed Properties

#### Handshake (`nomad_handshake.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Key secrecy | Attacker cannot learn initiator's session key |
| Q2 | Key secrecy | Attacker cannot learn responder's session key |
| Q3 | Authentication | Initiator completes ⟹ Responder participated |
| Q4 | Authentication | Responder accepts ⟹ Initiator started |
| Q5 | Key agreement | Both parties derive identical session keys |

#### Rekeying (`nomad_rekey_fixed.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Forward secrecy | Epoch 0 secrets safe after epoch 1 compromise |
| Q2 | Key independence | Epoch 1 secrets independent of epoch 0 |
| Q3 | Post-compromise | New keys secure even after session key leak |

#### Replay Protection (`nomad_replay.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Frame integrity | Accepted frames were authentically sent |
| Q2 | No replay | Same nonce never accepted twice |
| Q3 | Payload integrity | Payload not modified in transit |
| Q4 | Window ordering | Window advances only for authenticated frames |

## TLA+ Specifications

TLA+ verifies **state machine correctness** through exhaustive model checking of all reachable states.

### Models

| File | Algorithm | Properties |
|------|-----------|------------|
| `SyncLayer.tla` | State sync convergence | Idempotent diffs, eventual consistency |
| `RekeyStateMachine.tla` | Epoch management | Key rotation, counter limits |
| `SlidingWindow.tla` | Anti-replay window | DoS resistance, ordering invariants |
| `Roaming.tla` | Connection migration | Anti-amplification, session survival |

### Running

```bash
# Individual models
just formal-tlaplus-sync      # ~20s, 200K states
just formal-tlaplus-rekey     # ~2min, 2.8M states
just formal-tlaplus-window    # ~1min, 1.4M states
just formal-tlaplus-roaming   # ~30s

# All TLA+ models
just formal-tlaplus
```

### Example Output

```
$ just formal-tlaplus-sync
...
Model checking completed. No error has been found.
  Distinct states found: 199,951 states.
The depth of the complete state graph search is 27.
Finished in 19s
```

### Detailed Properties

#### Sync Layer (`SyncLayer.tla`) - Convergence Algorithm

| Property | Type | Description |
|----------|------|-------------|
| MonotonicStateNums | Safety | State version numbers only increase |
| AckedNeverExceedsSent | Safety | Acks bounded by sent versions |
| DiffsAreIdempotent | Safety | `ApplyDiff(ApplyDiff(s,d),d) = ApplyDiff(s,d)` |
| EventualConsistency | Liveness | States converge when messages delivered |

**Algorithm**: Last-Writer-Wins (LWW) with versioned state tracking. Each node maintains `state_num`, `last_sent_num`, `peer_state_num`. Convergence proof sketch included in model.

#### Rekey State Machine (`RekeyStateMachine.tla`) - Key Rotation

| Property | Type | Description |
|----------|------|-------------|
| MonotonicEpochs | Safety | Epoch numbers never decrease |
| KeysMatchEpoch | Safety | `currentKeys[r] = epoch[r]` always |
| OldKeysFromPreviousEpoch | Safety | Retained keys are from epoch-1 |
| NonceUniqueness | Safety | Nonces bounded by REJECT_AFTER_MESSAGES |

**Algorithm**: Time-based (300s) and message-based (2^32) rekey triggers. Epoch increment, nonce reset, old key retention for late packets.

#### Sliding Window (`SlidingWindow.tla`) - Anti-Replay Algorithm

| Property | Type | Description |
|----------|------|-------------|
| OnlyAuthenticatedMarkedSeen | Security | Only AEAD-verified nonces enter window |
| WindowBounded | Safety | `|seen_bitmap| ≤ WindowSize` |
| FloorEnforced | Safety | Nonces below floor always rejected |
| AttackerCannotAdvanceWindow | Security | Forged high-nonce packets don't cause DoS |

**Algorithm**: 3-phase receive: (1) Check if definite replay (read-only), (2) AEAD verification, (3) Mark seen and advance window. Critical ordering prevents DoS where attacker advances window with forged packets.

#### Roaming (`Roaming.tla`) - Connection Migration

| Property | Type | Description |
|----------|------|-------------|
| AntiAmplification | Safety | ≤3x data to unvalidated addresses |
| SessionSurvivesRoaming | Safety | Session active during IP change |
| AttackerCannotRedirect | Security | Spoofed frames can't hijack session |
| CommunicationResumes | Liveness | Connection recovers after roaming |

**Algorithm**: Address validation via authenticated frames. Unvalidated addresses get limited response data until validation completes.

## Correspondence to Specifications

| Spec Section | ProVerif | TLA+ |
|--------------|----------|------|
| 1-SECURITY.md §Handshake | `nomad_handshake.pv` | - |
| 1-SECURITY.md §Rekeying | `nomad_rekey_fixed.pv` | `RekeyStateMachine.tla` |
| 1-SECURITY.md §Anti-Replay | `nomad_replay.pv` | `SlidingWindow.tla` |
| 2-TRANSPORT.md §Roaming | - | `Roaming.tla` |
| 3-SYNC.md §Convergence | - | `SyncLayer.tla` |

## Installation

### ProVerif

```bash
# Fedora/RHEL
sudo dnf install ocaml ocaml-findlib
cd /tmp && curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05 && ./build
sudo cp proverif /usr/local/bin/

# Ubuntu/Debian
sudo apt install proverif

# macOS
brew install proverif
```

### TLA+

```bash
# Install Java
sudo dnf install java-21-openjdk  # Fedora
sudo apt install openjdk-21-jre   # Ubuntu

# Download TLC
mkdir -p ~/.local/lib/tlaplus
curl -L -o ~/.local/lib/tlaplus/tla2tools.jar \
    https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
```

Or use: `just formal-install`

## References

- [ProVerif Manual](https://proverif.inria.fr/manual.pdf)
- [TLA+ Hyperbook](https://lamport.azurewebsites.net/tla/hyperbook.html)
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [Noise Explorer](https://noiseexplorer.com/) - Visual Noise pattern analysis
