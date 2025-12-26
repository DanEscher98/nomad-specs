# NOMAD Protocol Formal Verification

This directory contains formal models for verifying security and correctness properties of the NOMAD protocol.

> **Security Findings**: See [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) for verification results and discovered limitations.

## Quick Start

```bash
# Run all formal verification (from project root)
just formal-all

# Or run separately
just formal-proverif  # Cryptographic properties
just formal-tlaplus   # State machine correctness
```

## Overview

| Tool | Purpose | Files |
|------|---------|-------|
| ProVerif | Cryptographic security properties | `proverif/*.pv` |
| TLA+ | State machine correctness | `tlaplus/*.tla` |

## ProVerif Models

ProVerif is a cryptographic protocol verifier that can prove security properties in the symbolic model (Dolev-Yao adversary).

### Installation

```bash
# Fedora/RHEL (build from source)
sudo dnf install ocaml ocaml-findlib
cd /tmp
curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz
cd proverif2.05
./build
sudo cp proverif proveriftotex /usr/local/bin/

# Ubuntu/Debian
sudo apt install proverif

# macOS
brew install proverif

# Verify installation
proverif --version
```

### Models

| File | Properties Verified |
|------|---------------------|
| `nomad_handshake.pv` | Noise_IK handshake: authentication, key secrecy, identity hiding |
| `nomad_rekey.pv` | Forward secrecy, post-compromise security, key independence |
| `nomad_replay.pv` | Replay protection, nonce uniqueness, frame integrity |

### Running

```bash
# Verify individual models
proverif formal/proverif/nomad_handshake.pv
proverif formal/proverif/nomad_rekey.pv
proverif formal/proverif/nomad_replay.pv

# Or use Justfile commands (from project root)
just formal-proverif           # Run all ProVerif models
just formal-proverif-handshake # Run handshake only
just formal-proverif-rekey     # Run rekey only
just formal-proverif-replay    # Run replay only
```

### Expected Output

Successful verification shows:
```
RESULT ... is true.
```

For each query in the model.

### Security Properties Verified

#### Handshake (`nomad_handshake.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Key secrecy | Attacker cannot learn initiator's session key |
| Q2 | Key secrecy | Attacker cannot learn responder's session key |
| Q3 | Authentication | Initiator completes => Responder participated |
| Q4 | Authentication | Responder accepts => Initiator started |
| Q5 | Key agreement | Both parties derive same session key |

#### Rekeying (`nomad_rekey.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Forward secrecy | Epoch 0 secrets safe after epoch 1 compromise |
| Q2 | Forward secrecy | Epoch 1 secrets independent of epoch 0 |
| Q3 | Baseline | Epoch 2 secrets safe (no compromise) |
| Q4 | Post-compromise | New keys secure after key compromise |

#### Replay Protection (`nomad_replay.pv`)

| Query | Property | Description |
|-------|----------|-------------|
| Q1 | Frame integrity | Accepted frames were sent by peer |
| Q2 | No replay | Same nonce never accepted twice |
| Q3 | Payload integrity | Payload not modified in transit |

## TLA+ Specifications

TLA+ is a formal specification language for modeling concurrent and distributed systems.

### Installation

```bash
# Install Java (required for TLA+ tools)
# Fedora/RHEL
sudo dnf install java-21-openjdk

# Ubuntu/Debian
sudo apt install openjdk-21-jre

# macOS
brew install openjdk@21

# Download TLA+ command-line tools
mkdir -p ~/.local/lib/tlaplus
curl -L -o ~/.local/lib/tlaplus/tla2tools.jar \
    https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

# Verify installation
java -cp ~/.local/lib/tlaplus/tla2tools.jar tlc2.TLC -h
```

**Optional**: Download [TLA+ Toolbox IDE](https://github.com/tlaplus/tlaplus/releases) for graphical model checker.

### Specifications

| File | System | Properties |
|------|--------|------------|
| `SyncLayer.tla` | State synchronization | Eventual consistency, idempotent diffs, monotonic versions |
| `RekeyStateMachine.tla` | Session rekeying | Key rotation, epoch management, counter limits |
| `Roaming.tla` | Connection migration | Session survival, anti-amplification, spoof prevention |

### Running

```bash
# Using TLC model checker (command line)
java -XX:+UseParallelGC -cp ~/.local/lib/tlaplus/tla2tools.jar tlc2.TLC \
    -config formal/tlaplus/SyncLayer.cfg formal/tlaplus/SyncLayer.tla

# Or use Justfile commands (from project root)
just formal-tlaplus          # Run all TLA+ models
just formal-tlaplus-sync     # Run SyncLayer only
just formal-tlaplus-rekey    # Run RekeyStateMachine only
just formal-tlaplus-roaming  # Run Roaming only

# Or open in TLA+ Toolbox IDE and run Model Checker
```

### Configuration Files

Each `.tla` file needs a `.cfg` file specifying constants and properties to check.

Example `SyncLayer.cfg`:
```
CONSTANTS
    MaxStateNum = 5
    MaxDiffValue = 3
    NumNodes = 2

SPECIFICATION Spec

INVARIANTS
    TypeOK
    Safety

PROPERTIES
    EventualConsistency
```

### Properties Verified

#### Sync Layer (`SyncLayer.tla`)

| Property | Type | Description |
|----------|------|-------------|
| TypeOK | Invariant | All variables have correct types |
| MonotonicStateNums | Safety | State numbers only increase |
| AckedNeverExceedsSent | Safety | Acks bounded by sent versions |
| EventualConsistency | Liveness | States converge when messages get through |

#### Rekey State Machine (`RekeyStateMachine.tla`)

| Property | Type | Description |
|----------|------|-------------|
| MonotonicEpochs | Safety | Epoch numbers only increase |
| KeysMatchEpoch | Safety | Current keys correspond to epoch |
| NonceUniqueness | Safety | Nonces never reused within epoch |
| RekeyEventuallyHappens | Liveness | Rekeying occurs before limits reached |

#### Roaming (`Roaming.tla`)

| Property | Type | Description |
|----------|------|-------------|
| AntiAmplification | Safety | 3x limit on unvalidated addresses |
| SessionSurvivesRoaming | Safety | Session stays active during roaming |
| AttackerCannotRedirect | Security | Spoofed frames can't hijack session |
| CommunicationResumes | Liveness | Connection recovers after IP change |

## Correspondence to Specifications

| Spec Section | ProVerif Model | TLA+ Spec |
|--------------|----------------|-----------|
| 1-SECURITY.md §Handshake | `nomad_handshake.pv` | - |
| 1-SECURITY.md §Rekeying | `nomad_rekey.pv` | `RekeyStateMachine.tla` |
| 1-SECURITY.md §Anti-Replay | `nomad_replay.pv` | - |
| 2-TRANSPORT.md §Roaming | - | `Roaming.tla` |
| 3-SYNC.md §Convergence | - | `SyncLayer.tla` |

## Modeling Assumptions

### ProVerif

- **Dolev-Yao adversary**: Attacker controls network, can observe/inject/modify
- **Perfect cryptography**: AEAD, DH, hash are idealized (no implementation bugs)
- **Symbolic model**: Keys are abstract symbols, not bit strings

### TLA+

- **Finite state space**: Constants bound model (e.g., MaxStateNum = 5)
- **Fair scheduling**: WF_vars ensures enabled actions eventually happen
- **Abstract time**: Discrete steps, not continuous time

## Cross-Validation with Test Vectors

The formal models should align with test vectors in `tests/vectors/`:

| Formal Model | Test Vectors |
|--------------|--------------|
| `nomad_handshake.pv` | `handshake_vectors.json5` |
| `nomad_rekey.pv` | `frame_vectors.json5` (rekey frames) |
| `SyncLayer.tla` | `sync_vectors.json5` |

To validate:
1. Extract symbolic traces from ProVerif models
2. Compare message sequences with test vector derivations
3. Verify state transitions match TLA+ model

## References

- [ProVerif Manual](https://proverif.inria.fr/manual.pdf)
- [TLA+ Home](https://lamport.azurewebsites.net/tla/tla.html)
- [Noise Protocol Analysis](https://noiseexplorer.com/)
- [Noise Specification](https://noiseprotocol.org/noise.html)

## Contributing

When modifying formal models:

1. Ensure all queries still verify
2. Update this README if adding new properties
3. Cross-reference with spec changes
4. Run model checker with increased bounds to catch edge cases
