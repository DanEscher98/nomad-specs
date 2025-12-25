# Master Todo - Nomad Conformance Suite

## Active Tentacles (ready to spawn)

| ID | Description | Scope | Worktree |
|----|-------------|-------|----------|
| t1-security | Security layer spec + tests | specs/1-SECURITY.md, tests/unit/test_crypto* | .worktrees/t1-security |
| t2-transport | Transport layer spec + tests | specs/2-TRANSPORT.md, tests/unit/test_frame* | .worktrees/t2-transport |
| t3-sync | Sync layer spec + tests | specs/3-SYNC.md, tests/protocol/test_sync* | .worktrees/t3-sync |
| t7-resilience | Network stress testing | tests/resilience/*, tests/lib/chaos.py | .worktrees/t7-resilience |
| t8-adversarial | Security red team testing | tests/adversarial/*, tests/lib/attacker.py | .worktrees/t8-adversarial |

## Pending Tentacles

| ID | Description | Blocked By |
|----|-------------|------------|
| t4-extensions | Extension mechanism | t1, t2, t3 |

## Completed Tentacles

| ID | Merged | Notes |
|----|--------|-------|
| t5-docker | b9c97e7 | Docker infrastructure, 10 tests passing |
| t6-vectors | 9eba181 | Reference codec (NomadCodec), 35 tests, sync_vectors.json5 |
