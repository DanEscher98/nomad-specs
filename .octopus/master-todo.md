# Master Todo - Nomad Conformance Suite

## Active Tentacles

| ID | Description | Scope | Status | Worktree |
|----|-------------|-------|--------|----------|
| t5-docker | Docker orchestration, plug & play | docker/*, tests/lib/containers.py | active | .worktrees/t5-docker |

## Pending Tentacles

| ID | Description | Blocked By |
|----|-------------|------------|
| t6-vectors | Reference codec, vector generation | t5-docker (partial) |
| t1-security | Security layer spec + tests | t6-vectors |
| t2-transport | Transport layer spec + tests | t6-vectors |
| t3-sync | Sync layer spec + tests | t6-vectors |
| t4-extensions | Extension mechanism | t1, t2, t3 |

## Completed Tentacles

| ID | Merged | Notes |
|----|--------|-------|
| - | - | - |
