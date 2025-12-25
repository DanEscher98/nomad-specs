# Master Todo - Nomad Conformance Suite

## Active Tentacles

| ID | Description | Scope | Status | Worktree |
|----|-------------|-------|--------|----------|
| - | - | - | - | - |

## Pending Tentacles

| ID | Description | Blocked By |
|----|-------------|------------|
| t6-vectors | Reference codec, vector generation | none |
| t1-security | Security layer spec + tests | t6-vectors |
| t2-transport | Transport layer spec + tests | t6-vectors |
| t3-sync | Sync layer spec + tests | t6-vectors |
| t4-extensions | Extension mechanism | t1, t2, t3 |

## Completed Tentacles

| ID | Merged | Notes |
|----|--------|-------|
| t5-docker | b9c97e7 | Docker infrastructure, 10 tests passing |
