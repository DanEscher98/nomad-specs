# Tentacle: t5-docker
## Docker orchestration and plug & play infrastructure

**Scope:** docker/*, tests/lib/containers.py, tests/conftest.py, CONFORMANCE.md

## Tasks
- [x] Move docker-compose.yml into docker/ directory and enhance
- [x] Create docker/Dockerfile.stub for minimal echo server/client
- [x] Create tests/lib/containers.py with Docker management utilities
- [x] Create tests/conftest.py with pytest fixtures (containers, packet capture, keypairs)
- [x] Create CONFORMANCE.md documentation for implementation authors
- [x] Set up tests/pyproject.toml with test dependencies (pytest, hypothesis, scapy, docker)
- [x] Create Justfile with docker-up, test commands
- [x] Verify infrastructure works end-to-end

## Notes
- Container interface defined in .octopus/contracts/interfaces.md
- Must expose: 19999/udp (protocol), 8080/tcp (health check)
- Environment: ROAM_SERVER_PRIVATE_KEY, ROAM_SERVER_PUBLIC_KEY, ROAM_STATE_TYPE, ROAM_LOG_LEVEL
- Stub implementation uses roam.echo.v1 state type (simple echo)
- tcpdump sidecar for packet capture
- pumba for network chaos testing (optional profile)

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Auto-generated from .octopus/master-todo.md*
