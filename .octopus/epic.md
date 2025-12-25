# Epic: Roam Protocol Conformance Suite

## Goal

Build a plug & play E2E conformance test suite that validates any Roam protocol implementation (Rust, Go, etc.) against the specification.

## Acceptance Criteria

- [ ] Docker infrastructure allows plugging any server/client implementation
- [ ] Python reference codec implements full protocol (handshake, frames, sync)
- [ ] Test vectors generated from reference libs (JSON5 with comments)
- [ ] Unit tests validate frame encoding/decoding
- [ ] Protocol tests validate handshake, rekeying, roaming
- [ ] Wire tests validate byte-level format compliance
- [ ] Adversarial tests validate security properties
- [ ] Specs are isomorphic to tests (each spec section maps to test cases)

## Exit Criteria

- [ ] All ACs demonstrated
- [ ] All tentacles merged
- [ ] Test suite runs green with stub implementation
- [ ] Documentation complete (CONFORMANCE.md)

## Out of Scope

- Actual Rust/Go implementations (separate repos)
- MoshiMoshi app
- Terminal state type implementation
- Performance benchmarks

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Test framework | pytest | Standard, good fixtures, hypothesis integration |
| Property testing | hypothesis | Finds edge cases humans miss |
| Packet inspection | scapy | Industry standard for protocol testing |
| Container mgmt | docker-compose | Simple, declarative |
| Dependency mgmt | uv | Fast, modern Python tooling |
| Vector format | JSON5 | Allows inline comments for documentation |
| Reference libs | snow, cryptography | Battle-tested implementations |

## Tentacle Breakdown

| ID | Scope | Dependencies | Status |
|----|-------|--------------|--------|
| t5-docker | docker/*, tests/lib/containers.py, tests/conftest.py, CONFORMANCE.md | none | pending |
| t6-vectors | specs/generate_vectors.py, tests/vectors/*.json5, tests/lib/reference.py | t5-docker (partial) | pending |
| t1-security | specs/SECURITY.md, tests/unit/test_crypto*, tests/protocol/test_handshake* | t6-vectors | pending |
| t2-transport | specs/TRANSPORT.md, tests/unit/test_frame*, tests/wire/* | t6-vectors | pending |
| t3-sync | specs/SYNC.md, tests/protocol/test_sync*, tests/unit/test_diff* | t6-vectors | pending |
| t4-extensions | specs/EXTENSIONS.md, tests/protocol/test_extension* | t1, t2, t3 | pending |

## Priority Order

1. **t5-docker** - Infrastructure first (plug & play foundation)
2. **t6-vectors** - Reference codec + vector generation
3. **t1, t2, t3** - Layer specs + tests (can parallelize)
4. **t4-extensions** - After core layers done
