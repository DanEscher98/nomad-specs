# Tentacle: t9-paper
## arXiv paper preparation - NOMAD Protocol

**Scope:** specs/, paper/

## Mission
Prepare the NOMAD Protocol for arXiv publication. Create a professional academic paper with LaTeX layout, diagrams, and clear technical exposition.

## Context
- **5 specs available**: 0-PROTOCOL, 1-SECURITY, 2-TRANSPORT, 3-SYNC, 4-EXTENSIONS
- **Conformance suite**: 657 spec tests, 60 server tests passing
- **First Rust implementation**: Has passed the conformance suite
- **Target**: arXiv cs.NI (Networking and Internet Architecture)

---

## Tasks

### Phase 1: Research & Extraction
- [ ] Extract key contributions from each spec
- [ ] Identify novel aspects vs Mosh/QUIC/WireGuard
- [ ] List evaluation metrics from test suite (657 spec, 60 server tests)
- [ ] Gather timing constants and security properties

### Phase 2: LaTeX Setup
- [ ] Create `paper/` directory
- [ ] Set up ACM or IEEE LaTeX template (arXiv-friendly)
- [ ] Create `paper/figures/` for diagrams
- [ ] Add Makefile for compilation

### Phase 3: Writing Sections
- [ ] Abstract (200 words): State sync + Noise + UDP
- [ ] Introduction: Problem statement, Mosh limitations, contribution
- [ ] Background: Noise Protocol, XChaCha20-Poly1305, SSP concept
- [ ] Protocol Overview: Layer diagram, message types
- [ ] Security Layer: Noise_IK handshake, rekeying, replay protection
- [ ] Transport Layer: Framing, keepalive, roaming
- [ ] Sync Layer: Versioned state, idempotent diffs, convergence
- [ ] Extensions: TLV mechanism, compression
- [ ] Evaluation: Test suite coverage, conformance methodology
- [ ] Related Work: Mosh, QUIC, WireGuard comparison table
- [ ] Conclusion & Future Work

### Phase 4: Figures (Mermaid → PDF/SVG)
- [ ] Protocol layer stack diagram
- [ ] Noise_IK handshake sequence
- [ ] Frame format packet diagram
- [ ] Sync convergence state machine
- [ ] Roaming message flow

### Phase 5: arXiv Prep
- [ ] Bibliography (BibTeX)
- [ ] Author affiliations
- [ ] License selection (CC BY)
- [ ] Abstract metadata for arXiv submission

---

## Key Contributions to Highlight

1. **Noise_IK + XChaCha20-Poly1305**: Modern crypto vs Mosh's AES-OCB
2. **Epoch-based rekeying**: Forward secrecy with nonce namespacing
3. **Roaming without reconnection**: Session ID continuity across IP changes
4. **Idempotent state diffs**: Convergence despite packet loss/reorder
5. **Conformance test suite**: 700+ tests, reference codec, test vectors

---

## References to Cite

- Winstein & Balakrishnan (2012): Mosh USENIX paper
- Perrin (2018): Noise Protocol Framework
- Donenfeld (2017): WireGuard NDSS
- RFC 8439: ChaCha20-Poly1305
- RFC 9000: QUIC

---

## Notes

- Use mermaid-cli (`mmdc`) to convert diagrams to PDF
- arXiv accepts PDF with source, or just PDF
- Target 10-12 pages double-column
- Specs already have Mermaid diagrams to adapt

---

## Blocked
<!-- If scope exceeded, document here and STOP -->

---
*Auto-generated from .octopus/master-todo.md*
