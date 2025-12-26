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
- [x] Extract key contributions from each spec
- [x] Identify novel aspects vs Mosh/QUIC/WireGuard
- [x] List evaluation metrics from test suite (657 spec, 60 server tests)
- [x] Gather timing constants and security properties

### Phase 2: LaTeX Setup
- [x] Create `paper/` directory
- [x] Set up ACM or IEEE LaTeX template (arXiv-friendly)
- [x] Create `paper/figures/` for diagrams
- [x] Add Makefile for compilation

### Phase 3: Writing Sections
- [x] Abstract (200 words): State sync + Noise + UDP
- [x] Introduction: Problem statement, Mosh limitations, contribution
- [x] Background: Noise Protocol, XChaCha20-Poly1305, SSP concept
- [x] Protocol Overview: Layer diagram, message types
- [x] Security Layer: Noise_IK handshake, rekeying, replay protection
- [x] Transport Layer: Framing, keepalive, roaming
- [x] Sync Layer: Versioned state, idempotent diffs, convergence
- [x] Extensions: TLV mechanism, compression
- [x] Evaluation: Test suite coverage, conformance methodology
- [x] Related Work: Mosh, QUIC, WireGuard comparison table
- [x] Conclusion & Future Work

### Phase 4: Figures (Mermaid → PDF/SVG)
- [x] Protocol layer stack diagram
- [x] Noise_IK handshake sequence
- [x] Frame format packet diagram
- [x] Sync convergence state machine
- [x] Roaming message flow

### Phase 5: arXiv Prep
- [x] Bibliography (BibTeX)
- [x] Author affiliations
- [ ] License selection (CC BY)
- [ ] Abstract metadata for arXiv submission

### Phase 6: Supplementary Documents
- [x] Constants mapping document (all constants, rationale, external refs)
- [x] Annotated bibliography (why each reference is relevant)

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

## Notes from Tentacle

**Author info added:**
- Danyiel Colin
- amaniel2718@protonmail.com
- Rust implementation: https://crates.io/crates/nomad-protocol

**Remaining items:**
- License selection: Confirm CC BY license for arXiv
- arXiv metadata: Complete submission form on arXiv.org

**Paper status:**
- nomad.tex: Complete 7-page paper with all sections
- references.bib: 12 entries covering all cited works
- figures/*.mmd: 5 Mermaid diagrams ready for conversion
- nomad.pdf: Compiles successfully with pdflatex/bibtex
- Target: arXiv cs.NI (Networking and Internet Architecture)

To compile: `cd paper && make pdf`

---

## arXiv Submission Checklist

From https://info.arxiv.org/help/submit_tex.html

### Files to Include
- [ ] `nomad.tex` - main LaTeX file
- [ ] `references.bib` - BibTeX source
- [ ] `nomad.bbl` - **REQUIRED**: processed BibTeX output (arXiv doesn't run bibtex)
- [ ] Figure files (PDF/PNG/JPG only for pdflatex)

### Files to EXCLUDE (arXiv auto-removes)
- `*.aux`, `*.log`, `*.toc`, `*.lot`, `*.lof`
- `*.dvi`, `*.ps`
- `nomad.pdf` (arXiv generates its own)
- Backup files, extraneous files

### Requirements Checklist
- [ ] Single-spaced (not double-spaced referee mode)
- [ ] No `\today` in `\date{}` field (we use `\date{}` which is fine)
- [ ] No JavaScript/animated content in figures
- [ ] Figures in PDF/PNG/JPG format (Mermaid → PDF conversion needed)
- [ ] All `\includegraphics` paths correct
- [ ] No `psfig` package (deprecated)

### Submission Package
```bash
# Generate .bbl file
cd paper
pdflatex nomad.tex
bibtex nomad
pdflatex nomad.tex
pdflatex nomad.tex

# Create submission archive (include .bbl, exclude .pdf and aux files)
zip arxiv-submission.zip nomad.tex nomad.bbl references.bib figures/*.pdf
```

### Before Submit
- [ ] Convert Mermaid diagrams to PDF: `mmdc -i fig.mmd -o fig.pdf`
- [ ] Verify .bbl file is generated and included
- [ ] Test compile on clean machine
- [ ] Select processor: PDFLaTeX
- [ ] Category: cs.NI (Networking and Internet Architecture)

---
*Auto-generated from .octopus/master-todo.md*
