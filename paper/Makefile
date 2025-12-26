# NOMAD Paper Makefile

MAIN = nomad
LATEX = pdflatex
BIBTEX = bibtex

# Mermaid CLI for diagram conversion
MMDC = mmdc

# Figures directory
FIGURES_DIR = figures

.PHONY: all clean figures pdf bib arxiv

all: pdf

# Build PDF (full compilation with bibliography)
pdf: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex references.bib $(wildcard $(FIGURES_DIR)/*.pdf)
	$(LATEX) $(MAIN)
	$(BIBTEX) $(MAIN)
	$(LATEX) $(MAIN)
	$(LATEX) $(MAIN)

# Quick build (single pass, no bibliography update)
quick:
	$(LATEX) $(MAIN)

# Convert Mermaid diagrams to PDF
figures: $(FIGURES_DIR)/layers.pdf $(FIGURES_DIR)/handshake.pdf $(FIGURES_DIR)/roaming.pdf

$(FIGURES_DIR)/layers.pdf: $(FIGURES_DIR)/layers.mmd
	$(MMDC) -i $< -o $@ -t neutral

$(FIGURES_DIR)/handshake.pdf: $(FIGURES_DIR)/handshake.mmd
	$(MMDC) -i $< -o $@ -t neutral

$(FIGURES_DIR)/roaming.pdf: $(FIGURES_DIR)/roaming.mmd
	$(MMDC) -i $< -o $@ -t neutral

# arXiv submission package
# Note: arXiv requires .bbl file (they don't run bibtex)
arxiv: $(MAIN).bbl
	@echo "Creating arXiv submission package..."
	@rm -f arxiv-submission.zip
	zip arxiv-submission.zip $(MAIN).tex $(MAIN).bbl references.bib
	@echo "Created arxiv-submission.zip"
	@echo "Contents:"
	@unzip -l arxiv-submission.zip
	@echo ""
	@echo "Submit to: https://arxiv.org/submit"
	@echo "Category: cs.NI (Networking and Internet Architecture)"

# Generate .bbl file
$(MAIN).bbl: $(MAIN).tex references.bib
	$(LATEX) $(MAIN)
	$(BIBTEX) $(MAIN)

# Clean auxiliary files (keeps .bbl for arxiv)
clean:
	rm -f $(MAIN).aux $(MAIN).blg $(MAIN).log $(MAIN).out
	rm -f $(MAIN).toc $(MAIN).lof $(MAIN).lot $(MAIN).fls $(MAIN).fdb_latexmk
	rm -f $(MAIN).synctex.gz

# Clean everything including PDF and .bbl
distclean: clean
	rm -f $(MAIN).pdf $(MAIN).bbl arxiv-submission.zip

# Watch for changes and rebuild (requires latexmk)
watch:
	latexmk -pdf -pvc $(MAIN)

# Check for common issues
lint:
	@echo "Checking for common LaTeX issues..."
	@grep -n "\\\\cite{}" $(MAIN).tex && echo "Warning: Empty citations found" || true
	@grep -n "TODO" $(MAIN).tex && echo "Warning: TODOs found" || true
	@grep -n "XXX" $(MAIN).tex && echo "Warning: XXX markers found" || true

# Word count (approximate)
wc:
	@texcount -1 -sum $(MAIN).tex

# Help
help:
	@echo "Available targets:"
	@echo "  all      - Build PDF (default)"
	@echo "  pdf      - Build PDF with bibliography"
	@echo "  quick    - Quick build (single pass)"
	@echo "  arxiv    - Create arXiv submission package (.zip)"
	@echo "  figures  - Convert Mermaid diagrams to PDF"
	@echo "  clean    - Remove auxiliary files (keeps .bbl)"
	@echo "  distclean- Remove all generated files"
	@echo "  watch    - Auto-rebuild on changes"
	@echo "  lint     - Check for common issues"
	@echo "  wc       - Word count"
