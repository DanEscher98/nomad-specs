# NOMAD Paper Makefile

MAIN = nomad
LATEX = pdflatex
BIBTEX = bibtex

# Mermaid CLI for diagram conversion
MMDC = mmdc

# Figures directory
FIGURES_DIR = figures

.PHONY: all clean figures pdf bib

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

# Clean auxiliary files
clean:
	rm -f $(MAIN).aux $(MAIN).bbl $(MAIN).blg $(MAIN).log $(MAIN).out
	rm -f $(MAIN).toc $(MAIN).lof $(MAIN).lot $(MAIN).fls $(MAIN).fdb_latexmk
	rm -f $(MAIN).synctex.gz

# Clean everything including PDF
distclean: clean
	rm -f $(MAIN).pdf

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
	@echo "  figures  - Convert Mermaid diagrams to PDF"
	@echo "  clean    - Remove auxiliary files"
	@echo "  distclean- Remove all generated files"
	@echo "  watch    - Auto-rebuild on changes"
	@echo "  lint     - Check for common issues"
	@echo "  wc       - Word count"
