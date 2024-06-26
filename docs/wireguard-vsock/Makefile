name   := paper
viewer := mupdf
attach := attachments

sections := $(wildcard sections/*.tex)

PDFLATEX_OPTS := -shell-escape -interaction=nonstopmode -file-line-error

all: $(name).pdf
view: $(name).pdf
	$(viewer) $(name).pdf

$(name).pdf: $(name).tex $(sections) $(name).bib architecture.pdf kubernetes-arch.pdf
	mkdir -p build
	pdflatex $(PDFLATEX_OPTS) -output-directory build/ $(name)
	bibtex build/$(name)
	pdflatex $(PDFLATEX_OPTS) -output-directory build/ $(name)
	pdflatex $(PDFLATEX_OPTS) -output-directory build/ $(name)
	mv build/$(name).pdf .

polyglot: polyglot/$(name).pdf
polyglot/$(attach).zip: FORCE
	mkdir -p polyglot
	zip -r polyglot/$(attach).zip $(attach)
polyglot/$(name).pdf: $(name).pdf polyglot/$(attach).zip
	cat $(name).pdf polyglot/$(attach).zip > polyglot/$(name).pdf
	zip -A polyglot/$(name).pdf
distribute: distclean all polyglot
	cp polyglot/$(name).pdf .

sign: $(name).pdf # Sign the document for validity...
	gpg --output $(name).sig --detach-sig $(name).pdf

clean:
	rm -rf build
distclean: clean
	rm -rf polyglot
	rm -f $(name).pdf
.PHONY: all view polyglot clean distclean distribute
FORCE:
