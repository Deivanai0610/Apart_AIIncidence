# Beginner note: `make matrix` renders the data files into tables.
# Only dependency is PyYAML (see requirements.txt).

PYTHON ?= python3

.PHONY: matrix deps clean

matrix:
	$(PYTHON) scripts/build_matrix.py

deps:
	$(PYTHON) -m pip install -r requirements.txt

clean:
	rm -rf out/*.md out/*.html
