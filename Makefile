PYTHON ?= python

.PHONY: install install-fast test demo bench lint clean

install:
	$(PYTHON) -m pip install -e .

install-fast:
	$(PYTHON) -m pip install -e ".[fast]"

test:
	$(PYTHON) -m pip install -e ".[dev]" >/dev/null
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) examples/demo.py

bench:
	$(PYTHON) examples/bench.py

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
