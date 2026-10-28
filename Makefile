PYTHON ?= python3
.PHONY: setup pull fetch verify test reproduce
setup:
	./scripts/setup.sh
pull:
	git submodule update --init --recursive
	git lfs pull
	git -C references/can1357-hl lfs pull
fetch:
	$(PYTHON) tools/artifacts.py fetch
verify:
	$(PYTHON) tools/artifacts.py verify
	$(PYTHON) tools/verify_imports.py
test:
	$(PYTHON) -m unittest discover -s tests -v
reproduce:
	$(PYTHON) tools/reproduce.py
