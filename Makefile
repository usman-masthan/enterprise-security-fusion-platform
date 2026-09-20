.PHONY: help setup sync test run report clean

help:
	@echo "Enterprise Security Fusion Platform - Developer CLI"
	@echo "===================================================="
	@echo "make setup   - Initialize git submodules and verify environment"
	@echo "make sync    - Pull latest upstream commits for all child repositories"
	@echo "make test    - Run cross-module integration test suite"
	@echo "make run     - Execute the full end-to-end multi-project pipeline"
	@echo "make clean   - Remove cache files, test outputs, and temporary artifacts"

setup:
	git submodule update --init --recursive
	python3 -m pip install -r requirements.txt 2>/dev/null || true

sync:
	python3 run_ecosystem.py --sync

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v

run:
	python3 run_ecosystem.py --all

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf data/test_output/
