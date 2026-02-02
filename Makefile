.PHONY: install test lint clean run help

help:
	@echo "Available targets:"
	@echo "  install    - Install the package in development mode"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linting"
	@echo "  clean      - Clean build artifacts"
	@echo "  run        - Run sentinel CLI"
	@echo "  docker     - Build Docker image"

install:
	pip install -e .

test:
	pytest tests/ -v

lint:
	flake8 sentinel/
	black --check sentinel/

clean:
	rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

run:
	sentinel --help

docker:
	docker build -t sentinel-cli:latest .
