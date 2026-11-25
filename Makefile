.PHONY: run run-debug db-migrate db-upgrade db-history test test-fast test-coverage lint format clean install edit install-dev help

## Project settings
PYTHON = python
UVICORN = uvicorn
ALEMBIC = alembic
PYTEST = pytest

## Run commands

run:          ## Start dev server (http://localhost:8000)
	$(UVICORN) zerotrace.main:app --reload --port 8000

run-debug:    ## Start server with debug logging
	$(UVICORN) zerotrace.main:app --reload --port 8000 --log-level debug

## Database commands

db-upgrade:   ## Run pending migrations
	$(ALEMBIC) upgrade head

db-downgrade: ## Revert last migration
	$(ALEMBIC) downgrade -1

db-history:   ## Show migration history
	$(ALEMBIC) history --verbose

db-current:   ## Show current migration
	$(ALEMBIC) current

db-stamp-head: ## Mark current DB as at head (no migration run)
	$(ALEMBIC) stamp head

## Test commands

test:         ## Run all tests
	$(PYTEST) tests/ -v --tb=short

test-fast:    ## Run quick tests only (no integration)
	$(PYTEST) tests/test_validator.py tests/test_orchestrator.py tests/test_database.py tests/test_api_schemas.py -v

test-coverage: ## Run tests with coverage report
	$(PYTEST) tests/ -v --cov=src/zerotrace --cov=cli --cov-report=term-missing

test-integration: ## Run integration tests
	$(PYTEST) tests/test_integration.py -v

## Lint and format

lint:         ## Run ruff linter
	ruff check src/ cli/ tests/

format:       ## Format code with ruff
	ruff format src/ cli/ tests/

## Development setup

install:      ## Install the package in editable mode
	$(PYTHON) -m pip install -e .

install-dev:  ## Install with dev dependencies
	$(PYTHON) -m pip install -e ".[dev]"

edit:         ## Quick editable install (for development changes)
	$(PYTHON) -m pip install --no-build-isolation -e .

## Utility commands

clean:        ## Remove cache files and compiled artifacts
	@echo "Cleaning __pycache__ directories..."
	@powershell -command "Get-ChildItem -Path . -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force"
	@powershell -command "Get-ChildItem -Path . -Recurse -Filter '*.pyc' | Remove-Item -Force"
	@echo "Done."

help:         ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'