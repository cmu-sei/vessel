# Automation of various common tasks

# -----------------------------------------------------------------------------
# QA
# -----------------------------------------------------------------------------

# Format all source code
.PHONY: format
format:
	poetry run ruff format

.PHONY: check-format
check-format:
	poetry run ruff format --check

# Lint all source code
.PHONY: lint
lint:
	poetry run ruff check --fix

.PHONY: check-lint
check-lint:
	poetry run ruff check

# Typecheck all source code
.PHONY: typecheck
typecheck:
	poetry run mypy vessel/

.PHONY: check-typecheck
check-typecheck: typecheck

# Clean cache files
.PHONY: clean
clean: 
	rm -r -f .mypy_cache .pytest_cache .ruff_cache

# All quality assurance
.PHONY: qa
qa: format lint typecheck

# Check all QA tasks
.PHONY: check
check: check-lint check-typecheck

# Run unit tests with pytest
.PHONY: test
test:
	poetry run pytest test

# -----------------------------------------------------------------------------
# All actions and checks needed to update and review for pushing.
# -----------------------------------------------------------------------------
.PHONY: ci
ci: clean qa test
