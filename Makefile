# Automation of various common tasks

# -----------------------------------------------------------------------------
# QA
# -----------------------------------------------------------------------------

# Sort imports.
.PHONY: isort
isort:
	poetry run ruff check --select I --fix

.PHONY: check-isort
check-isort:
	poetry run ruff check --select I

# Format all source code
.PHONY: format
format:
	poetry run ruff format

.PHONY: check-format
check-format:
	poetry run ruff format --check

# Lint all source code and workflows
.PHONY: lint
lint:
	poetry run ruff check --fix
	poetry run actionlint

.PHONY: check-lint
check-lint:
	poetry run ruff check
	poetry run actionlint

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
qa: isort format lint typecheck

# Check all QA tasks
.PHONY: check
check: check-isort check-format check-lint check-typecheck

# Run unit tests with pytest
.PHONY: test
test:
	poetry run pytest test

# -----------------------------------------------------------------------------
# Container actions.
# -----------------------------------------------------------------------------

# Build all containers.
.PHONY: containers
containers:
	bash build_containers.sh

# Run unit tests inside container
.PHONY: test-container
test-container:
	docker run --rm vessel-test

# Build and run unit tests inside container
.PHONY: build-test-container
build-test-container: containers test-container

# -----------------------------------------------------------------------------
# All actions and checks equivalent to what the CI does.
# -----------------------------------------------------------------------------
.PHONY: ci
ci: clean check test
