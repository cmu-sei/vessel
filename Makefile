# Automation of various common tasks

# -----------------------------------------------------------------------------
# Virtual enviroment setup actions
# -----------------------------------------------------------------------------

.PHONY: venv
venv:
	bash setup_venv.sh

.PHONY: venv_qa
venv_qa:
	bash setup_venv.sh -q

# -----------------------------------------------------------------------------
# QA actions
# -----------------------------------------------------------------------------

# Sort imports
.PHONY: isort
isort: venv_qa
	poetry run ruff check --select I --fix

.PHONY: check-isort
check-isort: venv_qa
	poetry run ruff check --select I

# Format all source code
.PHONY: format
format: venv_qa
	poetry run ruff format

.PHONY: check-format
check-format: venv_qa
	poetry run ruff format --check

# Lint all source code and workflows
.PHONY: lint
lint: venv_qa
	poetry run ruff check --fix

.PHONY: check-lint
check-lint: venv_qa
	poetry run ruff check

# Typecheck all source code
.PHONY: typecheck
typecheck: venv_qa
	poetry run mypy vessel/

.PHONY: check-typecheck
check-typecheck: typecheck

# All quality assurance
.PHONY: qa
qa: isort format lint typecheck

# Check all QA tasks
.PHONY: check
check: check-isort check-format check-lint check-typecheck

# -----------------------------------------------------------------------------
# Build actions
# -----------------------------------------------------------------------------

# Build all containers
.PHONY: build
build:
	bash build_containers.sh

# -----------------------------------------------------------------------------
# Test actions
# -----------------------------------------------------------------------------

# Run unit tests inside container
.PHONY: test
test: build
	docker run --rm vessel-test

# -----------------------------------------------------------------------------
# All actions and checks, equivalent to what the CI does
# -----------------------------------------------------------------------------

# Clean cache files
.PHONY: clean
clean: 
	rm -r -f .mypy_cache .pytest_cache .ruff_cache

.PHONY: ci
ci: clean check test
