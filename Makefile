SHELL := /bin/bash
REQUIRED_KUBE_CONTEXT := kind-runtimelens

.PHONY: help setup lint format typecheck test pre-commit-install verify-gates check-kube-context

help:
	@echo "RuntimeLens Development Automation"
	@echo "-----------------------------------"
	@echo "setup               : Install dependencies and setup venv via uv"
	@echo "lint                : Run ruff linter and format checker"
	@echo "format              : Auto-format and fix lint issues"
	@echo "typecheck           : Run mypy strict type checker"
	@echo "test                : Run all pytest suites"
	@echo "pre-commit-install  : Install git pre-commit hooks"
	@echo "verify-gates        : Re-run verification checks for passed tickets"

setup:
	uv sync --extra dev

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy src tests scripts

test:
	uv run pytest tests/unit/test_sanitizer.py tests/unit/test_secrets_guard.py

pre-commit-install:
	uv run pre-commit install

# Safety check required by D-06: Every cluster target must verify context == kind-runtimelens
check-kube-context:
	@which kubectl >/dev/null 2>&1 || (echo "ERROR: kubectl not installed" && exit 1)
	@CTX=$$(kubectl config current-context 2>/dev/null || echo "none"); \
	if [ "$$CTX" != "$(REQUIRED_KUBE_CONTEXT)" ]; then \
		echo "SAFETY REFUSAL: Current kubectl context '$$CTX' is NOT '$(REQUIRED_KUBE_CONTEXT)'. Refusing to execute cluster operations."; \
		exit 1; \
	fi

verify-gates:
	@echo "=== Verifying Gate 01: Repo Foundation, Secrets CI & Skeleton ==="
	$(MAKE) lint
	$(MAKE) typecheck
	$(MAKE) test
	uv run python scripts/check_secrets.py pyproject.toml README.md src/runtimelens/sanitizer.py
	@echo "=== Gate 01 Verification Passed ==="
