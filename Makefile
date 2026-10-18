SHELL := /bin/bash
REQUIRED_KUBE_CONTEXT := kind-runtimelens

.PHONY: help setup lint format typecheck test pre-commit-install precommit-review verify-gates check-kube-context lab-up lab-down lab-verify test-live-api

help:
	@echo "RuntimeLens Development Automation"
	@echo "-----------------------------------"
	@echo "setup               : Install dependencies and setup venv via uv"
	@echo "lint                : Run ruff linter and format checker"
	@echo "format              : Auto-format and fix lint issues"
	@echo "typecheck           : Run mypy strict type checker"
	@echo "test                : Run all pytest suites"
	@echo "pre-commit-install  : Install git pre-commit hooks"
	@echo "precommit-review    : Execute 9-point standing review checks before commit"
	@echo "verify-gates        : Re-run verification checks for passed tickets"
	@echo "lab-up              : Create kind cluster and install Cilium CNI"
	@echo "lab-verify          : Verify cluster health and context safety"
	@echo "lab-down            : Destroy kind lab cluster"
	@echo "test-live-api       : Run live ScaleDown API smoke test (requires SCALEDOWN_API_KEY)"

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
	uv run pytest tests/unit/ tests/contract/ tests/integration/

pre-commit-install:
	uv run pre-commit install

precommit-review:
	@echo "=== Executing 9-Point Pre-Commit Review Protocol ==="
	@echo "[Point 1: Diff & Scope Check]"
	git status -s
	@echo "[Point 2: Secrets & Privacy Check]"
	uv run python scripts/check_secrets.py $$(git ls-files)
	@echo "[Point 3: Code Lint & Formatting]"
	$(MAKE) lint
	@echo "[Point 4: Strict Typecheck]"
	$(MAKE) typecheck
	@echo "[Point 5: Test Suite]"
	$(MAKE) test
	@echo "[Point 6: Gate Regression Verification]"
	$(MAKE) verify-gates
	@echo "[Point 7: Review Documentation Existence]"
	@test -d docs/reviews || (echo "ERROR: docs/reviews/ missing" && exit 1)
	@echo "=== Pre-Commit Review Protocol PASSED ==="

# Safety check required by D-06: Every cluster target must verify context == kind-runtimelens
check-kube-context:
	@which kubectl >/dev/null 2>&1 || (echo "ERROR: kubectl not installed" && exit 1)
	@CTX=$$(kubectl config current-context 2>/dev/null || echo "none"); \
	if [ "$$CTX" != "$(REQUIRED_KUBE_CONTEXT)" ]; then \
		echo "SAFETY REFUSAL: Current kubectl context '$$CTX' is NOT '$(REQUIRED_KUBE_CONTEXT)'. Refusing to execute cluster operations."; \
		exit 1; \
	fi

lab-up:
	@echo "Creating kind cluster with config lab/kind/kind-config.yaml..."
	kind create cluster --config lab/kind/kind-config.yaml
	$(MAKE) check-kube-context
	@echo "Installing Cilium with kubeProxyReplacement and Hubble Relay..."
	cilium install --set kubeProxyReplacement=true --set hubble.enabled=true --set hubble.relay.enabled=true --set hubble.ui.enabled=false
	cilium status --wait

lab-verify: check-kube-context
	@echo "Verifying lab cluster status..."
	cilium status
	kubectl get nodes -o wide

lab-down: check-kube-context
	@echo "Tearing down kind cluster 'runtimelens'..."
	kind delete cluster --name runtimelens

test-live-api:
	@if [ -z "$$SCALEDOWN_API_KEY" ]; then \
		echo "ERROR: SCALEDOWN_API_KEY environment variable is not set."; \
		echo "Please export SCALEDOWN_API_KEY in your terminal before running this target."; \
		exit 1; \
	fi
	RUN_LIVE_API_TESTS=1 uv run pytest tests/live/test_smoke.py -v -s

verify-gates:
	@echo "=== Verifying Gate 01: Repo Foundation, Secrets CI & Skeleton ==="
	$(MAKE) lint
	$(MAKE) typecheck
	$(MAKE) test
	uv run python scripts/check_secrets.py pyproject.toml README.md src/runtimelens/sanitizer.py
	@echo "=== Gate 01 Verification Passed ==="
