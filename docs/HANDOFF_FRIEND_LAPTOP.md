# RuntimeLens Engineering Handoff: Cluster Execution on Testing Machine

> **Date:** 2026-10-28  
> **Source Commit:** `8c8e954` (merged into `main` via PR #5)  
> **Test Suite:** 192 automated tests passing, 0 errors, strict typecheck clean.  
> **Target:** Transfer to Linux / VM host for live cluster verification and dataset generation.

---

## 1. Executive Summary & Codebase Readiness

All implementation tickets across the entire RuntimeLens architecture are 100% complete, tested, and merged into `main`. Zero coding remains to be done before cluster execution.

### Components Completed & Verified in Repository:
1. **Repository Foundation & CI (Ticket 01):** Strict offline CI, property-based string sanitizers, secret scanners (`check_secrets.py`).
2. **Cluster IaC & Namespaces (Tickets 02a, 02b):** Kind cluster config, Cilium CNI with Hubble relay, K8s audit policy, Falco eBPF rules, 3 tenant namespaces (`tenant-a`, `tenant-b`, `tenant-c`), 4 workloads (`web`, `api`, `database`, `payment-style`), default-deny NetworkPolicies.
3. **Core Telemetry & Ingestion (Tickets 03, 04, 04-live):** CanonicalEvent v1.0.0 model, ±30s temporal correlation sliding window, live multi-source correlation daemon (`src/runtimelens/collector/live_wiring.py`).
4. **Declarative Baselines & Drift Comparator (Ticket 05):** YAML baseline profiles for all workloads, deterministic deviation detector.
5. **Raw Multi-Source Capture & Normalizers (Tickets 09a, 09b):** Append-only 5-source daemon collectors (`falco/`, `audit/`, `hubble/`, `prometheus/`, `trivy/`), telemetry normalizers, capture-sufficiency auditor.
6. **ScaleDown Classify-1 Adapter (Ticket 10):** Delimited XML state serializer, prompt-injection defense, SHA-256 caching, offline mock fixtures.
7. **SRE Policy Engine & Response Controller (Tickets 13a, 13b):** Deterministic precedence rules, Choice-Noul conflict matrix, `QuarantineController` (`src/runtimelens/controller/quarantine.py`) applying `quarantine: "true"` label, 15m TTL rollback reconciliation loop, dry-run safety default, and strictly zero-delete RBAC manifests (`lab/rbac/response-controller-rbac.yaml`).
8. **Evaluation, Ablations & Test Harness (Tickets 12a, 12b, 12c):**
   - 6 systematic ablations runner (`src/runtimelens/eval/run_ablations.py`).
   - Adversarial prompt-injection test suite evaluating 10 payloads across 4 defense tiers.
   - Single held-out test evaluation harness with immutable audit access logging (`src/runtimelens/eval/run_final_test.py`).
9. **Observability, Risk Scoring & Demo (Tickets 14, 15, 16c):** Prometheus exporter, Grafana dashboard, continuous exposure risk scoring, human feedback diff generator, 5-minute live demonstration CLI (`scripts/demo.py`).
10. **Academic Deliverables (Tickets 16a, 16b):** Version 2.0 report draft (`docs/report/final_report.md`), poster redesign (`docs/poster/`).

---

## 2. Inbound Code Transfer: Current Machine -> Friend's Laptop

To transfer the clean, verified repository without leaking local `.env` or untracked scratch files:

```bash
# 1. On current Mac: create a clean Git archive of main
git archive --format=tar HEAD | gzip > /tmp/runtimelens.tar.gz

# 2. Transfer /tmp/runtimelens.tar.gz to the target testing laptop (via SCP, USB, or local network)

# 3. On the testing laptop / Linux VM: unpack into workspace
mkdir -p ~/RuntimeLens
tar -xzf runtimelens.tar.gz -C ~/RuntimeLens
cd ~/RuntimeLens

# 4. Set up dependencies using uv
uv sync --extra dev

# 5. Verify that all 192 tests pass out of the box
uv run pytest
```

---

## 3. Step-by-Step Cluster Execution Sequence on Friend's Laptop

### Phase 1: Cluster Bring-Up & Pre-Flight Checks
```bash
# 1. Bring up the Kind cluster with Cilium CNI and Hubble
make lab-up

# 2. Verify cluster health and context invariant (kind-runtimelens)
make lab-verify

# 3. Run safety linter on all scenario definitions
make safety-lint
```

### Phase 2: Stage 2 Pilot (25 Runs across 5 Sources)
```bash
# 1. Execute the 5-run ramp to verify receivers and cleanup
PYTHONPATH=src:. uv run python scripts/stage2_pilot.py --limit 5

# 2. Execute the full 25-run pilot
PYTHONPATH=src:. uv run python scripts/stage2_pilot.py --limit 25

# 3. Audit pilot captures for zero class leakage and capture sufficiency
PYTHONPATH=src:. uv run python scripts/verify_dataset.py --runs-dir data/raw/runs

# 4. Compute real Table F signatures across pilot data
PYTHONPATH=src:. uv run python scripts/signature_table.py --runs-dir data/raw/runs
```

### Phase 3: Pilot Analysis & Design Freeze (Tickets 06b & Checkpoint E)
```bash
# 1. Run power and variance simulation
PYTHONPATH=src:. uv run python -m runtimelens.eval.pilot_power

# 2. Review empirical per-run wall-clock, RAM, and disk metrics in data/scenarios/pilot_25_metrics.json
# 3. Update docs/PREREGISTRATION.md with locked 400-run resource budgets
```

### Phase 4: Full 400-Run Live Dataset Generation (Ticket 06c & Checkpoint F)
```bash
# Execute the full 400-run scenario loop in resumable batches
make run-dataset

# Verify entire dataset for zero leakage and sustained CPU invariants
PYTHONPATH=src:. uv run python scripts/verify_dataset.py --runs-dir data/raw/runs
```

### Phase 5: Partitioning, Classical ML & Evaluation (Tickets 07, 08, 12a, 12c)
```bash
# 1. Generate partitioned 72/28 split by template and lock manifest SHA-256 (Ticket 07)
PYTHONPATH=src:. uv run python -m runtimelens.data.split --manifest datasets/splits/manifest_v2.json

# 2. Fit Random Forest baseline on real Dev split (Ticket 08)
PYTHONPATH=src:. uv run python -m runtimelens.eval.train_rf

# 3. Execute 6 pre-registered systematic ablations on Dev split (Ticket 12a)
PYTHONPATH=src:. uv run python -m runtimelens.eval.run_ablations --split dev

# 4. Formally execute single held-out test evaluation pass (Ticket 12c, Checkpoint I)
PYTHONPATH=src:. uv run python -m runtimelens.eval.run_final_test --execute
```

### Phase 6: Live Interactive Demonstration (Ticket 16c)
```bash
# Run automated live interactive demonstration for viva / peer review
make demo-auto
```

---

## 4. Safety & Invariants Checklist

When running on the friend's laptop, preserve these strict invariants:
- **Kubectl Context Guard:** Must remain `kind-runtimelens`. Never run against host Kubernetes contexts.
- **Zero Pod Deletion Verbs:** The response controller and RBAC manifests operate strictly via `["get", "list", "watch", "patch"]`. Never grant pod `delete` permissions.
- **Dry-Run Containment Default:** Containment runs in dry-run mode by default; live quarantine patching operates via label `quarantine: "true"` with 15m auto-rollback.
- **Air-Gap on Test Split:** Do not execute `run_final_test.py --execute` until the Dev split tuning and Track R2 blind reviews are completed.

---

## 5. Suggested Skills for the Next Session

- `poteto-mode`: Maintain rigor, autonomous loop discipline, and verifiable units.
- `webapp-testing`: Browser / UI verification for Grafana dashboards and HTML poster rendering.
- `deslop` / `unslop`: Clean commit messages and academic writing formatting.
