# RuntimeLens — Teacher Demo Commands

> **Project:** Context-Aware Runtime Threat Classification for Multi-Tenant Kubernetes
> **What it does:** Watches a Kubernetes cluster across 5 data sources, detects threats (crypto-mining, privilege abuse, container escape), and takes automatic containment actions — all with a tamper-evident audit log.

---

## Step 0 — Go to the project folder

```bash
cd ~/Desktop/RuntimeLens
```

---

## Step 1 — Install dependencies

```bash
make setup
```
> **Why:** This creates a virtual environment and installs all Python packages via `uv`. Run once.

---

## Step 2 — Check code quality (linting + type checking)

```bash
make lint
```
```bash
make typecheck
```
> **Why:** `lint` checks code style. `typecheck` runs mypy to catch type errors. Both must pass before any commit.

---

## Step 3 — Run all unit + integration tests

```bash
make test
```
> **Why:** Runs the full test suite (unit, contract, integration). Shows the system is verified and working.

---

## Step 4 — Environment health check (doctor)

```bash
uv run python scripts/control_runtimelens.py doctor
```
> **Why:** Verifies Python version, installed packages, and tool availability. Good "are we ready?" check.

---

## Step 5 — Run the live demonstration (KEY DEMO)

**Interactive mode** (pauses between scenarios, good for teacher walkthrough):
```bash
make demo
```

**Automated mode** (runs fully without pausing, good for a quick show):
```bash
make demo-auto
```

> **What it shows:**
> The system processes events from 4 threat scenarios — Benign, Privilege Abuse, Container Escape, Cryptomining — and prints classifications + policy actions (log / alert / quarantine) with risk scores.

---

## Step 6 — Start the webhook ingestion server

This starts a local HTTP server that receives real-time Falco/Kubernetes alerts:

```bash
uv run python scripts/control_runtimelens.py start-webhook \
  --host 127.0.0.1 \
  --port 18765 \
  --audit-file data/audit/webhook_audit.jsonl \
  --secret dev-token-sample \
  --pid-file /tmp/runtimelens-webhook.pid
```

> **Why:** This is the "live ingestion" component. It listens on localhost for security events pushed by Falco or Kubernetes audit.

---

## Step 7 — Send a test security event to the webhook

```bash
uv run python scripts/control_runtimelens.py post-event \
  --host 127.0.0.1 \
  --port 18765 \
  --endpoint /falco \
  --secret dev-token-sample \
  --payload '{"output": "Notice: Shell spawned", "rule": "Terminal shell in container", "output_fields": {"k8s.ns.name": "tenant-a", "k8s.pod.name": "web-01", "proc.name": "bash"}}'
```

> **What it shows:** A Falco alert (shell spawned inside a container) is sent to the system, classified, and a policy action is taken.

---

## Step 8 — Stop the webhook server

```bash
uv run python scripts/control_runtimelens.py stop-webhook \
  --pid-file /tmp/runtimelens-webhook.pid
```

---

## Step 9 — Verify the audit log integrity

```bash
uv run python scripts/control_runtimelens.py verify-audit \
  --audit-file data/audit/demo_audit.jsonl
```

> **Why (key research feature):** Every decision is recorded in a SHA-256 hash-chained JSONL file. This command proves no record was tampered with — like a blockchain for security decisions.

---

## Step 10 — Run the safety scenario linter

```bash
make safety-lint
```

> **Why:** Checks all scenario definition files for safety compliance (no real malware, no real miners). Academic integrity check.

---

## Recommended order for the teacher demo

| # | Command | Talking point |
|---|---------|---------------|
| 1 | `make setup` | Install & environment |
| 2 | `make lint && make typecheck` | Code quality |
| 3 | `make test` | All tests pass |
| 4 | `doctor` command | System health |
| 5 | `make demo` | **Main demo** — threat classification live |
| 6 | `start-webhook` → `post-event` → `stop-webhook` | Live ingestion pipeline |
| 7 | `verify-audit` | Tamper-evident audit log |

---

## Architecture in one line

```
5 sources (Falco + K8s audit + Hubble + Prometheus + Trivy)
  → normalize → correlate → baseline compare → classify → policy action → audit log
```
