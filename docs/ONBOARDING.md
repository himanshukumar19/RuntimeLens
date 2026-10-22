# RuntimeLens — Onboarding Walkthrough (Plain-English)

> Purpose: a step-by-step orientation to *what this project is* and *what it actually does*.
> Branch: `learn/runtimelens-onboarding`
> Source of truth for facts: `docs/PROJECT_BRIEF.md`, `docs/ARCHITECTURE.md`, `docs/GLOSSARY.md`,
> `docs/HANDOFF.md`, plus the code under `src/runtimelens/`.

---

## 0. The 30-second version

RuntimeLens is a **security tool for Kubernetes containers** that watches what is happening
*inside running containers* (not just what was baked into the image), decides **whether that
behaviour is a threat**, and then **acts safely and reversibly** (log / alert / ask a human /
isolate the pod).

The interesting academic twist: it compares **three classifiers** fairly, and its central
research question is *"does telling the model what 'normal' looks like for this specific
workload actually improve the decision?"*

---

## 1. The problem it solves

Container security today mostly means **scanning images before deployment** (Trivy).
But by the time an image is scanned, the attacker may already be *running*:

| Threat | What happens | Why image scanning misses it |
|---|---|---|
| **Container escape** | A process reaches the host kernel / Docker socket | Image is "clean" — the danger is in the *runtime behaviour* |
| **Privilege abuse** | A container spawns a shell it was never supposed to run | Image is "clean" — the danger is in the *runtime behaviour* |
| **Cryptomining** | A pod quietly burns CPU and talks to a pool | Image is "clean" — the danger is in the *runtime behaviour* |

All containers on a node **share one OS kernel**. So one compromised container can affect the
whole node. RuntimeLens watches the *live* behaviour across **five telemetry sources** and
judges it.

**The gap it fills:** existing rule engines (like Falco's rules) have no idea what your
workload normally does — they flag the same syscall as "suspicious" even when it's routine.
Classical ML can learn it, but needs manual feature engineering and lots of data.

---

## 2. The five telemetry sources (the "eyes")

| Source | What it sees | Where it comes from |
|---|---|---|
| **Falco** | Syscalls / process behaviour (eBPF at kernel level) | `src/runtimelens/normalizer/falco.py` |
| **Kubernetes Audit** | Control-plane API calls (`exec`, `get secret`, RBAC changes) | `src/runtimelens/collector/audit_webhook.py` |
| **Hubble (Cilium)** | Network flows — who talked to whom, was it dropped | `src/runtimelens/normalizer/hubble.py` |
| **Prometheus (cAdvisor)** | CPU / memory usage over time | `src/runtimelens/normalizer/prometheus.py` |
| **Trivy** | Static image vulnerabilities | `src/runtimelens/normalizer/trivy.py` |

All raw data is **sanitized (secret redaction) at the moment of capture**, before it is stored
or sent anywhere — see `src/runtimelens/sanitizer.py`.

---

## 3. The pipeline — 7 stages, one event at a time

Read the code in this order. Each stage is one file, and each stage has one job.

```
Raw telemetry
   │
   ▼
[1] COLLECT + SANITIZE        collector/*.py , sanitizer.py
   │   Receive events, strip secrets/tokens/env vars, write raw JSONL
   ▼
[2] NORMALIZE + CORRELATE     normalizer/*.py , collector/correlation.py
   │   Map each source's own format → one canonical shape.
   │   Merge events from DIFFERENT sources that belong to the same
   │   (namespace, pod, workload) within a ±30 second window.
   ▼
[3] FACT EXTRACT + BASELINE   models/event.py , baseline/*.py
   │   Compute unambiguous booleans in code (not guessed by a model):
   │   is_root? is_shell_process? host_socket_mounted? privileged?
   │   Compare against the workload's declarative baseline YAML.
   ▼
[4] CLASSIFY                  classifiers/rules.py , classifiers/scaledown.py , eval/train_rf.py
   │   Ask the classifier: what class? how severe? what evidence?
   ▼
[5] POLICY ENGINE              policy/engine.py
   │   Deterministic, pure function. Safety rules override the model, always.
   ▼
[6] ACT                       (response controller — mostly dry-run today)
   │   log / alert / human_review / quarantine (label + TTL auto-rollback)
   ▼
[7] AUDIT                      audit/writer.py
       Hash-chained JSONL. Tamper-evident: each record includes the hash
       of the previous one, so edits are detectable.
```

### Stage 1 in code — collect & sanitize
`src/runtimelens/collector/webhook.py` (Falco JSON webhook receiver),
`src/runtimelens/collector/audit_webhook.py` (K8s audit receiver),
`src/runtimelens/sanitizer.py` (secret scrubbing, fuzz-tested with Hypothesis).

### Stage 2–3 in code — the canonical event
`src/runtimelens/models/event.py` defines `CanonicalEvent v1.0.0`. **Every** source,
no matter how different, is squeezed into this one Pydantic model:

```
CanonicalEvent
├── workload      : tenant, namespace, pod_name, pod_uid, owner_workload, image_digest
├── telemetry_source : source, source_event_id, source_rule_name, raw_event_ref
├── facts         : host_runtime_socket_mounted, sensitive_host_path_mounted,
│                   privileged_container, is_root_user, is_shell_process,
│                   has_critical_vulnerability, cpu_usage_mcores, is_cpu_abnormal,
│                   is_outbound_egress, is_cross_tenant_flow
├── runtime       : process_name, parent_process, command_args_sanitized, syscall
├── orchestration : verb, resource, subresource, request_user
├── network       : destination_ip, destination_port, protocol, verdict, dns_query
├── baseline      : baseline_version, shell_expected, expected_binaries,
│                   expected_peers, baseline_deviation_detected, deviations
└── health        : is_telemetry_degraded, missing_sources
```

Note `extra="forbid"` on every model — an unexpected field is an **error**, not silently
ignored. That is how they keep the schema honest.

### Stage 4 in code — three classifiers, one interface
All three answer the same contract, so the benchmark is fair:

```python
def classify(state: CanonicalEvent) -> ClassificationResult
```

| Classifier | File | What it is |
|---|---|---|
| **Rules** | `classifiers/rules.py` | Maps Falco rule names → threat class. The "dumb" baseline. |
| **Random Forest** | `eval/train_rf.py` | Classical ML on 19 engineered features (`features/extractor.py`). |
| **ScaleDown Classify-1** | `classifiers/scaledown.py` | Hosted typed-decision model (the "interesting" one). |

**What "typed-decision" means** (this is the paper's core trick):
Instead of asking the model to write free-form text, RuntimeLens asks **6 fixed questions**
(see `models/rubrics.py`):

1. **Choice** — Which single class? (`benign` / `container_escape` / `privilege_abuse` /
   `cryptomining` / `unknown`) → returns a probability distribution.
2. **Score** — How severe (1–5 rubric)? → returns an interpolated continuous score.
3. **Noul × 4** — four independent yes/no evidence checks:
   `baseline_deviation`, `shell_unexpected`, `resource_exposure`, `resource_abuse`
   → each returns a probability 0–1.

Because answers are constrained, you get **calibrated, comparable, machine-checkable** output —
not prose you'd have to parse. The adapter also escapes XML delimiters in the state text
(`escape_state_delimiters`) so a malicious command line can't **prompt-inject** the model.

### Stage 5 in code — the policy engine (the safety brain)
`src/runtimelens/policy/engine.py` is a **pure function**. No I/O, no randomness. Same input →
same output, always. Precedence order:

```
1. Safety overrides        degraded telemetry? degraded model? stale baseline?
                            host socket / sensitive path mounted?   → human_review
2. Choice↔Noul conflict    model said "benign" but says baseline_deviation 0.8?
                            model said "container_escape" but no exposure & no shell?
                            → human_review  (the model contradicted itself)
3. Confidence gate         confidence < 0.70  → human_review
4. Action tiers            benign → log
                            severity ≥ 4.0 + allowed namespace → quarantine (+900s TTL)
                            severity ≥ 3.0 → alert
```

Two hard safety properties you can verify by reading the file:
- Quarantine is **only** allowed in `tenant-a/b/c`. System namespaces (`kube-system`, `cilium`,
  `falco`, …) get `alert` instead. (`ALLOWED_QUARANTINE_NAMESPACES` / `FORBIDDEN_SYSTEM_NAMESPACES`)
- There is **no `terminate` action at all**. The action literal is
  `Literal["log", "alert", "human_review", "quarantine"]`. No pod-deletion permission exists
  anywhere in the RBAC or code. Pod termination is explicitly *future work*.

### Stage 6–7 in code — act and record
- Quarantine is **label-based**: patch label `quarantine=true` onto the pod; a pre-installed
  default-deny `NetworkPolicy` isolates it automatically. After 900s (15 min) the label is
  removed if nobody confirms → **auto-rollback**.
- `dry_run=True` is the default everywhere.
- `audit/writer.py` writes append-only JSONL where each record embeds `prev_record_hash`
  → tamper-evident chain.

---

## 4. Workload baselines — the "what normal looks like" file

`baselines/web.yaml`, `baselines/api.yaml`, `baselines/database.yaml`,
`baselines/payment-style.yaml`.

```yaml
runtime:
  shell_allowed: false
  allowed_binaries: ["/usr/sbin/nginx", "/bin/nc", "/bin/busybox"]
  allowed_parent_processes: ["containerd-shim", "init"]
  allowed_volume_mounts: ["/var/run/secrets/kubernetes.io/serviceaccount", "/tmp"]
  disallowed_mount_patterns: ["/var/run/*.sock", "/proc/*", "/sys/*"]
network:
  allowed_inbound_ports: [8080]
  allowed_peers: ["api.tenant-a.svc.cluster.local", ...]
  allow_external_egress: false
resources:
  cpu_baseline_mcores: 25
  cpu_max_envelope_mcores: 150
```

`baseline/comparator.py` diffs reality against this and produces `deviations[]` +
`baseline_deviation_detected`. **This is the variable the whole research project tests.**

---

## 5. The research question (this is the actual "paper")

> **Primary hypothesis:** Adding per-workload baseline context to the typed-decision model
> produces a statistically significant change in Macro-F1 and/or benign false-positive rate
> versus the same classifier without baseline context.

How they try to keep the science clean:

- **Paired counterfactual scenarios** — the *same* action (e.g. "spawn a shell") is run on a
  workload where it's normal and one where it violates the baseline. Baseline context is the
  only variable that changed.
- **Grouped splits** — split by `run_id`, never by individual event, so events from the same
  run can't leak across dev/test (`data/split.py`, 288 dev runs / 112 test runs, seed 1337).
- **Manifest air-gap lock** — `datasets/splits/manifest_v1.json` is SHA-256 locked. If anyone
  edits the split, the hash breaks.
- **Test split access log** — every read of the test split is logged (`log_test_eval_access`).
- **Pre-registration** — `docs/PREREGISTRATION.md` locks the plan *before* results exist, so
  they can't p-hack. Altering it after seeing dev results is explicitly forbidden by `AGENTS.md`.
- **Cluster-aware bootstrap** — confidence intervals resample whole runs, not events, so
  intra-run correlation doesn't inflate significance.

**Honesty rule:** negative and inconclusive results are just as reportable as positive ones.

---

## 6. The lab environment

Real experiments run against a **real** cluster, but a sandboxed one:

- `kind` cluster named `runtimelens` on an **Ubuntu 24.04 ARM64 Multipass VM** (4 vCPU, 6 GB RAM).
- **Cilium** CNI with eBPF host routing + **Hubble** for network flows.
- **3 tenant namespaces** (`tenant-a`, `tenant-b`, `tenant-c`), each with 4 hardened workloads:
  `web` (nginx), `api` (FastAPI), `database` (Redis), `payment-style` (transaction worker).
- API server / Hubble / Grafana bind to **127.0.0.1 only**.
- Scenarios are **controlled, benign-intent simulations** — no real malware, no weaponized
  exploits. Mining traffic only ever targets an in-cluster mock sink, never a real pool.

Safety guards baked into the tooling:
- `make check-kube-context` — refuses to run unless context is exactly `kind-runtimelens`.
- `make safety-lint` — lints the scenario manifests for unsafe actions.
- `make verify-gates` — re-runs the verification for passed tickets.
- `scripts/check_secrets.py` — secret scanning, runs in CI and pre-commit.
- `make precommit-review` — the 9-point review protocol from `AGENTS.md`.

---

## 7. Where the project currently stands

**Done and tagged:** `01`, `02a`, `02b`, `03`, `04`, `05`, `09a`, `09b`, `10`, `13a`, plus a live
ScaleDown API smoke test (`11`).

**Formally invalidated** (and this is important — they threw out their own earlier work):
`06a`, `06b`, `06c`, `07`, `08`, and the `12b` claim. Reason: the earlier dataset was
**synthetic** (injected, not captured), and the features were derived from ground-truth labels
and scenario IDs → **data leakage**. They quarantined it (`data/invalid_v0/`) and are
rebuilding with genuinely captured 5-source telemetry.

**Currently:** halted at the **Stage 2 pilot** boundary, blocked on `A-007` (host macOS
routing fix for the VM) and awaiting a decision on `A-006` (the dataset remediation plan).

Open approval items live in `docs/APPROVAL_QUEUE.md`. The active pointer is at the top of
`docs/TICKET_TREE.md`.

---

## 8. Repo map

```
src/runtimelens/
├── models/        event.py (CanonicalEvent) · decision.py (results, policy, audit) · rubrics.py (6 questions)
├── collector/     webhook · audit_webhook · correlation · raw_capture · per_run_capture
├── normalizer/    falco · hubble · prometheus · trivy
├── baseline/      loader · models · comparator
├── features/      extractor.py  (19 anti-leakage features)
├── classifiers/   rules · scaledown
├── policy/        engine.py  (the safety brain)
├── eval/          train_rf · pilot_power
├── data/          split.py  (grouped, locked split)
├── scenarios/     runner.py  (live scenario execution)
├── audit/         writer.py  (hash-chained log)
└── sanitizer.py   (secret redaction)

baselines/         web.yaml · api.yaml · database.yaml · payment-style.yaml
lab/               kind config · falco rules · audit policy · tenant manifests · workloads
scripts/           check_secrets · verify_dataset · stage2_pilot · scenario_safety_lint · proof_run
tests/             unit/ · contract/ · integration/ · live/ (live needs SCALEDOWN_API_KEY)
docs/              the 30+ governance and design documents
```

---

## 9. Common commands

```bash
make setup        # uv sync --extra dev
make lint         # ruff check + format check
make typecheck    # mypy strict
make test         # pytest unit + contract + integration
make verify-gates # re-run gate verification for passed tickets
make lab-up       # create kind cluster + install Cilium
make lab-verify   # cluster health check
make safety-lint  # scenario safety manifest linter
```

Live API test needs `SCALEDOWN_API_KEY` in the environment. **Never paste the key in chat** —
`AGENTS.md` forbids it, and the project uses it only via the env var.

---

## 10. The 10 concepts that matter most

1. **CanonicalEvent** — one shape for all telemetry.
2. **Deterministic facts** — booleans computed in code, never guessed.
3. **Workload baseline** — declarative YAML of expected behaviour.
4. **Typed-decision model** — 6 fixed questions instead of free text.
5. **Choice / Score / Noul** — the three question shapes.
6. **Policy engine** — pure deterministic function; safety > model.
7. **Dry-run by default** — actions are proposed, TTL-rollback-able.
8. **Hash-chained audit log** — tamper-evident.
9. **Grouped split + air-gap lock** — prevents data leakage.
10. **Degraded mode** — if telemetry or API fails, → human review, never silently benign.

---

## 11. Suggested reading order

1. `docs/GLOSSARY.md` — the vocabulary (~15 min)
2. `docs/PROJECT_BRIEF.md` — the why (~10 min)
3. `docs/ARCHITECTURE.md` — the diagram (~15 min)
4. `src/runtimelens/models/event.py` — the data shape
5. `src/runtimelens/policy/engine.py` — the safety brain
6. `src/runtimelens/models/rubrics.py` — the 6 questions
7. `src/runtimelens/classifiers/scaledown.py` — how the model is called
8. `tests/unit/test_policy.py` — the rules, written as tests (very readable)
9. `docs/PREREGISTRATION.md` + `docs/EVALUATION_PLAN.md` — the science
10. `docs/HANDOFF.md` — where things stand right now
