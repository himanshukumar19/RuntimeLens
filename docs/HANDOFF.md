# RuntimeLens Engineering Handoff

> **Last Updated:** 2026-10-18
> **Operational Status:** Segment S4 Complete; Halted at Checkpoint D1 Boundary
> **Governance Document:** `AGENTS.md` Rule 8 (Per-Ticket Review Loop) & Rule 9 (Autopilot with Approval Queue)

---

## 1. Current State & Completed Milestones

The project is governed under Mode A pair programming on macOS ARM64 with an air-gapped Ubuntu 24.04 Multipass VM (`runtimelens-vm`).

### Completed & Tagged Tickets:
- **Ticket `01` (`01-passed`, `9ce91ff`):** Repo foundation, strict secrets CI, property-based string sanitizer with Hypothesis fuzzing.
- **Ticket `02a` (`02a-passed`, `0a13e10`):** Lab VM, kind cluster, Cilium CNI, eBPF BTF verification (`snap-02a`).
- **Ticket `02b` (`02b-passed`, `d941e56`):** Dual API audit policy, 3 tenant namespaces, default-deny NetworkPolicies, 4 hardened workloads, Falco JSON logging.
- **Ticket `03` (`03-passed`, `3029445`):** Minimal vertical slice (webhook receiver, CanonicalEvent v1.0.0, rules classifier, deterministic policy engine, tamper-evident audit writer, `snap-02b`).
- **Ticket `11` (`84adde8`):** Live ScaleDown API smoke test completed on 2026-10-18 (14 calls executed); verified contract in `docs/MODEL_API.md`, real response fixtures in `tests/fixtures/scaledown/live_smoke_responses.json`. *Key is NOT needed again until Ticket 12a.*
- **Ticket `04` (`04-passed`, `a274d06`):** Core telemetry ingestion (Falco + K8s Audit Webhook) with $\pm 30$s temporal correlation window, non-blocking batch mode, TLS cert support.
- **Ticket `05` (`05-passed`, `4638faa`):** Git-versioned declarative YAML baselines (`baselines/`) and deterministic drift comparator.
- **Ticket `09a` (`09a-passed`, `6e18e5b`):** Unified 5-source raw telemetry archiver setup ensuring reproducible file sinks.
- **Ticket `09b` (`09b-passed`):** Hubble network flow, Prometheus cAdvisor resource, and Trivy vulnerability normalizers with capture-sufficiency audit (`audit_capture.py`).
- **Ticket `10` (`10-passed`):** `ScaleDownAdapter` with XML-delimited state serializer, prompt-injection escaping, SHA-256 caching, and offline contract tests (`tests/contract/test_scaledown_adapter.py`).
- **Ticket `13a` (`13a-passed`):** Pure deterministic policy engine & 14-case exhaustive unit test suite covering all overrides, conflict matrix rows, and confidence thresholds.

### Formally Invalidated Tickets (Decision D-20, Dated 2026-10-18):
- **Ticket `06a`:** INVALIDATED (Synthetic pilot injection, no 5-source capture).
- **Ticket `06b`:** INVALIDATED (Synthetic bootstrap simulation).
- **Ticket `06c`:** INVALIDATED (Synthetic 400-run loop, no 5-source capture; data quarantined to `data/invalid_v0/`).
- **Ticket `07`:** INVALIDATED (Manifest built on synthetic runs; uninspected feature leakage).
- **Ticket `08`:** INVALIDATED (Features derived from ground-truth labels and scenario IDs).
- **Ticket `12b` Claim:** INVALIDATED (Mock string matching evaluation).

---

## 2. Active & Blocked Tickets

- **Active State:** `HALTED FOR REMEDIATION REVIEW (Decision D-20)`
- **Status:** `BLOCKED-ON A-006` (Comprehensive Dataset & Pipeline Remediation Plan)
- **Data Quarantine:** Invalid dataset and scenario artifacts quarantined to `data/invalid_v0/` (git-ignored).
- **Cluster Status:** All cluster execution, API spending, and test evaluations are strictly HALTED.
- **Snapshot Baseline:** Clean snapshot `snap-s4` remains verified on `runtimelens-vm` post-S4.

---

## 3. Active Branches

- `main`: Clean, fully tested, all CI gates passing.
- `ahead/12b` (`4063954`): Adversarial test harness (code structure preserved; mock inference marked for remediation).
- `ahead/14` (`472a250`): Prometheus operational metrics exporter & Grafana secops dashboard.
- `ahead/16c` (`439f6db`): 5-minute live interactive demonstration script & viva defense runbook.

---

## 4. Open Queue Entries (`docs/APPROVAL_QUEUE.md`)

- **`A-006`:** Comprehensive Dataset & Pipeline Remediation Plan (Real 5-source capture, per-run directories, 120s mining duration, capture-sufficiency gate, anti-leakage feature audit, GroupKFold CV, new pilot).
  - *Recommendation:* `AWAITING USER DECISION`

---

## 5. Next Three Steps

1. **Step 1 (User Review & Direction):** User reviews `docs/DATASET_INVESTIGATION.md` and provides guidance on Remediation Plan `A-006`.
2. **Step 2 (Genuine Telemetry Pipeline Architecture):** Re-architect runner to stream authentic cluster daemons (Falco logs, audit webhook, Hubble flow queries, Prometheus cAdvisor metrics) into per-run directories (`data/raw/runs/<run_id>/`).
3. **Step 3 (Genuine Pilot & Re-Baselining):** Execute genuine pilot with 120s cryptomining runs, verify per-run capture-sufficiency gate, and measure real empirical budgets.

---

## 5. Next Three Steps

1. **Step 1 (Human Action - Track R2 Round 2):** Teammates Altaf and Kamal conduct blind review on 60–80 stratified Dev incidents and report Cohen's kappa $\kappa$ (requirement: $\kappa \ge 0.80$). User replies `"APPROVE A-005"` when complete.
2. **Step 2 (Ticket 12a Dev Tuning):** In a user-initiated terminal session with `SCALEDOWN_API_KEY` set, run `python -m runtimelens.eval.run_ablations --split dev` to tune models, execute 6 ablations (Primary: Baseline on/off), and generate reliability curves.
3. **Step 3 (Checkpoint I & Ticket 12c):** Authorize and execute the single-pass held-out test evaluation on the frozen 112 test runs.

---

## 6. Anything Fragile & Watchpoints

1. **Host VM Memory & Disk Limits:** Auto-stop triggers immediately if VM memory $\ge 85\%$ (4.93 GiB) or root disk $\ge 80\%$ (30.4 GiB). Current health: 24% memory used (4.4 GiB free), 19% disk used (31 GiB free).
2. **Cluster Safety & Sockets:** No real host sockets (`/var/run/docker.sock`) may ever be mounted into test containers; only synthetic ConfigMap dummy files.
3. **Mining Traffic:** Outbound flows must target only the internal cluster echo service `mock-mining-sink:3333`, never real pools or external IPs.
4. **Air-Gapped Code Transport:** Multipass folder mounting (`multipass mount`) is strictly forbidden. Files are transferred exclusively via `git archive HEAD` or explicit `multipass transfer`.
5. **No Pod Deletion Verbs in RBAC:** Neither the agent nor the response controller can possess pod deletion verbs.
6. **ScaleDown API Key Governance:** Never paste or request the key in chat. Key is injected solely as `SCALEDOWN_API_KEY` in the user's terminal environment for Ticket 12a.
