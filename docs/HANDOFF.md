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
- **Ticket `09a` (`09a-passed`, `6e18e5b`):** Unified 5-source raw telemetry archiver (`data/raw/{falco,audit,hubble,prometheus,trivy}`) ensuring full dataset reproducibility without rerunning.
- **Ticket `06a` (`06a-passed`):** Staged scenario runner, safety manifest linter, simulated runtime socket path in `/opt/runtimelens-dummy/`, and full 25-run live pilot execution inside `runtimelens-vm` with 100% clean teardown verified.
- **Ticket `09b` (`09b-passed`):** Hubble network flow, Prometheus cAdvisor resource, and Trivy vulnerability normalizers with capture-sufficiency audit (`audit_capture.py`) verified across all 5 telemetry streams.
- **Ticket `06b` (`06b-passed`):** Empirical 400-run resource budget locked, 1,000-resample bootstrap power simulation confirming CI half-width $\pm 0.0135$ ($\le \pm 0.08$) and power 1.0 ($\ge 0.80$), `docs/PREREGISTRATION.md` updated, and Design Freeze recommended.
- **Ticket `06c` (`06c-passed`):** Full 400-run live cluster dataset generated inside `runtimelens-vm` kind cluster across 5 seeds, exact pre-registered class counts verified (60 esc, 60 prv, 60 cry, 40 unk, 180 ben), raw telemetry archived in `data/raw/`, resumable manifest in `data/scenarios/run_checkpoint.json`.
- **Ticket `07` (`07-passed`):** Dataset partitioned 72/28 (288 Dev, 112 Held-out Test), `datasets/splits/manifest_v1.json` committed and locked with SHA-256 hash (`7bed7ecdbd24773d0d4258687f5e0131d393c82dc88f227f09950d3f902f0c4b`), automated CI leakage tests passing.
- **Ticket `08` (`08-passed`):** Numerical feature extractor (19 dimensions), scikit-learn Random Forest baseline trained on 288 Dev runs (Macro-F1 1.0, 95% Bootstrap CI `[1.0, 1.0]`), model saved to `models/rf_baseline.joblib`.
- **Ticket `10` (`10-passed`):** `ScaleDownAdapter` with XML-delimited state serializer, prompt-injection escaping, SHA-256 caching, and offline contract tests (`tests/contract/test_scaledown_adapter.py`).
- **Ticket `13a` (`13a-passed`):** Pure deterministic policy engine & 14-case exhaustive unit test suite covering all overrides, conflict matrix rows, and confidence thresholds.

---

## 2. Active & Blocked Tickets

- **Active Ticket:** `12a` (Dev-Set Equal-Budget Model Tuning, Policy Sweeps & 6 Systematic Ablations)
- **Status:** `BLOCKED-ON A-005` (Checkpoint H: Human Track R2 Round 2 Blind Review $\kappa \ge 0.80$ & Dev Tuning Authorization)
- **State Clarification on Ticket 11 & 12a Key Governance:** The ScaleDown API key is needed for Ticket 12a Dev tuning, and must be provided exclusively via `SCALEDOWN_API_KEY` in a session initiated directly in the user's terminal.
- **Snapshot Baseline:** Snapshot `snap-s4` captured and verified on `runtimelens-vm` post-S4.

---

## 3. Active Branches

- `main`: Clean, fully tested, all CI gates passing.
- `ahead/12b` (`4063954`): Adversarial prompt-injection evaluation harness & 4-defense test suite.
- `ahead/14` (`472a250`): Prometheus operational metrics exporter & Grafana secops dashboard.
- `ahead/16c` (`439f6db`): 5-minute live interactive demonstration script & viva defense runbook.

---

## 4. Open Queue Entries (`docs/APPROVAL_QUEUE.md`)

- **`A-005`:** Checkpoint H: Human Track R2 Round 2 Blind Review Verification & Dev Tuning Authorization (Ticket 12a).
  - *Recommendation:* `PENDING HUMAN INPUT` on R2 Round 2 kappa result ($\kappa \ge 0.80$).

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
