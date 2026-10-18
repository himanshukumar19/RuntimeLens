# RuntimeLens Human Approval Queue

> **Queue Governance:** `AGENTS.md` Rule 9 (Autopilot with an Approval Queue).
> **Operational Protocol:** When an action requires human review or authorization, the agent appends a structured entry, marks the ticket `BLOCKED-ON A-xxx`, and proceeds to any unblocked offline work. When nothing unblocked remains, the agent stops and presents a digest.
> **Human Reply Format:** The user responds with:
> `APPROVE A-001, DENY A-002: <reason>`
> The agent logs decisions with dates in this file and proceeds.

---

## Decision Log

| Date | Queue ID | Ticket | Decision | Reason / Guidance |
|:---:|:---:|:---:|:---:|:---|
| 2026-10-18 | A-001 | 06a | CONDITIONALLY APPROVED | Approved: VM stop, snapshot `snap-s4`, VM restart, `make lab-up` & `make lab-verify`. Required safety sheet revisions: Option A inert dummy hostPath, anti-leakage neutral naming, 2-minute sustained mining duration across 10s scrape intervals, pre-flight cleanup sweep, and `snap-s4` rollback documentation before running pilot. |
| 2026-10-18 | A-002 | 06a | APPROVED WITH CONDITIONS | Approved with 6 conditions: (1) no real runtime socket path on node (/var/run is symlink to /run); inert dummy in /opt/runtimelens-dummy/ with extractor rule & unit tests; (2) hostPath pod strictly in ephemeral privileged lab namespace (not tenant namespaces); (3) scenario_safety_lint.py & make safety-lint verifying all invariants; (4) branch inspection confirming zero ahead/* merged; (5) show code-review output & confirm ahead/13a diffs; (6) staged ramp (dry-run -> ramp-5 -> full-25) with health check & cleanup proof after each step. |
| 2026-10-18 | A-003 | 06b/06c | APPROVED | Approved: Checkpoint E formal Design Freeze and launch authorization for Full 400-Run Live Cluster Scenario Generation (Ticket 06c) under empirical budgets (22.3m active time, ~28m operational envelope, peak RAM 25.2%, disk growth ~0.57 MB). |
| 2026-10-18 | A-004 | 07 | APPROVED | Approved: Checkpoint G verification of dataset split SHA-256 air-gap lock (7bed7ecdbd24773d0d4258687f5e0131d393c82dc88f227f09950d3f902f0c4b), exact 72/28 counts (288 Dev, 112 Test), and authorization to advance to Ticket 08. |

---

## Active Approval Items

### Entry `A-006` — Comprehensive Dataset & Pipeline Remediation Plan (Tickets 06a, 06b, 06c, 07, 08, 12b)

- **Queue ID:** `A-006`
- **Ticket ID:** `06a-08 Remediation` (Pillars 1 to 5)
- **Status:** `PENDING HUMAN REVIEW & DECISION`
- **Specification Document:** `docs/DATASET_INVESTIGATION.md`
- **What:** Authorize executing the comprehensive 5-pillar dataset and pipeline remediation plan:
  1. *Genuine Multi-Source Live Telemetry Runner:* Real container execution for authentic durations (120s sustained CPU for cryptomining; 15–30s for standard probes) writing directly into **per-run directories** (`data/raw/runs/<run_id>/<source>/`) from live cluster daemons (Falco logs, audit webhook stream, Hubble observe flows, Prometheus cAdvisor metrics, Trivy scan reports).
  2. *Enforced Per-Run Capture-Sufficiency Gate:* Automated assertion verifying minimum real event counts across all 5 streams before advancing to the next run.
  3. *Enforced Dataset-Validity & Anti-Leakage Gate:*
     - Feature extractor accepts only `CanonicalEvent` and `BaselineContext` objects (zero access to scenario IDs, ground truth labels, or metadata).
     - Automated label-permutation test asserting $F1 \approx \text{chance}$ (baseline validity).
     - Group-wise cross-validation (`GroupKFold`) grouped strictly by scenario variant.
     - Single-feature predictive ceiling ($\le 0.65$ Macro-F1).
  4. *Empirical Budgeting on New Pilot:* Execute a genuine 25-run pilot with 120s cryptomining runs and measure authentic wall-clock time, disk bytes per run, and RAM utilization under sustained load.
  5. *Documented Pre-Registration Deviation:* Record remediation in `docs/PREREGISTRATION.md`, generate a new manifest (`manifest_v2.json`) with new SHA-256 air-gap lock, and evaluate test split strictly once at 12c.
- **What It Changes:**
  - Discards synthetic single-file logs in favor of authentic per-run multi-source telemetry directories.
  - Re-architects feature extraction to eliminate ground truth label leakage.
  - Establishes genuine empirical baselines for classical ML and SLM evaluation.
- **Undo / Rollback:**
  - Current synthetic data quarantined safely under `data/invalid_v0/` (git-ignored); zero historical tags or commits deleted.
  - VM state can be rolled back to clean baseline snapshot `snap-s4`.
- **Risk Assessment:**
  - *Risk:* 400 genuine runs including 60 mining runs (120s each) will require ~2.5 to 3.0 hours of total cluster execution.
    *Mitigation:* Batched execution of 50 runs with per-run health checks, memory auto-stop at 85% RAM / 80% disk, and atomic per-run directory writes.
- **Agent Recommendation:** `[RECOMMENDATION] APPROVE A-006`. This plan completely cures the synthetic shortcuts, restores absolute academic integrity, and guarantees verified empirical science.
- **What It Blocks:**
  - All dataset re-generation (Ticket 06a-rem, 06c-rem), classical ML training (Ticket 08-rem), and model evaluation.
