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

---

## Active Approval Items

### Entry `A-003` — Checkpoint E: Design Freeze & Launch Authorization for Full 400-Run Dataset (Ticket 06c)

- **Queue ID:** `A-003`
- **Ticket ID:** `06b` / `06c` (Design Freeze & Full Live Dataset Generation)
- **Status:** `PENDING HUMAN AUTHORIZATION`
- **What:** Authorize formal Design Freeze (Checkpoint E) and approve launching Ticket 06c (Full 400-Run Live Cluster Scenario Generation) inside `runtimelens-vm` kind cluster under the empirical resource budget measured in Ticket 06b.
- **Specification Document:** `docs/PREREGISTRATION.md` (Updated) & `docs/SCENARIOS.md`
- **Exact Commands:**
  ```bash
  # Inside runtimelens-vm:
  cd /home/ubuntu/RuntimeLens
  make lab-verify
  uv run python -m runtimelens.scenarios.runner --stage full-400 --raw-dir data/raw
  make capture-check
  ```
- **What It Changes:**
  - Schedules 400 live cluster runs across 5 threat classes (60 escape, 60 privilege, 60 mining, 40 unknown, 180 benign) and 3 paired families with neutral workload names.
  - Generates full raw telemetry across all 5 sources (`data/raw/`) to support all subsequent feature extraction, RF training, and evaluation without regenerating.
  - Maintains resumable run state manifest in `data/scenarios/run_checkpoint.json`.
- **Empirical Measured Budgets (from Ticket 06b):**
  - Active execution wall time: **22.3 minutes** (~0.4 hours).
  - Recommended operational envelope (with buffer): **27.9 minutes** (~0.5 hours).
  - Peak VM RAM: **25.2%** (1.46 GiB, headroom > 4.3 GiB, far below 85% limit).
  - Disk growth: **~0.57 MB** (31.0 GiB free space available).
  - Statistical power: **1.0** (exceeds 0.80 threshold); 95% bootstrap CI half-width = $\pm 0.0135$ ($\le \pm 0.08$).
- **Undo / Rollback:**
  - Guaranteed idempotent pre/post-flight cleanup for all runs.
  - Complete rollback to pre-dataset baseline snapshot **`snap-s4`** via `multipass restore runtimelens-vm.snap-s4`.
- **Risk Assessment:**
  - *Risk:* 400 sequential container runs over ~28 minutes could accumulate orphaned resources if interrupted.
    *Mitigation:* Resumable state manifest (`run_checkpoint.json`), pre-flight sweep at start of every run, exit trap on signals, and memory auto-stop at $\ge 85\%$ RAM.
- **Agent Recommendation:** `[RECOMMENDATION] APPROVE A-003`. All pre-registered requirements for statistical power and empirical resource limits are satisfied.
- **What It Blocks:**
  - Ticket `06c` (Full 400-Run Live Cluster Scenario Generation).
  - Ticket `07` (Dataset Partitioning, Leakage Test & Manifest Hash).
  - Human Track R2 Round 2 blind review.
