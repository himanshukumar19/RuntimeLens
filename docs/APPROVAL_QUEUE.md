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
| *(Pending)* | A-002 | 06a | PENDING | Final Authorization for Ticket 06a Live Pilot Scenario Execution (25 runs). |

---

## Active Approval Items

### Entry `A-002` — Final Authorization for Ticket 06a Live Pilot Scenario Execution

- **Queue ID:** `A-002`
- **Ticket ID:** `06a` (Live Cluster Pilot Scenario Run)
- **Status:** `PENDING HUMAN AUTHORIZATION`
- **What:** Authorize executing the 25 live cluster pilot scenario runs across 5 threat classes and 3 paired counterfactual families inside `runtimelens-vm` kind cluster under revised `docs/SCENARIO_SAFETY_SHEET.md`.
- **Specification Document:** `docs/SCENARIO_SAFETY_SHEET.md` (Revised)
- **Exact Commands:**
  ```bash
  # Executed inside runtimelens-vm:
  cd /home/ubuntu/RuntimeLens
  make lab-verify
  uv run python -m runtimelens.scenarios.runner --pilot --runs 25 --raw-dir data/raw
  make capture-check
  ```
- **What It Changes:**
  - Schedules 25 live runs across `tenant-a`, `tenant-b`, and `tenant-c` with neutral workload names (`worker-task-*`, `service-agent-*`, `sync-collector`).
  - Generates authentic eBPF syscalls, K8s API audit logs, Hubble network flows, and Prometheus cAdvisor resource time series.
  - Appends unmanipulated raw data to `data/raw/{falco,audit,hubble,prometheus,trivy}/events_raw.jsonl` (git-ignored).
  - Measures empirical per-run wall time, disk bytes, and RAM consumption in `data/scenarios/pilot_metrics.json` to calibrate 06c budgets.
- **Undo / Rollback:**
  - Pre-flight and post-flight sweeps clean all test resources matching `runtimelens.test=true`.
  - Full system rollback to snapshot **`snap-s4`**:
    ```bash
    multipass restore runtimelens-vm.snap-s4
    ```
    *Restore impact:* Preserves 100% of S4 deliverables; drops only ephemeral pilot test data.
- **Risk Assessment:**
  - *Risk:* Sustained CPU load for 2 minutes during 3 cryptomining runs.
    *Mitigation:* Capped to 50% CPU limit on 1 core (`limits.cpu: 500m`); memory auto-stop triggers at $\ge 85\%$ RAM; disk auto-stop at $\ge 80\%$.
  - *Risk:* Telemetry or event loss.
    *Mitigation:* Bounded buffers and drop counters active in collectors.
- **Agent Recommendation:** `[RECOMMENDATION] APPROVE A-002`. All 6 feedback items from A-001 review are fully incorporated.
- **What It Blocks:**
  - Ticket `06a` (Pilot Run).
  - Ticket `09b` (Telemetry Normalizers & Capture-Sufficiency Audit).
  - Ticket `06b` (Pilot Power Analysis, CI Width Simulation & Design Freeze - Checkpoint E).
  - Ticket `06c` (Full 400-Run Live Cluster Scenario Generation).
