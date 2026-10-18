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

### Entry `A-005` — Checkpoint H: Human Track R2 Round 2 Blind Review Verification & Dev Tuning Authorization (Ticket 12a)

- **Queue ID:** `A-005`
- **Ticket ID:** `12a` (Dev-Set Equal-Budget Model Tuning, Policy Sweeps & 6 Systematic Ablations)
- **Status:** `PENDING HUMAN INPUT & AUTHORIZATION`
- **What:** Verify that teammates Altaf and Kamal have completed the Human Track R2 Round 2 blind review on 60–80 stratified Dev split incidents with inter-annotator agreement meeting or exceeding the pre-registered threshold ($\kappa \ge 0.80$), and authorize beginning Ticket 12a Dev model tuning and ablations with `SCALEDOWN_API_KEY` provided via user-initiated terminal session.
- **Specification Document:** `docs/LABELING_GUIDE.md` (Section 4) & `docs/PREREGISTRATION.md`
- **What It Changes:**
  - Unblocks model tuning on the 72% Development split (288 runs).
  - Evaluates the 6 pre-registered systematic ablations (Primary: Baseline on/off).
  - Tunes confidence thresholds and risk-coverage curves on Dev data.
- **Undo / Rollback:**
  - Test set remains 100% untouched and air-gapped; all tuning affects only Dev artifacts.
- **Risk Assessment:**
  - *Risk:* Proceeding to model tuning before annotator agreement is confirmed risks tuning against ambiguous or biased labels.
    *Mitigation:* Checkpoint H hard stop mandates verified $\kappa \ge 0.80$ before any model parameters or confidence thresholds are fitted.
- **Agent Recommendation:** `[RECOMMENDATION]` Awaiting user input reporting the measured Cohen's kappa $\kappa$ from Altaf and Kamal's Round 2 review. If $\kappa \ge 0.80$, `APPROVE A-005`.
- **What It Blocks:**
  - Ticket `12a` (Dev-Set Equal-Budget Tuning & 6 Ablations).
  - Ticket `12c` (Single Held-Out Test Set Evaluation - Checkpoint I).
