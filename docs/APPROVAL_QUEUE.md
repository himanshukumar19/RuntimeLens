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
| 2026-10-19 | A-006 | 06a-08 Rem | APPROVED | Approved: Comprehensive 5-pillar dataset and pipeline remediation plan. Stage 0 (doc/node sanitation) and Stage 1 (proof runs + verify_dataset.py gate) verified clean; Stage 2 (real 25-run pilot) authorized with staged ramp. |

---

## Active Approval Items

### Entry `A-007` — Host macOS Routing and Multipassd Service Kickstart

- **Queue ID:** `A-007`
- **Ticket ID:** `Stage 2 Pilot Execution`
- **Status:** `PENDING HUMAN EXECUTION & CONFIRMATION`
- **What:** Authorize executing host routing additions and multipass daemon kickstart on macOS to resolve `ssh connection failed: 'Failed to connect: No route to host'`. The Multipass VM (`runtimelens-vm`) reports 3 internal IPs (`192.168.252.2`, `172.17.0.1`, `172.18.0.1`). When `multipassd` attempts to reach the Docker/Kind bridge subnets (`172.17.0.0/16`, `172.18.0.0/16`), macOS attempts to route them to the external Wi-Fi gateway (`10.0.0.2`), which fails. Adding static routes directed to `192.168.252.2` and kickstarting `multipassd` restores immediate, reliable communication.
- **Exact commands:**
  ```bash
  sudo route -n add 172.17.0.0/16 192.168.252.2
  sudo route -n add 172.18.0.0/16 192.168.252.2
  sudo launchctl kickstart -k system/com.canonical.multipassd
  ```
- **What It Changes:**
  - Adds two host static routes directing Docker/Kind bridge subnets to the Multipass VM adapter `192.168.252.2`.
  - Restarts `com.canonical.multipassd` daemon cleanly.
- **Undo / Rollback:**
  ```bash
  sudo route -n delete 172.17.0.0/16 192.168.252.2
  sudo route -n delete 172.18.0.0/16 192.168.252.2
  ```
- **Risk Assessment:**
  - *Risk:* Negligible. Subnets `172.17.0.0/16` and `172.18.0.0/16` are private non-routable container networks used exclusively by Docker/Kind inside the VM.
- **Agent Recommendation:** `[RECOMMENDATION] APPROVE A-007`. Execute the exact commands so `multipass exec` can reach the VM without packet drops.
- **What It Blocks:**
  - Stage 2 25-run pilot execution and all subsequent live cluster operations.
