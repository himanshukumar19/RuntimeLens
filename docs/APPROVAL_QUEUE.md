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
| 2026-10-19 | A-007 | VM Conn | RESOLVED (DIAGNOSED) | User executed routes and daemon kickstart. Network diagnostics confirmed /usr/bin/ssh and /usr/bin/nc connect to 192.168.252.2:22 with 100% success; multipass CLI binary is blocked by macOS Local Network privacy sandbox. Resolution via native Apple OpenSSH identity key (A-008). |
| 2026-10-19 | A-008 | SSH Key Extraction | DENIED | Denied by user. User confirmed `multipass exec` works directly from their own Terminal. Zero private keys to be copied and zero sudo commands to be used. |

---

## Active Approval Items

*(No active approval items pending.)*

---

## Deferred Items — explicitly postponed by user decision, not awaiting an answer

### A-009 — Live webhook secrets and correlation wiring (DEFERRED, after the dataset)

| Field | Value |
|:---|:---|
| **ID** | A-009 (deferred) |
| **Ticket** | Ticket 10 (vertical slice) / Ticket 03 follow-up — live alert-to-audit correlation |
| **What** | The live `Falco -> webhook -> HMAC audit record` pipeline and the `kube-apiserver -> audit webhook` pipeline are non-functional: both receivers refuse every request because their shared secrets are not in their environments. The two **environment variable names** are `FALCO_WEBHOOK_SECRET` (expected by `src/runtimelens/collector/webhook.py:46`) and `K8S_AUDIT_WEBHOOK_SECRET` (expected by `src/runtimelens/collector/audit_webhook.py:45`). The values must come from: (a) the `bearerToken` entry of `/etc/kubernetes/policies/audit-webhook.yaml` on the VM (root-only, mode 0600) for the audit receiver, and (b) the `token=` query parameter of `falco.http_output.url`, currently the placeholder `REDACTED_WEBHOOK_TOKEN` in the committed `lab/falco/falco-values.yaml`, for the Falco receiver. |
| **Exact commands** | **NOT RUN — the verbatim command list is withheld from execution and will be written out for review when this item is approved.** The procedure has four steps: (1) read the root-only apiserver webhook config to obtain the audit `bearerToken`; (2) write the secret into a 0600 file **outside** the repository; (3) restart `lab/run_webhook.py` and `lab/run_audit_webhook.py` with the secret in their environment; (4) `helm upgrade` the Falco daemonset with a matching `falco.http_output.url` token through a **non-git-tracked** values override. Step 1 needs `sudo` and step 4 restarts the Falco pod, which is why the whole item is deferred rather than executed. |
| **What it changes** | Creates a 0600 secret file outside the repository, restarts the two webhook receiver processes with the secret in their environment, and re-deploys the Falco daemonset with a matching token via a **non-git-tracked** Helm values override. No repository file would ever contain a real secret. |
| **Undo** | `pkill -f 'lab/run_webhook.py'; pkill -f 'lab/run_audit_webhook.py'` (stops the receivers) and `helm upgrade falco … -f lab/falco/falco-values.yaml` (restores the placeholder token). Delete the 0600 secret file. |
| **Risk** | The `helm upgrade` briefly restarts the Falco daemonset, which would interrupt telemetry capture; the receivers log to `/tmp/falco_webhook.log` and `/tmp/audit_webhook.log`. Reading the root-only apiserver config requires `sudo`, which is outside the currently approved operations. A token mismatch would leave the pipeline in the same refusing state (no worse than now). |
| **Recommendation** | **[RECOMMENDATION]** Defer until after the 400-run dataset is collected. The per-run capture path is **not** affected: `capture_falco_alerts` reads the Falco **pod log** (`kubectl logs -n falco`), not the webhook, and every run of the current corpus captured its Falco events normally. The live correlation path is a separate deliverable and must not consume a dataset-collection window. |
| **What it blocks** | The live `Falco -> webhook -> HMAC audit record` demo of the vertical slice, and the audit-webhook ingestion path used by the live correlation demo. It blocks **no** dataset run. |
| **State** | DEFERRED BY USER DECISION (2026-10-22): "Webhook restart: NOT approved now (needs sudo and a secret copy, and a Falco redeploy would interrupt capture). Log it as a deferred ticket 'live webhook secrets and correlation wiring', for after the dataset." |
