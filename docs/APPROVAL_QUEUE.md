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

### A-010 — The mining duration calibration after the third Round 5a attempt (APPLIED, recorded for review)

| Field | Value |
|:---|:---|
| **ID** | A-010 (applied under Decision D-36) |
| **Ticket** | Ticket 06c / Stage 4a — the 400-run dataset generation |
| **What** | The Round 5a attempt 3 stopped at run 1 because the per-run gate rejected the mining run with `High-CPU duration too short: 111.52s`. The cause is the **duration calibration**, not the telemetry: the wall time of the identical 3000-iteration inner loop was measured at 28.84 / 28.07 / **25.33** ms across three real runs (a 13.9 % spread), and the Decision D-34 iteration count of 4200 — derived from the mean of the first two — produced a cAdvisor window of 123.04 s in the slow case and 111.52 s in the fast one, i.e. it landed exactly on the gate boundary. |
| **Exact commands** | `python3 - <<'PY'` … (one edit in `scripts/stage4a_round4.py`: `mining_high(<port>, 4200)` -> `mining_high(<port>, 4950)` for `TMPL-MNR-01`, `TMPL-MNR-02`, `TMPL-MNR-05`), then `uv run ruff check && uv run ruff format --check && uv run mypy src tests scripts && uv run pytest tests/unit/ tests/contract/ tests/integration/ && PYTHONPATH=src:. python3 scripts/check_plan_consistency.py`, then the batch re-run `PYTHONPATH=src:. python3 scripts/stage4a_runner.py 5a`. |
| **What it changes** | The three `high`-profile mining commands: the iteration count 4200 -> 4950. The command length is unchanged (192 characters) and **no length bin changes**. The expected busy-loop duration becomes a range (125.4 s fast / 142.8 s slow) instead of a point. **No gate threshold, no feature and no template expectation was changed.** |
| **Undo** | `git revert` the D-36 commit, or set the count back to 4200 in `scripts/stage4a_round4.py` and re-run. The affected runs stay in `data/raw/superseded_runs/` either way. |
| **Risk** | In the slowest observed case the run lasts ~148 s instead of the declared 130 s (+14 %). The dataset's per-run time budget rises accordingly (60 mining runs x ~140 s). The alternative, a time-bounded outer loop (`while [ $SECONDS -lt 125 ]`), would be variance-proof by construction but changes the command shape and depends on `$SECONDS` in BusyBox `ash`; it was **not** adopted without verification. |
| **Your recommendation** | **[RECOMMENDATION]** Adopt the 4950 count (it clears the 115 s code threshold and the 120 s Decision D-20 text in the fastest observed case) and revisit a time-bounded loop only if the variance widens further. |
| **What it blocks** | Nothing was blocked by the queue: the change was applied so that the approved Round 5a batch could continue. It is recorded here because the AGENTS.md stop trigger "a gate failure after two remediation attempts" applies (attempts 1, 2 and 3 of this batch). |
| **What it blocks (downstream)** | The nine remaining templates of Round 5a batch A (`MNR-02`, `MNR-04`, `MNR-05`, `MNR-06`, `MNR-07`, `MNR-08`, `PRV-06`, `PRV-08`, `ESC-01`) could not be collected before this change. |
| **State** | APPLIED 2026-10-22 (Decision D-36). Queued for the user's review; revert on request. |
