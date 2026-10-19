# TICKET TREE: RuntimeLens Implementation Workflow

**ACTIVE TICKET:** HALTED (Remediation Plan A-006 pending approval; tickets 06a-08 invalidated)

---

## 1. ASCII Dependency Tree

```
[01: Repo Foundation & Secrets CI]
        |
        v
[02a: Lab VM & eBPF Feasibility Gate] -------- (Checkpoint A: Go/No-Go Feasibility)
        |
        v
[02b: Falco, Audit, Namespaces & Workloads]
        |
        v
[03: Minimal Vertical Slice (Syscall -> Audit Record)] -- (Checkpoint B: Scope Re-Check)
        |
        +-----------------------------------+
        |                                   |
        v                                   v
[11: Live API Smoke Test] (PASSED 2026-10-18)   [04: Core Telemetry (Falco + Audit) & Window]
        |                                   |
        |          +------------------------+
        |          |                        |
        |          v                        v
        |  [05: Baseline Loader]    [09a: Raw Capture (Hubble/Prom/Trivy)]
        |          |                        |
        |          +------------+-----------+
        |                       |
        |                       v
        |            [06a: Pilot Run (20-30 runs, 5 sources)] -- (Checkpoint D1: Safety Review BEFORE run)
        |                       |                                 (Checkpoint D2: Pilot Done AFTER run)
        |                       v
        |                       v
        |            [09b: Telemetry Normalizers (Hubble/Prom/Trivy)]
        |                       |
        |                       v
        |            [06b: Pilot Analysis, Power Estimate & Freeze] -- (Checkpoint E: Design Freeze)
        |                       |
        |                       v
        |            [06c: Full 400-Run Live Dataset] ---------- (Checkpoint F: Launch Full Run)
        |                       |
        |                       v
        |            [07: Dataset Split, Leakage Test & Manifest] - (Checkpoint G: Air-Gap Lock)
        |                       |
        |                       | ---> Human Track R2 Round 2 (60-80 Dev incidents, kappa >= 0.80)
        |                       v
        |            [08: Random Forest Baseline & Bootstrap]
        |                       |
        +-----------------------+
        |
        v
[10: ScaleDown Classify-1 Adapter & Mock Tests]
        |
        v
[13a: Pure Deterministic Policy Engine (Overrides & Conflict Table)]
        |
        v  (Checkpoint H: Hard Stop before 12a - R2 Round 2 kappa >= 0.80 verified)
[12a: Dev Tuning, Policy Sweeps & 6 Ablations]
        |
        v
[12b: Adversarial Test Suite]
        |
        v
[12c: Single Held-Out Test Set Evaluation] ------------- (Checkpoint I: Final Test Eval)
        |
        v
[13b: Response Controller (Quarantine & Rollback)] ----- (Checkpoint J: Live Quarantine)
        |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
[14: Prometheus & Grafana]   [15: SRE Extensions]   [16a: Final Report v2] (Checkpoint K)
                                                        |
                                                        v
                                                    [16b: Academic Poster]
                                                        |
                                                        v
                                                    [16c: Live Demo & Runbook]

Non-Agent Human Tracks (Teammates Altaf & Kamal):
  - Track R1: Report/Poster Stage 1 revisions (docs/REPORT_REVISION_CHECKLIST.md)
  - Track R2: Blind Review Round 1 (during 06b) & Round 2 (dev-set immediately after 07, kappa >= 0.80) -> Blocks 12a
    [Rule: Labeling guide clarifications use dev data only; no definitions change after test labels are seen]
```

---

## 2. Strict Linear Execution Queue

All code tickets are implemented strictly **one at a time** (one VM, one cluster, one repo, one API budget) in the following risk-first sequence:

1. **`01`**: Repository Foundation, Secret Scanning & CI Skeleton
2. **`02a`**: VM, kind, Cilium, BTF & eBPF Feasibility Gate *(Checkpoint A)*
3. **`02b`**: Falco, Audit Policy, Tenant Namespaces & Workloads
4. **`03`**: Minimal Vertical Slice: Synthetic Syscall Probe to Tamper-Evident Audit Record *(Checkpoint B - Synthetic Probe Proof)*
5. **`11`**: Live ScaleDown API Smoke Test & Contract Verification *(Checkpoint C - COMPLETED)*
   - *Execution Note:* Executed and PASSED on 2026-10-18 (14 calls executed cleanly). Real fixtures committed in `84adde8`, verified contract documented in `docs/MODEL_API.md`. Key needed again only for Ticket 12a, from a session started by the user in their own terminal.
6. **`04`**: Core Telemetry Ingestion (Live Falco + Audit) & Correlation Window
7. **`05`**: Declarative YAML Baseline Loader & Drift Detector
8. **`09a`**: Raw Telemetry Capture Setup (Hubble, Prometheus, Trivy) [STATUS: NEEDS RE-VERIFICATION]
   - *Ordering Note:* Implemented before any pilot runs so that all five sources are captured raw from the very first cluster execution.
9. **`06a`**: Live Cluster Pilot Scenario Run (20–30 runs across all 5 sources) *(Checkpoints D1 & D2)*
   - *Safety Review Note (Checkpoint D1):* Mandatory stop BEFORE execution to review scenario definitions (dummy runtime socket instead of real host socket, CPU-capped mining with no real pool, scoped roles in lab namespace, automated post-run cleanup).
   - *Resource Measurement Note (Checkpoint D2):* Measures per-run wall time, disk bytes, and RAM usage under sustained-CPU load to establish empirical budgets for 06c.
10. **`09b`**: Telemetry Normalizers & Capture-Sufficiency Audit (Hubble/Prometheus first, Trivy last)
11. **`06b`**: Pilot Power Analysis, CI Width Simulation & Design Freeze *(Checkpoint E)*
    - *Budget Lock Note:* Produces measured time, disk, and RAM budgets for 06c; updates `docs/PREREGISTRATION.md`; reviews R2 Round 1 blind review.
12. **`06c`**: Full Live Cluster Scenario Dataset Generation (400 runs) *(Checkpoint F)*
13. **`07`**: Dataset Partitioning (72/28), Leakage Assertion & Final Baseline Regeneration *(Checkpoint G)*
    - *Human Track R2 Note:* Teammates execute Round 2 blind review on 60–80 stratified Dev incidents immediately following this ticket.
14. **`08`**: Random Forest Classical ML Baseline & Cluster-Aware Bootstrap Harness
15. **`10`**: ScaleDown Classify-1 Adapter, State Hardening & Contract Mock Tests
16. **`13a`**: Pure Deterministic Decision Policy Engine & Conflict Resolution
    - *Ordering Note:* Placed immediately after `10` and before `12a` so confidence-threshold sweeps, review rates, auto-action precision, and risk-coverage curves can be tuned on the Dev set, freezing policy logic before the test evaluation.
17. **`12a`**: Dev-Set Equal-Budget Model Tuning, Policy Sweeps & 6 Systematic Ablations *(Checkpoint H - gated by R2 Round 2 $\kappa \ge 0.80$)*
18. **`12b`**: Adversarial Prompt-Injection Test Suite
19. **`12c`**: Single-Pass Held-Out Test Set Evaluation *(Checkpoint I)*
20. **`13b`**: SRE Response Controller (Label Quarantine, NetworkPolicy, Auto-Rollback) *(Checkpoint J)*
21. **`14`**: Prometheus Metrics Exporter & Operational Observability
22. **`15`**: SRE Extensions: Exposure-Based Risk Score & Human Feedback Diff Loop
23. **`16a`**: Final Academic Report v2 (Measured Results, Confusion Matrices) *(Checkpoint K)*
24. **`16b`**: Academic Poster Redesign & Visual Asset Finalization
25. **`16c`**: Live Lab Demonstration Script (`make demo`) & Viva Runbook

---

## 3. Hybrid Execution Segments & Stop Checkpoints

Inside a segment, when a ticket passes all automated gate checks and real test evidence is recorded, execution may proceed to the next ticket within the same segment. The ticket is marked `GATE REPORT READY` and git is tagged.

**MANDATORY HARD STOP CHECKPOINTS:** The agent MUST STOP and wait for explicit human approval at:
1. **Checkpoint A (after `02a`):** Feasibility gate evaluation; decision to stay on local VM or switch to cloud Linux VM.
2. **Checkpoint B (after `03`):** Scope re-check on the working vertical slice.
3. **Checkpoint C1 & C2 (Ticket `11`):** COMPLETED on 2026-10-18. 14 live calls executed; API contract verified in `docs/MODEL_API.md` and fixtures committed in `84adde8`. (API key needed again only at Ticket 12a via user terminal session).
4. **Checkpoint D1 (before `06a`):** Mandatory safety review of scenario definitions (dummy socket instead of real container socket, CPU-capped mining with no real pool, scoped roles in lab namespace, automatic cleanup). [QUEUED: `A-001` in `docs/APPROVAL_QUEUE.md`]
5. **Checkpoint D2 (after `06a`):** Pilot run capture inspection (verify per-run metrics for time, disk, RAM).
6. **Checkpoint E (after `06b`):** Review power estimate, CI width simulation, empirical 06c resource budget, pre-registration update, and R2 Round 1 blind review.
7. **Checkpoint F (before `06c`):** Approval to launch the long-running 400-run live cluster scenario generation.
8. **Checkpoint G (after `07`):** Verify dataset split hash, air-gap lock, and pre-registration commitment prior to any test access.
9. **Checkpoint H (before `12a`):** Verify Human Track R2 Round 2 blind review passes ($\kappa \ge 0.80$ on Dev data) before starting Dev model tuning and ablations.
10. **Checkpoint I (before `12c`):** Final authorization for the single, one-shot held-out test evaluation pass.
11. **Checkpoint J (before live mode in `13b`):** Authorize live (non-dry-run) Kubernetes label-based quarantine.
12. **Checkpoint K (at `16a`):** Review measured empirical numbers before drafting final academic deliverables.

### Autopilot with an Approval Queue Protocol
1. **Approval Queue (`docs/APPROVAL_QUEUE.md`):** Whenever action requires explicit human approval, append an entry (`A-001`, `A-002`, ...) documenting: Ticket, What, Exact commands, What it changes, Undo, Risk, Agent Recommendation, and What it blocks.
2. **Blocked State & Autonomous Continuation:** Mark the ticket `BLOCKED-ON A-xxx` and continue immediately with any unblocked ticket that does not depend on it.
3. **Digest & Stop:** Stop only when zero unblocked tickets remain; present a digest with recommended answers. The user replies `"APPROVE A-xxx, DENY A-yyy: reason"` which is logged with the date in `docs/APPROVAL_QUEUE.md`.
4. **Work-Ahead Rules:** Work-ahead is permitted exclusively for fully offline tickets (no VM/cluster, no API spend, no dataset generation, no test split) on isolated git branches `ahead/<ticket-id>`, never merged until blocking approvals are answered. Never run two tickets on the VM or cluster at once.
5. **Pre-Approved (Log each):** Local project folder edits, unit tests, commits, tags, local branches; `kubectl`, `helm`, `kind`, `make lab-up/lab-reset/lab-verify` in VM for active ticket; installing documented pinned tools with checksum verification.
6. **Always Queue Instead of Executing:** `git push` or remote changes; any `SCALEDOWN_API_KEY` usage or spend; `sudo` beyond documented installs, chmod, chown, setfacl; `rm -rf`, `multipass delete/purge/stop --all`, `kubectl delete` outside lab namespaces; new paid/external services; 06a scenario safety review; launching 400 runs (06c); design freeze (06b); test split first access (12c); live quarantine (13b); plan/preregistration changes after dev results exist; human tasks (Track R2 review, report text).
7. **Auto-Stop Triggers:** Gate failing after two fix attempts, flaky tests, contradictory docs, VM memory $>85\%$ or disk $>80\%$, unhealthy cluster twice consecutively, anything looking like a secret, anomalous metrics, or urge to bypass rules. Quality is non-negotiable (full reviews, gate reports, and tags required).

### Unscheduled Emergency Stop Triggers
Stop immediately and ask the user before running:
- Any destructive or cluster-wide command (`rm -rf`, `kubectl delete`, namespace deletions, `curl | sh`).
- Any `sudo` command or filesystem modification outside the project root and VM.
- Any invocation of a new paid external service or unapproved API endpoint.
- Any detected gate failure or test assertion error.

| Segment | Segment Name | Tickets Included | Permitted Action Inside Segment | Hard Stop Boundary |
|:---:|:---|:---|:---|:---|
| **S1** | Foundation & Feasibility | `01`, `02a` | Run 01 $\rightarrow$ 02a autonomously if tests pass | **STOP after 02a** (Feasibility review) |
| **S2** | Cluster & Vertical Slice | `02b`, `03` | Run 02b $\rightarrow$ 03 autonomously if tests pass | **STOP after 03** (Scope re-check) |
| **S3** | Live API Verification | `11` | Isolated manual execution | COMPLETED on 2026-10-18 (14 calls verified; fixtures in 84adde8) |
| **S4** | Telemetry Ingestion Setup | `04`, `05`, `09a` | Run 04 $\rightarrow$ 05 $\rightarrow$ 09a autonomously | Run completed; ready for pilot |
| **S5** | Pilot & Design Freeze | `06a`, `09b`, `06b` | Run 06a on approval $\rightarrow$ STOP; then 09b $\rightarrow$ 06b | **STOP before 06a:** Safety review of scenario definitions (dummy sockets, scoped roles, CPU limits, cleanup).<br>**STOP after 06a:** Inspect pilot captures & resource usage.<br>**STOP after 06b:** Review power analysis, empirical budget & design freeze. |
| **S6** | Live Dataset Generation | `06c`, `07` | Launch 06c on approval $\rightarrow$ 07 | **STOP before 06c:** Authorize 400 live runs.<br>**STOP after 07:** Verify air-gap, manifest hash, and final baselines. |
| **S7** | Dev Models & Policy Engine | `08`, `10`, `13a` | Advance 08 $\rightarrow$ 10 $\rightarrow$ 13a autonomously | **STOP before 12a:** Verify R2 Round 2 kappa ($\ge 0.80$) on Dev data. |
| **S8** | Dev Tuning & Ablations | `12a`, `12b` | Advance 12a $\rightarrow$ 12b on Dev split | **STOP before 12c:** Authorize final test evaluation. |
| **S9** | Final Evaluation & Actuation | `12c`, `13b` | Run 12c on approval $\rightarrow$ test 13b (dry-run) | **STOP before live quarantine** in 13b. |
| **S10** | Observability & Extensions | `14`, `15` | Run 14 $\rightarrow$ 15 autonomously | Observability & extensions ready. |
| **S11** | Academic Deliverables | `16a`, `16b`, `16c` | Advance 16a on approval $\rightarrow$ 16b $\rightarrow$ 16c | **STOP at 16a:** Sign off on measured empirical numbers. |

---

## 4. Master Ticket Registry

| ID | Title | Blocked By | Unblocks | Entry Condition | Key Deliverables | Exit Gate Verification (Commands & Evidence) | Safety Checks | Cut Priority | Status |
|:---:|:---|:---:|:---:|:---|:---|:---|:---|:---:|:---:|
| **`01`** | Repo Foundation, Secrets CI & Skeleton | None | `02a`, `11` | Clean workspace | Python 3.12 `uv` package, `.gitignore`, pre-commit hooks, property-based sanitizer test, offline CI | `make lint`, `make typecheck`, `pytest tests/unit/test_sanitizer.py`; attempt to commit fake `.env` fails; CI passes | Zero secrets logged; CI 100% offline | Mandatory | APPROVED |
| **`02a`** | Lab VM & eBPF Feasibility Gate | `01` | `02b` | `01` passed; host macOS ready | Ubuntu 24.04 VM (4 vCPU, 6 GB), `kind`, Cilium CNI, BTF verification | `/sys/kernel/btf/vmlinux` present; `cilium status --wait` healthy; clean VM snapshot `snap-02a` | Bind 127.0.0.1; VM RAM capped at 6 GB | Mandatory | APPROVED |
| **`02b`** | Falco, Audit, Namespaces & Workloads | `02a` | `03`, `09a` | `02a` approved | Falco with modern eBPF, K8s audit policy, 3 tenant namespaces, 4 ARM64 workloads, `make lab-up/lab-verify` | `make lab-verify` passes; test syscall alert received by webhook; default-deny NetworkPolicies active | Verify `context == kind-runtimelens`; PSS enforced | Mandatory | APPROVED |
| **`03`** | Minimal Vertical Slice (Synthetic Probe -> Audit) | `02b` | `04`, `11` | `02b` passed | Webhook receiver, CanonicalEvent v1.0.0, minimal rules, policy engine, tamper-evident audit writer | Synthetic test event (`curl/test-event -> webhook -> audit log -> HMAC verify`; zero real tenant pod execution) produces validated audit JSONL record with hash-chain in $<2$s | Dry-run default; verify schema forbidding extra fields | Mandatory | APPROVED (SYNTHETIC PROBE ONLY) |
| **`11`** | Live API Smoke Test & Contract Verification | `01`, `03` | `10` | Executed 2026-10-18 | `make test-live-api` target, real API contract validation, Score formula verification, fixture capture | `RUN_LIVE_API_TESTS=1 pytest tests/live/test_smoke.py`; 14 live calls passed, contract in docs/MODEL_API.md, fixtures in 84adde8 | Hard cap 20 requests; zero key logging; synthetic only | Mandatory | PASSED |
| **`04`** | Core Telemetry (Falco + Audit) & Window Buffer | `03` | `05`, `09a` | `03` passed | Live Falco + Audit collectors, secret redactors, bounded buffers, $\pm 30$s window correlation (unit-tested on fixtures, not run on live events) | `pytest tests/integration/test_correlation.py`; multi-source incident aggregation unit-tested on fixtures, not run on live events | Redact secrets before queue; drop counter active | Mandatory | APPROVED |
| **`04-live`** | Live Multi-Source Correlation Wiring | `04`, `09b` | `13a` | 04 passed | Wire live Falco webhook and K8s audit webhook streams simultaneously into CorrelationBuffer daemon | Real live exec triggers correlated live audit record joining syscall with orchestration context | Dry-run default | Mandatory | PENDING |
| **`05`** | Declarative YAML Baselines & Drift Detector | `04` | `06a`, `10` | `04` passed | Baseline YAML loader, profiles for 4 workloads from observation runs, deterministic drift comparator | `pytest tests/unit/test_baseline.py`; unauthorized binary triggers `baseline_deviation_detected=True` | Zero auto-learning; baselines read-only | Mandatory | APPROVED |
| **`09a`** | Raw Telemetry Capture Setup (Hubble/Prom/Trivy) | `02b`, `04` | `06a` | `02b`, `04` passed | Append-only rotated JSONL capture for Hubble flows, Prometheus CPU/mem scraper, Trivy CLI scanner | `make capture-check`; sample flows, metrics, and image scan hashes recorded in `data/raw/` | Size-capped rotated files; zero packet leaks | Mandatory | NEEDS RE-VERIFICATION |
| **`06a`** | Live Cluster Pilot Scenario Run | `05`, `09a` | `09b`, `06b` | `05`, `09a` passed; User safety approval | 20–30 live cluster runs across all 5 classes, capturing all 5 sources raw; measure per-run wall time, disk, RAM | `make run-pilot`; all pilot runs complete; zero orphaned pods; raw captures present; resource log saved | Hard stop before run: review dummy socket, scoped roles, CPU-capped mining, cleanup after every run | Mandatory | INVALIDATED (2026-10-18) |
| **`09b`** | Telemetry Normalizers & Sufficiency Audit | `06a` | `06b`, `12a` | `06a` passed | Hubble flow and Prometheus normalizers (Trivy last); capture-sufficiency verification script | `python -m runtimelens.audit_capture --pilot`; 100% of required feature fields present in pilot events | Explicit missing flags; no false claims of zero activity | Trivy normalizer dropped 4th if short | NEEDS RE-VERIFICATION |
| **`06b`** | Pilot Analysis, Power Estimate & Freeze | `06a`, `09b` | `06c` | Pilot data & normalizers ready | Power/variance simulation using rules proxy; CI width estimate; measured 06c time/disk/RAM budget; update preregistration; R2 Round 1 | `python -m runtimelens.eval.pilot_power`; CI width $\le \pm 0.08$ confirmed; empirical 06c budget logged; R2 Round 1 logged | Freeze test protocol; mark exploratory if underpowered | Mandatory | INVALIDATED (2026-10-18) |
| **`06c`** | Full Live Cluster Scenario Dataset (400 Runs) | `06b` | `07` | User approval; freeze complete | 400 live cluster runs (60 esc, 60 prv, 60 cry, 40 unk, 180 ben) across 5 seeds; 3 paired families; atomic run manifest with resume support; automatic cleanup; adhering to 06b resource budget | `make run-dataset`; 400 runs complete; ground truth & phase tags assigned; raw logs verified; resume verified; resource budget respected | CPU-capped stress-ng; dummy endpoints; lab namespaces; automatic cleanup after every run | Mandatory | INVALIDATED (2026-10-18) |
| **`07`** | Dataset Split, Leakage Test & Manifest Hash | `06c` | `08` | `06c` passed | Grouped 72/28 split by run/variant; `manifest_v1.json` with SHA-256; automated CI leakage test; final baselines | `pytest tests/unit/test_leakage.py`; split manifest committed; zero test runs contribute to baselines | Air-gap test split; test access logged | Mandatory | INVALIDATED (2026-10-18) |
| **`08`** | Random Forest Baseline & Bootstrap Harness | `07` | `10`, `12a` | `07` passed | Feature extraction pipeline; scikit-learn Random Forest on Dev split; cluster-aware bootstrap (1k runs) | `python -m runtimelens.eval.train_rf`; cross-validated Macro-F1 and 95% bootstrap CIs generated on Dev | Scalers fit strictly on train split; zero test leakage | Mandatory | INVALIDATED (2026-10-18) |
| **`10`** | ScaleDown Adapter, State Hardening & Mocks | `11`, `04`, `05`, `08` | `13a` | `11` contract verified; `08` ready | `/v1/scaledown` client, delimited state serializer, response caching, offline contract test suite | `pytest tests/contract/test_scaledown_adapter.py`; all recorded fixtures pass offline with zero network calls | Secret redaction; sanitize & truncate to 128 chars | Mandatory | PASSED |
| **`13a`** | Deterministic Decision Policy Engine | `10` | `12a` | `10` passed | Pure policy function: safety overrides, Choice-Noul conflict table, calibrated confidence gates (0.70 default) | `pytest tests/unit/test_policy.py`; exhaustive test of conflict matrix and safety overrides passing | Safety overrides strictly force alert/review | Mandatory | PASSED |
| **`12a`** | Dev-Set Equal-Budget Tuning & 6 Ablations | `08`, `10`, `13a`, `09b` | `12b` | `13a` passed; R2 Round 2 kappa $\ge 0.80$ | Equal-budget dev tuning of Rules, RF, ScaleDown; 6 ablations (Primary: Baseline on/off); policy sweeps | `python -m runtimelens.eval.run_ablations --split dev`; ablation tables and reliability curves generated | Strictly zero test-set access; Holm-Bonferroni correction | Mandatory | BLOCKED (Awaiting Remediation) |
| **`12b`** | Adversarial Prompt-Injection Test Suite | `10`, `12a` | `12c` | Adapter & Dev models ready | Adversarial evaluation harness testing prompt injections across args/labels under 4 defense combinations | `python -m runtimelens.eval.adversarial`; Attack Success Rate reported with/without sanitization & overrides | Text-only attacks; zero real exploits | Mandatory | INVALIDATED CLAIM (2026-10-18) |
| **`12c`** | Single Held-Out Test Set Evaluation | `12a`, `12b` | `13b`, `16a` | User approval; R2 passed | Single evaluation pass on frozen test split (112 runs); cluster-aware bootstrap CIs; pre-registered hypothesis test | `python -m runtimelens.eval.run_final_test`; test access logged; primary CI evaluated; git tag `evaluation-frozen-v1` | One-shot evaluation; zero post-test parameter tuning | Mandatory | NOT STARTED |
| **`13b`** | SRE Response Controller (Quarantine & Rollback) | `12c` | `14`, `15`, `16c` | `12c` passed | Response controller patching `quarantine=true`; pre-installed NetworkPolicy; 15m TTL rollback; RBAC zero delete | `pytest tests/integration/test_quarantine.py`; `kubectl auth can-i delete pods` returns `no`; TTL rollback verified | Zero pod delete verb anywhere; dry-run default | Live quarantine dropped 3rd if short | NOT STARTED |
| **`14`** | Prometheus Metrics Exporter & Observability | `13b` | `16c` | `13b` passed | Prometheus exporter on port 9090 (latencies, class counts, drops; ECE excluded); Grafana dashboard JSON | `curl -s 127.0.0.1:9090/metrics | grep runtimelens`; Grafana dashboard renders without errors | Low memory footprint; no ELK/Kafka | Dashboards dropped 2nd if short | NOT STARTED |
| **`15`** | SRE Extensions: Risk Score & Feedback Loop | `13b` | None | `13b` passed | Deterministic exposure-based risk scoring; analyst review CLI (`review.py`) generating Dev baseline Git diffs | `python -m runtimelens.review --generate-diff`; valid YAML diff generated for Dev split baseline | Dev split only; test baselines strictly root-owned and tamper-evident | Dropped 1st if short | NOT STARTED |
| **`16a`** | Final Report v2 with Measured Findings | `12c` | `16b` | User approval; `12c` complete | Final Report v2 in `docs/report/final_report.pdf` with measured Macro-F1, bootstrap CIs, confusion matrices | Report compiles cleanly; all worked examples marked ILLUSTRATIVE; limitations and findings disclosed | Disclose synthetic lab nature; faculty guide informed | Mandatory | NOT STARTED |
| **`16b`** | Academic Poster Redesign | `16a` | `16c` | `16a` passed | Updated architecture poster graphic with ScaleDown branding, tenant names, and design-only termination | High-resolution poster image exported; team review complete | Remove Jev branding; flag termination as design-only | Mandatory | NOT STARTED |
| **`16c`** | Live Demonstration Script & Viva Runbook | `13b`, `14`, `16a` | None | `13b`, `14`, `16a` passed | 5-minute live demo script (`make demo`); operator runbook; viva defense question/answer guide | `make demo` runs cleanly in $<5$ minutes on clean cluster; team completes simulated viva rehearsal | Idempotent cleanup after demo run | Mandatory | NOT STARTED |
| **`06d`** | Report/Implementation Delta Log & Scenario Plan v2 Design | `03` (corrected status) | `06c`, `16a` | Stage 3 accepted (2026-10-19) | `docs/REPORT_DELTA.md` cataloguing all 55+ Jev-vs-ScaleDown discrepancies and 8 other implementation divergences; `docs/SCENARIO_PLAN_v2.md` defining 50 anti-shortcut templates for the proposed 400-run dataset | `wc -l docs/REPORT_DELTA.md docs/SCENARIO_PLAN_v2.md`; every report/poster section carrying Jev catalogued; per-class template counts and CPU profiles listed | No report file edited; nothing frozen; zero cluster runs; test split untouched | Mandatory | IN REVIEW (NOT FROZEN) |

---

## 5. Scope-Shedding & De-Scoping Protocol

If project deadlines compress, scope is shed strictly in the following predefined order, ensuring the primary research claim and core evaluation are never compromised:

1. **Drop `15` (SRE Extensions):** Omit exposure risk score and human feedback diff generator.
2. **Drop `14` (Grafana Dashboards):** Retain lightweight Prometheus metrics exporter; drop Grafana dashboard JSON.
3. **Drop Live Quarantine in `13b`:** Retain full dry-run quarantine Diff logging and NetworkPolicy manifests; omit live active controller actuation.
4. **Drop Trivy Normalizer in `09b`:** Keep raw Trivy scans in `09a`; omit static CVE feature extraction from the final multi-source vector.

*Never Dropped Under Any Circumstances:* `01`, `02a`, `02b`, `03`, `04`, `05`, `09a`, `06a`, `09b` (Hubble and Prometheus normalizers are never dropped), `06b`, `06c`, `07`, `08`, `10`, `11`, `13a`, `12a`, `12b`, `12c`, `16a`, `16b`, `16c`.

---

## 6. How to Work Through This File

1. **One Active Ticket:** The agent works on strictly one ticket at a time in the exact linear queue order.
2. **Entry Condition Check:** Before beginning a ticket, verify that all dependencies in `Blocked By` are marked `APPROVED` (or `GATE REPORT READY` within the same segment) and that the ticket's specific entry condition is satisfied.
3. **Gate Report Generation:** Upon completing a ticket's implementation and verification:
   - Run the exact exit gate commands.
   - Capture real terminal output, execution timestamps, and Git commit hash.
   - Append the gate evidence to `docs/GATE_REPORTS.md`.
   - Create an annotated Git tag: `git tag -a <ticket_id>-passed -m "Pass gate <ticket_id>"`.
   - Update `docs/TICKET_TREE.md` marking the ticket status `GATE REPORT READY` (or `APPROVED` if user confirmed).
4. **Automated Verification Runner:** Maintain and run `make verify-gates` to re-execute all previously completed gate checks, ensuring zero regressions.
5. **Handling Checkpoints:** When a ticket ends at a designated Stop Checkpoint, update the status, report the gate evidence, and **WAIT** for the user's explicit authorization before advancing to the next segment.
6. **Air-Gap Invariant:** Under no circumstances may code access or evaluate `datasets/splits/held_out_test.jsonl` prior to the authorized execution of Ticket `12c`.
7. **Secrets Invariant:** Never open, read, echo, log, or commit `.env` or API key files.
