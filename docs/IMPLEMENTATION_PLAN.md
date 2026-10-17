# IMPLEMENTATION PLAN: Phases, Exit Gates & Risk Management

## 1. Governance, Operational Model (Mode A) & Scope Shedding Order
- **Governance & Mode A Protocol:**
  - **Technical Lead & Sole Human Operator:** Himanshu Kumar.
  - **Pair-Programming Agent Role (Mode A):** The agent writes all implementation code, unit/integration tests, Kubernetes manifests, and automation scripts under Himanshu's explicit direction.
  - **Human Verification & Approval:** Himanshu reviews the code, executes all phase gate tests personally, inspects the saved output/evidence, and explicitly approves advancement to the next phase.
  - **Operational Rules:**
    1. *Pause at Every Gate:* The agent must pause and wait for explicit human approval before advancing across any phase gate.
    2. *Verified Evidence Required:* Never mark a gate passed without a real execution and saved terminal/test evidence.
    3. *Plain-Language Summary:* After each phase, the agent provides a concise plain-language summary explaining what was built, why it was designed that way, and its known limitations.
    4. *Atomic Tagged Commits:* Git commits must remain small and atomic, tagged at each verified phase gate (e.g. `phase-0-passed`, `phase-1-passed`).
- **Academic & Documentation Support:** Altaf Raja & Kamal Nayan Kumar (Report v2 revisions, poster redesign, labeling blind reviews, README testing).
- **Data Origin & Ordering Invariant:**
  - All dataset events originate from **live Kubernetes laboratory cluster scenario runs** capturing real Falco eBPF syscalls, K8s API audit logs, Cilium/Hubble network flows, Prometheus container resource metrics, and Trivy static image scans—not a synthetic mock generator.
  - **Raw Ingestion from Run 1:** Raw telemetry from **all five sources** is captured and archived from the very first run. While normalizers and feature extractors for Hubble, Prometheus, and Trivy may be implemented later (Phase 6), the raw multi-source data is captured upfront so that **the 400-run dataset never needs to be regenerated**.
  - **Pilot & Design Freeze:** A pilot of **20–30 runs** is conducted prior to executing the 400-run dataset. Scenarios and capture design are permanently frozen after the pilot.
- **Critical Path:**
  $$\text{Lab Rebuild} \longrightarrow \text{5-Source Raw Capture \& Core Normalizer} \longrightarrow \text{Pilot (20--30 runs) \& Freeze} \longrightarrow \text{400 Runs Capture} \longrightarrow \text{Classifiers} \longrightarrow \text{Evaluation}$$
  *The core research claim (evaluating baseline context impact via paired comparison) must NEVER be dropped.*
- **Predefined Scope Shedding Order (Lowest Priority First):**
  1. Extension 5 (Human feedback loop diff generation)
  2. Extension 4 (Exposure-based risk score)
  3. Live quarantine enforcement (retain dry-run)
  4. Grafana dashboards (retain Prometheus metrics export)
  5. Hubble network normalizer/features (retain raw Hubble capture + Falco + Audit)
  6. Trivy vulnerability normalizer/features (retain raw Trivy reports)

---

## 2. Phased Roadmap & Hard Exit Gates

### Phase 0: Repository Invariants, Secrets Management & Docs
- **Owner:** Himanshu (Mode A: Agent writes configs/scripts, Himanshu reviews & runs)
- **Build:**
  - Initialize Git repo, `.gitignore` (blocking `.env`, `*.key`, `data/raw/`, `datasets/splits/`).
  - Pre-commit hooks (`ruff`, secret scanning, large-file checks).
  - Pinned `.python-version` (3.12) and `uv.lock`.
  - Initial doc suite committed (`docs/DECISIONS.md`, `docs/ARCHITECTURE.md`, `AGENTS.md`, `docs/PREREGISTRATION.md`, `docs/LABELING_GUIDE.md`, etc.).
- **Exit Gate 0:**
  1. `git status` verifies clean tree.
  2. Attempting to commit a fake secret or `.env` fails via pre-commit hook.
  3. CI pipeline passes linting and type checking on GitHub Actions.

### Phase 1: Lab Infrastructure & Feasibility Gate
- **Owner:** Himanshu
- **Build:**
  - Multipass/Colima Ubuntu 24.04 VM provisioned (4 vCPUs, 6–8 GB RAM, 40 GB disk, standard kernel).
  - Cluster IaC: `kind` cluster with Cilium CNI, Hubble relay, K8s Audit Policy, and Falco modern eBPF probe.
  - Multi-tenant namespaces (`tenant-a`, `tenant-b`, `tenant-c`) running 4 ARM64 workloads (`web`, `api`, `database`, `payment-style`).
  - Idempotent `Makefile` targets: `lab-up`, `lab-reset`, `lab-down`, `lab-verify`.
- **Exit Gate 1 (EARLY GO/NO-GO FEASIBILITY GATE):**
  1. Linux kernel BTF verified (`/sys/kernel/btf/vmlinux` present).
  2. `make lab-up` executes without manual intervention.
  3. `cilium status` confirms healthy CNI and Hubble relay.
  4. Falco event generator fires a test syscall alert into local webhook.
  5. Clean VM snapshot captured: `snapshot-phase-1-passed`.
  *Fallback Trigger:* If eBPF/BTF fails inside local VM, immediately switch to Cloud Ubuntu VM per D-01.

### Phase 2: One End-to-End Vertical Slice
- **Owner:** Himanshu
- **Build:**
  - One telemetry source (Falco webhook) ingests raw runtime alert.
  - Normalizer maps event to Canonical Schema v1.0.0.
  - Minimal rule-based detector classifies event.
  - Deterministic policy evaluates decision.
  - Tamper-evident audit record written to `data/audit/decisions.jsonl`.
- **Exit Gate 2 (SCOPE RE-CHECK GATE):**
  1. One end-to-end event flows from live container shell spawn to written audit JSONL record.
  2. Schema validation succeeds; raw event pointer is verified.

### Phase 3: Core Telemetry, Multi-Source Raw Archiving & Baselines
- **Owner:** Himanshu
- **Build:**
  - Ingestion and unmanipulated raw JSONL persistence for **all five telemetry sources**:
    - Falco eBPF webhook receiver (`data/raw/falco/`).
    - Kubernetes Audit log stream (`data/raw/audit/`).
    - Hubble network flow streaming collector (`data/raw/hubble/`).
    - Prometheus container metrics periodic scraper (`data/raw/prometheus/`).
    - Trivy container image scan cache (`data/raw/trivy/`).
  - Core CanonicalEvent model and JSON schema export (normalizing Falco + Audit).
  - Deterministic fact extractors (root UID, sensitive mounts, shell binary, relative baseline comparisons).
  - Temporal sliding window buffer ($\pm 30$s) correlating out-of-order raw events by `(namespace, pod_uid, owner_workload, container_id)`.
  - Baseline loader: declarative YAML profiles for the 4 lab workloads; drift detection logic.
- **Exit Gate 3:**
  1. Unit tests pass for fact extraction across 20+ synthetic pod/syscall payloads.
  2. Correlation engine correctly aggregates out-of-order live Falco and Audit events within the $\pm 30$s window.
  3. Raw collector verifies live recording of all five streams to `data/raw/`.
  4. Loading a baseline and testing a mismatched binary asserts `baseline_deviation_detected == True`.

### Phase 4: Pilot Study, Freeze, 400 Runs Capture & Frozen Split
- **Owner:** Himanshu (Support: Altaf & Kamal for blind review)
- **Build:**
  - **Step 4.1: Pilot Execution (20–30 runs):**
    - Execute 20–30 pilot scenario runs across all 5 classes and paired counterfactuals.
    - Verify completeness and integrity of raw archives for all five sources.
    - Estimate empirical power and 95% bootstrap CI width via simulation.
    - Calibrate minimum meaningful effect size; designate exploratory status if power $<0.80$.
    - **Freeze:** Permanently freeze scenario definitions, seeds, and raw capture schema.
  - **Step 4.2: Full 400 Runs Cluster Execution:**
    - Execute **400 independent cluster runs** (60 escape, 60 privilege, 60 crypto, 40 unknown, 180 benign).
    - Resource & runtime budget: ~45–60s per run (~6–7 hours cluster execution, 8–10 hours wall-clock budget).
    - Batching & resumability: Run in batches of 25–50 with checkpointing in `data/scenarios/run_checkpoint.json`.
    - Automated cleanup hook after every run guaranteeing zero orphaned cluster resources.
    - Cryptomining multi-signal enforcement ($\ge 2$ signals required) and paired same-port benign runs (e.g. port 3333).
    - Automated event-phase labeling (`benign-noise`, `precursor`, `attack`, `aftermath`) derived from scenario timeline milestones.
    - An incident is defined strictly by the scenario run (`run_id`).
  - **Step 4.3: Blind Review & Split Lock:**
    - Stratified blind sample of **60–80 incidents** independently annotated by Altaf and Kamal.
    - Inter-reviewer agreement ($\kappa \ge 0.80$), reviewer vs ground truth kappa, and severity weighted kappa ($\kappa_w$) reported with 95% CIs. Clarifications made using dev data only.
    - Grouped dataset splitting: Dev set (72%, 288 runs) vs Held-out Test set (28%, 112 runs) with unseen variants held out.
- **Exit Gate 4:**
  1. All 400 scenario runs complete with automated cleanup leaving zero orphaned pods.
  2. Raw data from all 5 sources confirmed present for all 400 runs.
  3. Teammates complete blind review on 60–80 incident sample according to `docs/LABELING_GUIDE.md`, achieving Cohen's $\kappa \ge 0.80$.
  4. `datasets/splits/manifest_v1.json` and raw event SHA-256 hashes committed to Git.
  5. Automated CI check asserts zero identifier leakage in feature/state representations.

### Phase 5: Classical ML Baseline & Evaluation Harness
- **Owner:** Himanshu
- **Build:**
  - Scikit-learn feature extraction pipeline (sanitized numerical/categorical vectors).
  - Random Forest classifier trained strictly on Dev split via 5-fold grouped cross-validation.
  - Cluster-aware bootstrap confidence interval evaluation harness.
  - Allocation of equal dev-set tuning budget for all classifiers.
- **Exit Gate 5:**
  1. Random Forest baseline trains without data leakage errors.
  2. Evaluation harness outputs cross-validated Macro-F1, per-class metrics, and 95% bootstrap CIs.

### Phase 6: Telemetry Normalizers Expansion (Hubble, Trivy, Prometheus)
- **Owner:** Himanshu
- **Build:**
  - Normalizers parsing previously archived raw Hubble flow logs, Trivy vulnerability scans, and Prometheus CPU/memory metrics into canonical event fields without re-running cluster scenarios.
  - Multi-source correlation joining audit, network, and metric context.
  - Bounded buffers with drop counters for runtime streaming.
- **Exit Gate 6:**
  1. Multi-source integration test verifies that an incident joins Falco, Audit, Hubble egress, and CPU metrics within the correlation window from archived raw runs.
  2. Bounded buffers demonstrate graceful drop counting under synthetic telemetry flood.

### Phase 7: ScaleDown Model Adapter, Smoke Test & Contract Tests
- **Owner:** Himanshu
- **Build:**
  - ScaleDown Classify-1 adapter (`POST https://api.scaledown.xyz/v1/scaledown`).
  - State serializer formatting Markdown text with delimited `<untrusted_args>` tags.
  - Defense-in-depth sanitization: unicode normalization, control character stripping, 128-char truncation.
  - Choice (5 classes), 5-level Score, and 4 Noul questions integration.
  - Timeout (hard 5s), transient retries with exponential backoff, local file-based response caching.
  - Contract test suite using recorded JSON fixtures (zero live key in CI).
  - Manual live smoke test target (`make test-live-api`).
- **Exit Gate 7 (GO/NO-GO MODEL GATE):**
  1. 100% of offline contract tests pass in CI.
  2. User manually runs `make test-live-api`: real API roundtrip succeeds, returning valid Choice, Score, and Noul answers within expected latency. Verify Severity = Score + 1.0 formula.
  3. Response caching verified: repeat call takes $<1$ ms and incurs $0.00 cost.

### Phase 8: Full Comparative Evaluation, Ablations & Adversarial Tests
- **Owner:** Himanshu
- **Build:**
  - Run Rules, Random Forest, and ScaleDown models on frozen Dev split for prompt/threshold tuning under equal tuning budgets.
  - Evaluate 6 systematic ablations (Primary: Baseline ON vs OFF via paired comparison on identical runs).
  - Execute adversarial prompt-injection test suite.
  - Single-pass evaluation on frozen Held-Out Test Set; all access logged.
- **Exit Gate 8 (CODE FREEZE):**
  1. Primary hypothesis tested: Paired comparison $\Delta\text{Macro-F1}$ and benign $\Delta\text{FPR}$ computed with 95% cluster-aware bootstrap CIs (width evaluated against pilot calibration; marked exploratory if underpowered).
  2. Paired McNemar test confirms significance of baseline context addition.
  3. Adversarial attack success rate reported under all 4 defense configurations.
  4. Git tag created: `evaluation-frozen-v1`. Full codebase frozen against further feature changes.

### Phase 9: Response Engineering, Label Quarantine & SRE Containment
- **Owner:** Himanshu
- **Build:**
  - Label-based quarantine controller (`quarantine=true`).
  - Pre-installed tenant `NetworkPolicy` blocking traffic while preserving `kube-dns`.
  - Automatic TTL rollback reconciliation loop.
  - Scoped RBAC ServiceAccount (`runtimelens-response-controller`) with zero delete permissions.
  - Webhook/Slack alert dispatcher with local JSONL fallback.
  - Pod Termination: Documented as not implemented; design-only.
- **Exit Gate 9:**
  1. Live quarantine test verifies target pod loses network egress within 2 seconds of label patch.
  2. RBAC negative test passes (`kubectl auth can-i delete pods` returns `no`).
  3. Simulated TTL expiration successfully triggers automated label removal and connectivity restoration.

### Phase 10: Observability, Metrics Exporter & Dashboards
- **Owner:** Himanshu
- **Build:**
  - Prometheus metrics exporter (`prometheus_client`) on port 9090 (latencies, class distributions, drops; ECE excluded).
  - Structured audit trail with hash-chaining verification script.
  - Grafana dashboard JSON visualizing detection rates, latency percentiles, and quarantine status.
- **Exit Gate 10:**
  1. Prometheus scrapes RuntimeLens exporter with zero scrape failures.
  2. Grafana dashboard renders real-time pipeline latency and threat distributions during scenario playback.

### Phase 11: Final Deliverables, Academic Revisions & Live Demo
- **Owner:** Altaf & Kamal (Report & Poster), Himanshu (Live Demo & Technical Validation)
- **Build:**
  - Execute Stage 2 report revisions: incorporate measured evaluation numbers, confusion matrices, and limitations into `docs/report/final_report.pdf`.
  - Redesign academic poster with updated architecture, ScaleDown branding, and measured metrics.
  - Script reproducible 5-minute live lab demo (`make demo`).
  - Complete viva defense rehearsal covering threat taxonomy, SRE availability trade-offs, and statistical findings.
- **Exit Gate 11 (FINAL PROJECT COMPLETION):**
  1. `make demo` runs end-to-end from a clean state in $<5$ minutes, showing detection, baseline context comparison, and reversible quarantine.
  2. Final Report v2 and Poster PDFs compiled, reviewed, and signed off.
  3. All team members rehearse and pass simulated viva grilling.

### Phase 9: Response Engineering, Label Quarantine & SRE Containment
- **Owner:** Himanshu
- **Build:**
  - Label-based quarantine controller (`quarantine=true`).
  - Pre-installed tenant `NetworkPolicy` blocking traffic while preserving `kube-dns`.
  - Automatic TTL rollback reconciliation loop.
  - Scoped RBAC ServiceAccount (`runtimelens-response-controller`) with zero delete permissions.
  - Webhook/Slack alert dispatcher with local JSONL fallback.
  - Pod Termination: Documented as not implemented; design-only.
- **Exit Gate 9:**
  1. Live quarantine test verifies target pod loses network egress within 2 seconds of label patch.
  2. RBAC negative test passes (`kubectl auth can-i delete pods` returns `no`).
  3. Simulated TTL expiration successfully triggers automated label removal and connectivity restoration.

### Phase 10: Observability, Metrics Exporter & Dashboards
- **Owner:** Himanshu
- **Build:**
  - Prometheus metrics exporter (`prometheus_client`) on port 9090 (latencies, class distributions, drops; ECE excluded).
  - Structured audit trail with hash-chaining verification script.
  - Grafana dashboard JSON visualizing detection rates, latency percentiles, and quarantine status.
- **Exit Gate 10:**
  1. Prometheus scrapes RuntimeLens exporter with zero scrape failures.
  2. Grafana dashboard renders real-time pipeline latency and threat distributions during scenario playback.

### Phase 11: Final Deliverables, Academic Revisions & Live Demo
- **Owner:** Altaf & Kamal (Report & Poster), Himanshu (Live Demo & Technical Validation)
- **Build:**
  - Execute Stage 2 report revisions: incorporate measured evaluation numbers, confusion matrices, and limitations into `docs/report/final_report.pdf`.
  - Redesign academic poster with updated architecture, ScaleDown branding, and measured metrics.
  - Script reproducible 5-minute live lab demo (`make demo`).
  - Complete viva defense rehearsal covering threat taxonomy, SRE availability trade-offs, and statistical findings.
- **Exit Gate 11 (FINAL PROJECT COMPLETION):**
  1. `make demo` runs end-to-end from a clean state in $<5$ minutes, showing detection, baseline context comparison, and reversible quarantine.
  2. Final Report v2 and Poster PDFs compiled, reviewed, and signed off.
  3. All team members rehearse and pass simulated viva grilling.
