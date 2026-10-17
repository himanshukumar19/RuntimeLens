# DATASET LABELING GUIDE & BLIND REVIEW PROTOCOL

## 1. Ground Truth Architecture & Incident Definition
RuntimeLens operates a dual-level labeling structure:
1. **Incident-Level Ground Truth (Primary):**
   - **Incident Definition:** An incident is defined strictly by the **scenario execution run (`run_id`)**. All telemetry emitted during that run belongs to that incident.
   - Ground truth threat class and severity are derived deterministically from the scenario definition metadata (`run_id`, `scenario_id`, `family`, `variant`, `seed`).
   - The $\pm 30$s temporal sliding window is used **strictly for correlating and joining out-of-order raw telemetry events** across sensors into canonical records, NOT for segmenting or defining separate incidents.
2. **Event-Level Phase Labels (Secondary):**
   - Every individual raw telemetry event within an incident is tagged with an operational phase derived **automatically from the scenario runner execution timeline milestones**:
     - `benign-noise`: Ambient cluster telemetry generated before scenario deployment ($t < t_{\text{start}}$).
     - `precursor`: Setup, scheduling, container initialization, or reconnaissance phase ($t_{\text{start}} \le t < t_{\text{exec}}$).
     - `attack`: Active execution of the simulated threat indicator ($t_{\text{exec}} \le t \le t_{\text{end}}$).
     - `aftermath`: Post-execution telemetry, process termination, connection close, and cleanup ($t > t_{\text{end}}$).
   - Milestone timestamps are recorded automatically by the test runner harness and injected during event normalization.

---

## 2. Threat Class Taxonomy & Annotation Rubrics

### 2.1 `benign`
- **Definition:** Standard application execution, routine administration, authorized rolling updates, scheduled batch jobs, health check probes, or authorized debug sessions adhering to workload baselines.
- **Observable Evidence:**
  - Binaries match `expected_binaries` in active workload baseline.
  - Inbound and outbound network flows match `expected_peers` and bandwidth is within baseline envelope.
  - CPU usage remains within the workload's baseline envelope (relative to `baseline.cpu_envelope_mcores` or typical historical distribution, rather than an arbitrary global constant).
  - Shell execution occurs only in containers where `shell_allowed: true`.

### 2.2 `container_escape`
- **Definition:** Actions attempting to access or compromise the underlying host kernel, host filesystems, container runtime daemons, or unshared host namespaces.
- **Observable Evidence:**
  - Accessing host runtime socket (`/var/run/docker.sock`, `containerd.sock`) or host filesystem paths (`/proc/sys`, `/etc/shadow`, `/sys/kernel`, `/dev/kmem`).
  - Container executing with `privileged: true` or invoking namespace traversal (`setns`, `nsenter`).
  - Verified Falco rule triggers from pinned ruleset:
    - `Launch Sensitive Mount Container`
    - `Read sensitive file untrusted`
    - `Change thread namespace`
    - `Write below etc`

### 2.3 `privilege_abuse`
- **Definition:** Misuse of Kubernetes orchestration-layer permissions, unauthorized service account token reads, cross-tenant Secret exfiltration, or unauthorized pod exec.
- **Observable Evidence:**
  - ServiceAccount querying Secrets or ConfigMaps outside its assigned tenant namespace.
  - Creating or patching `Roles` or `RoleBindings` to elevate cluster permissions.
  - Invoking `pods/exec` into a pod belonging to another tenant or unauthorized workload.
  - Kubernetes Audit log captures: `403 Forbidden` on sensitive verbs or unexpected `200 OK` on unauthorized cross-tenant resources.

### 2.4 `cryptomining`
- **Definition:** Unauthorized compute resource exhaustion coupled with anomalous execution and unauthorized egress communication.
- **Multi-Signal Requirement:** To prevent false positives and trivial heuristic shortcuts, **at least two (2) out of the following three (3) corroborating signals are strictly required** for the `cryptomining` label:
  1. *Relative CPU Anomaly:* Sustained container CPU rate exceeding the workload baseline envelope by $\ge 3\times$ or sustained $>80\%$ of container CPU quota where baseline average is $<25\%$.
  2. *Ephemeral / Unapproved Binary:* Execution of binaries from volatile directories (`/tmp`, `/dev/shm`) or execution of binaries absent from `expected_binaries`.
  3. *Unauthorized Egress:* Outbound network connection to an IP/host not present in `baseline.expected_peers`.
- **Anti-Shortcut / Port Guardrail:** Port numbers (e.g. 3333, 4444, 8333) alone are **NEVER** accepted as sole evidence of cryptomining. Paired benign scenarios run on identical ports (e.g. benign analytics worker connecting on port 3333) to verify that classification models cannot rely on port numbers as a shortcut.

### 2.5 `unknown`
- **Definition:** Telemetry is incomplete, degraded, dropped, or corrupted **by design**, such that the evidence is insufficient to render a verified threat classification. (Conflict-based scenarios are excluded from `unknown`; genuine conflicting evidence routes to human review under policy, not threat-class re-labeling).
- **Observable Evidence (Strictly Telemetry Impairment):**
  - Collector failure, sensor disconnected, or dropped audit stream (`missing_sources: ["k8s_audit"]`, `telemetry_degraded: true`).
  - eBPF ring-buffer drop or kernel event loss flagged by Falco health check.
  - Truncated or missing core attributes (e.g. container ID or process name unavailable at normalizer arrival).

---

## 3. Severity Scoring Rubric (1 to 5)

| Score | Severity Level | Operational Criteria |
|:---:|:---|:---|
| **1.0** | `Informational` | Normal baseline execution, standard pod deployment, routine health probe. |
| **2.0** | `Low` | Minor transient anomaly; authorized administrative task outside normal hours. |
| **3.0** | `Medium` | Uncorroborated anomaly; unexpected process arguments or unrecognized network peer. |
| **4.0** | `High` | Confirmed baseline violation; unauthorized Secret read, sustained mining spike, or unprivileged shell execution. |
| **5.0** | `Critical` | Confirmed container breakout indicator, host socket manipulation, or cluster-wide credential exfiltration. |

---

## 4. Teammate Blind Review & Agreement Protocol
To ensure ground-truth labeling validity and guard against researcher bias, a formal blind review is conducted:

1. **Stratified Sampling:** A sample of **60–80 incidents** (stratified across all 5 threat classes and all paired counterfactual scenario families) is drawn from the dataset prior to splitting. (Note: 10% of a 400-run corpus is ~40 runs; a 60–80 incident sample provides a statistically robust 15–20% stratified sample).
2. **Review Tool Execution:** Teammates (Altaf Raja and Kamal Nayan Kumar) independently run the review tool in blind mode:
   ```bash
   python -m runtimelens.review --blind --sample 70
   ```
3. **Blind Interface:** The tool presents:
   - Workload identity and active baseline.
   - Raw event facts (process, mounts, syscalls, audit verbs, network flows, relative resource consumption).
   - **Model predictions, rule matches, and scenario ground-truth manifests are completely hidden.**
4. **Annotator Verdict:** Each reviewer independently selects the threat class and severity score.
5. **Agreement Metrics & Confidence Intervals:**
   The evaluation harness computes and reports:
   - **Inter-Reviewer Agreement:** Cohen's $\kappa$ between Reviewer 1 (Altaf) and Reviewer 2 (Kamal) on threat classes, with analytical 95% CI.
   - **Reviewer 1 vs Ground Truth:** Cohen's $\kappa$ between Altaf and scenario ground truth, with 95% CI.
   - **Reviewer 2 vs Ground Truth:** Cohen's $\kappa$ between Kamal and scenario ground truth, with 95% CI.
   - **Severity Agreement:** Weighted Cohen's Kappa ($\kappa_w$, quadratic weights) for 5-level severity scores across reviewers and against ground truth, with 95% CI.
6. **Acceptance Threshold & Air-Gap Rule:**
   - **Target:** Cohen's $\kappa \ge 0.80$ across reviewers and ground truth (indicating substantial/near-perfect agreement).
   - **Discrepancy Resolution:** If $\kappa < 0.80$, ambiguous cases are reviewed, and the labeling guide is clarified using **Dev-set data ONLY**.
   - **Immutable Definitions:** Scenario definitions, class rubrics, and ground-truth rules **must NEVER be changed** after held-out test labels are accessed or test-split evaluation has begun.
