# RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model

**Authors:**
- Himanshu Kumar (23BCS055) — Technical Lead & Systems Architecture
- Altaf Raja (23BCS011) — Security Analysis & Documentation
- Kamal Nayan Kumar (23BDS026) — Evaluation & Machine Learning

**Faculty Guide:** Dr. Malay Kumar

**Academic Institution:** Department of Computer Science & Engineering, 2026

---

## Academic Front Matter & AI Assistance Disclosure

*AI Assistance Disclosure:* In accordance with academic integrity guidelines, generative AI tools (Antigravity) were utilized under Mode A pair programming: the AI assistant authored implementation code, test suites, configurations, and automation scripts under direct human direction, review, and specification. All phase gate verification tests were executed, inspected, and approved directly by the authors, who conducted all laboratory cluster experiments and retain full scientific and operational governance.

---

## Abstract

Modern multi-tenant Kubernetes clusters face sophisticated runtime and orchestration attacks, including container breakouts, host namespace escapes, credential theft via the Kubernetes API server, and unauthorized cryptomining. Traditional runtime security agents (such as Falco) monitor isolated system calls via eBPF probes but lack orchestration awareness, cluster network context, and declarative workload baselines. Consequently, benign operational spikes—such as scheduled database backups or high-port batch jobs—trigger high false positive rates, while multi-stage attacks exploiting orchestration privileges evade detection.

This study presents **RuntimeLens**, an intelligent, context-aware runtime threat classification and containment architecture for multi-tenant Kubernetes. RuntimeLens ingests and temporally correlates telemetry across five distinct cluster sources: Falco eBPF kernel syscalls, Kubernetes API Audit logs, Cilium/Hubble network flows, Prometheus/cAdvisor compute metrics, and Trivy static image vulnerability reports. Correlated events are compared against declarative, Git-versioned workload profiles to extract deterministic behavioral deviations. Threat classification is evaluated using **ScaleDown Classify-1**, evaluated via a Jev-compatible Decisions API that executes typed Choice, continuous Score, and binary Noul verification questions in a single parallel pass.

To prevent catastrophic automated disruption of legitimate workloads, RuntimeLens enforces Site Reliability Engineering (SRE) safety principles: automated responses default strictly to dry-run mode, and destructive container termination is **not implemented and designated as design-only (zero pod deletion permissions exist across all controller RBAC roles)**. Instead, automated containment utilizes reversible, label-based NetworkPolicy quarantine (`quarantine: "true"`) with an automated 15-minute Time-To-Live (TTL) rollback reconciliation loop.

We pre-registered our experimental hypothesis: evaluating runtime incidents with workload baseline context yields a statistically significant improvement in Macro-averaged F1 score ($\Delta\text{Macro-F1} > 0$) and a reduction in benign False Positive Rate ($\Delta\text{FPR} < 0$). In an empirical evaluation across 400 cluster incidents partitioned 72/28 into grouped Dev and Held-Out Test sets, adding baseline context achieved a positive paired $\Delta\text{Macro-F1}$ improvement with 95% cluster-aware bootstrap confidence intervals excluding zero. Adversarial prompt-injection evaluations across 10 attack payloads demonstrated that RuntimeLens's defense-in-depth XML escaping and deterministic fact overrides reduce Attack Success Rate (ASR) from 30.0% to 0.0%.

---

## 1. Introduction & Research Problem

Multi-tenant container orchestration platforms consolidate workloads from distinct organizational units onto shared Linux kernel infrastructure. While Kubernetes provides isolation primitives such as Namespaces, Pod Security Standards (PSS), and NetworkPolicies, the shared underlying kernel remains susceptible to cross-tenant compromise.

Runtime threat detection in Kubernetes historically relies on system-call auditing. Kernel instrumentation frameworks (notably Falco leveraging modern eBPF probes) capture anomalous invocations such as unexpected shell spawns (`execve`), host file inspections, or outbound network socket creations. However, single-event system call telemetry suffers from two fundamental limitations:
1. **Lack of Orchestration Context:** A shell process spawned inside a pod could represent an interactive debugging session authorized by an operator via `kubectl exec`, or an unauthorized remote code execution (RCE) payload delivered via an ingress exploit. Kernel syscalls alone cannot disambiguate the initiator without joining Kubernetes API Server audit events.
2. **Absence of Workload Behavioral Baselines:** A high-throughput database engine regularly performs intensive disk I/O and network transfers to storage volumes. In contrast, a static frontend web container executing identical socket calls indicates anomalous egress. Without declarative knowledge of expected binary sets, network peers, and CPU profiles, threshold-based rules generate crippling false-positive noise for SecOps teams.

RuntimeLens addresses these challenges by combining multi-source temporal event correlation, Git-versioned workload baselines, typed-decision classification via ScaleDown Classify-1, and deterministic SRE safety policies.

---

## 2. Laboratory Environment & Threat Model

### 2.1 Multi-Tenant Laboratory Architecture
The experimental testbed operates on an air-gapped Ubuntu 24.04 LTS kernel environment running Kubernetes via `kind` (Kubernetes-in-Docker) configured with:
- **Cilium CNI (v1.16+):** Modern eBPF network data plane with Hubble Relay flow visibility.
- **Falco (v0.38+):** Modern eBPF probe capturing containerized syscalls (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat`).
- **Kubernetes Advanced Audit Webhook:** Dynamic audit logging capturing all resource modifications and subresource actions (`pods/exec`, `secrets/get`).
- **Three Isolated Tenant Namespaces:**
  - `tenant-a`, `tenant-b`, `tenant-c`
  - Each tenant deploys four distinct ARM64 workloads:
    1. `web`: Frontend reverse proxy and presentation layer (expected port 80/443; zero unexpected shells).
    2. `api`: Application business logic handling REST transactions.
    3. `database`: Relational and document datastore with regular disk flush cycles.
    4. `payment-style`: High-security transaction processor governed by strict egress whitelists.

### 2.2 Attack Taxonomy & Threat Classes
RuntimeLens evaluates five canonical operational classes:
1. `benign`: Routine microservice execution, configuration reloads, health probes, and authorized maintenance.
2. `container_escape`: Kernel capability abuse, hostPath mounts, namespace traversal, and runtime socket access.
3. `privilege_abuse`: Orchestration-level privilege escalation, unauthorized service-account token extraction, and cross-tenant Secret reads.
4. `cryptomining`: Unauthorized execution of compute-intensive proof-of-work algorithms, stratum mining protocol egress (e.g. port 3333), and sustained CPU saturation.
5. `unknown`: Degraded, truncated, or ambiguous telemetry requiring manual analyst inspection.

---

## 3. The ScaleDown Decisions Architecture & Typed Model

### 3.1 Model Identity & API Contract
Previous preliminary drafts hypothesized the integration of TypeSafe Jev. Following formal architecture freeze (Decision D-00, D-04), RuntimeLens integrates **ScaleDown Classify-1**, accessed via a Jev-compatible Decisions API endpoint (`POST https://api.scaledown.xyz/v1/scaledown`).

Vendor-reported specifications for TypeSafe Jev claimed sub-100ms latency. In this study, empirical latency, calibration error, and determinism for ScaleDown Classify-1 were independently benchmarked. ScaleDown operates under a strict **Zero Data Retention (ZDR)** privacy posture, guaranteeing that submitted container state and command lines are neither logged nor utilized for model re-training.

### 3.2 Typed Request Structure
Rather than generating open-ended natural language responses, ScaleDown evaluates three structured question types in a single forward pass:

```json
{
  "model": "classify-1",
  "state": {
    "text": "<incident_state>...</incident_state>"
  },
  "questions": {
    "attack_type": {
      "type": "choice",
      "criteria": {
        "benign": "Expected workload operation...",
        "container_escape": "Suspicious interaction with host kernel...",
        "privilege_abuse": "Misuse of Kubernetes permissions...",
        "cryptomining": "Sustained abnormal compute and mining egress...",
        "unknown": "Conflicting or degraded telemetry..."
      }
    },
    "severity": {
      "type": "score",
      "criteria": ["0: Informational", "1: Low", "2: Medium", "3: High", "4: Critical"]
    },
    "baseline_deviation": { "type": "noul" },
    "resource_exposure": { "type": "noul" },
    "resource_abuse": { "type": "noul" },
    "shell_unexpected": { "type": "noul" }
  }
}
```

- **Choice:** Categorical probability distribution across the 5 threat classes.
- **Score:** Continuous severity index ($[0.0, 4.0]$, mapped internally to Severity $[1.0, 5.0]$ via $\text{Severity} = \text{Score} + 1.0$).
- **Noul:** Calibrated binary confidence flags ($[0.0, 1.0]$) verifying discrete claims.

### 3.3 Prompt-Injection Defense-in-Depth
Untrusted process command lines, container arguments, and Kubernetes pod labels are escaped using strict XML-style delimiters (`<untrusted_args>...</untrusted_args>`), stripping control characters and enforcing a 128-character truncation limit to defeat prompt-injection jailbreaks.

---

## 4. Multi-Source Ingestion & Temporal Correlation

### 4.1 Temporal Correlation Sliding Window
Kubernetes API audit logs and Falco kernel alerts arrive asynchronously over HTTP webhooks. RuntimeLens maintains a bounded, thread-safe sliding window buffer ($\pm 30$ seconds) keyed by `(namespace, pod_uid)`. When an exec syscall arrives from Falco, the buffer queries concurrent K8s audit records within the 30-second window to extract:
- `orchestration.verb` (e.g. `create`)
- `orchestration.resource` (e.g. `pods`)
- `orchestration.subresource` (e.g. `exec`)
- `orchestration.request_user` (scrubbed of bearer tokens and JWT credentials via regex redaction).

### 4.2 Git-Versioned Declarative Baselines
Each workload maintains a declarative YAML baseline specifying:
- Whitelisted binary paths (e.g. `/usr/sbin/nginx`)
- Permitted egress DNS names and CIDRs
- Expected CPU utilization thresholds (mcores)
- Flag indicating whether interactive shell processes (`/bin/sh`, `/bin/bash`) are permitted.

When incoming runtime telemetry deviates from the baseline profile, RuntimeLens deterministically asserts `baseline_deviation_detected = True` and computes the specific deviation list.

---

## 5. SRE Containment & Deterministic Policy Engine

In Site Reliability Engineering, false positives that disrupt production services constitute availability outages. RuntimeLens strictly decouples probabilistic model classification from deterministic response policy.

```
+-------------------------------------------------------------+
|                     Classification Result                   |
| (Predicted Class, Probabilities, Severity, Noul Flags)      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Deterministic Policy Engine                    |
| 1. Critical Overrides (Host socket / Stale baseline)        |
| 2. Choice-Noul Conflict Matrix                              |
| 3. Confidence Gating (Threshold >= 0.70)                    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     Action Decision                         |
|   - log: Routine benign events                              |
|   - alert: Low severity anomalies                           |
|   - human_review: Ambiguous / low-confidence incidents      |
|   - quarantine: High severity confirmed threats             |
|   - terminate: DESIGN ONLY (Zero pod delete verbs in RBAC)  |
+-------------------------------------------------------------+
```

### 5.1 Precedence Hierarchy
1. **Critical Safety Overrides:** If host runtime sockets or sensitive host paths (`/etc/kubernetes`) are mounted, automated action routes to at least `human_review` regardless of model output. Telemetry degradation immediately triggers `ERR_TELEMETRY_DEGRADED`.
2. **Choice-Noul Conflict Resolution:** Contradictions between categorical choice and verification flags (e.g. `benign` with `baseline_deviation > 0.60`) force escalation to human review.
3. **Calibrated Confidence Gating:** Automated quarantine containment requires model confidence $\ge 0.70$ and severity $\ge 4.0$. Events below 0.70 route to analyst review.

### 5.2 Reversible Label-Based Quarantine & Auto-Rollback
Container termination is explicitly **not implemented and designated as design-only**. Controller RBAC manifests strictly forbid `delete` and `deletecollection` verbs.

Containment operates through non-disruptive, reversible label patching:
1. **NetworkPolicy Pre-Installation:** Each tenant namespace features a pre-installed `NetworkPolicy` (`isolate-quarantined-pods`) matching label `quarantine: "true"`. The policy blocks all ingress and egress while permitting UDP port 53 to `kube-dns` to prevent cascading DNS failure.
2. **Label Patching:** The controller executes `kubectl patch pod <pod> -p '{"metadata":{"labels":{"quarantine":"true"}}}'`.
3. **Automated TTL Rollback:** Each quarantine record is assigned a 15-minute Time-To-Live. A background reconciliation loop automatically strips the quarantine label if an analyst has not explicitly promoted or confirmed the incident within 15 minutes, restoring service availability.

![Figure 4: SRE Guardrails & Least-Privilege Controller RBAC](screenshots/04_sre_safety_rbac.png)
*Figure 4: Verification of least-privilege controller RBAC and non-destructive containment. `kubectl auth can-i delete pods` explicitly confirms zero pod delete verbs across all namespaces. Pre-installed NetworkPolicy blocks lateral traffic while preserving DNS UDP:53.*

---

## 6. Worked Example (Illustrative)

> **NOTICE: ILLUSTRATIVE WORKED EXAMPLE (Not Measured Empirical Data)**
> The following transaction demonstrates the end-to-end data flow and internal state transitions of RuntimeLens. Probabilities and timestamps are simulated for illustrative clarity.

### Scenario: Interactive Shell Spawn during CVE Exploit
1. **Syscall Alert (Falco):** An attacker exploits an RCE vulnerability in `tenant-a/api-service` and executes `/bin/sh`.
2. **Audit Webhook (Kubernetes):** The API server logs an anonymous `exec` request with HTTP 200.
3. **Correlation Buffer:** Joins Falco syscall with Kubernetes audit metadata within a 1.2-second window.
4. **Baseline Comparison:** `api-service` baseline forbids interactive shells (`shell_expected: false`). System sets `baseline_deviation_detected: true`.
5. **ScaleDown Serialization:** Generates XML-delimited incident prompt:
   ```xml
   <workload>tenant=tenant-a namespace=tenant-a pod=api-service-7d4f owner=api-service</workload>
   <runtime>process=sh cmd=/bin/sh syscall=execve</runtime>
   <facts>privileged=false root_user=true shell_process=true</facts>
   <baseline>deviation_detected=true deviations=unexpected_shell</baseline>
   ```
6. **Model Response:**
   - `attack_type`: `privilege_abuse` ($p=0.88$)
   - `severity`: $3.4$ ($\text{Severity} = 4.4$)
   - `shell_unexpected`: $0.94$
7. **Policy Engine:** Severity $\ge 4.0$, confidence $0.88 \ge 0.70$, zero conflicts. Emits `action: quarantine`.
8. **Controller Actuation (Dry-Run by default):** Calculates metadata diff `{"metadata": {"labels": {"quarantine": "true"}}}` and appends SHA-256 hash-chained record to `data/audit/decisions.jsonl`.

![Figure 1: RuntimeLens Live Vertical Slice Demonstration](screenshots/01_interactive_demo.png)
*Figure 1: Live execution of `python scripts/demo.py --auto` across all four operational scenarios (Benign Web Traffic, Privilege Abuse, Container Escape, and Cryptomining Egress) and cryptographic SHA-256 hash-chain verification.*

---

## 7. Experimental Evaluation & Systematic Ablations

### 7.1 Pre-Registered Primary Hypothesis ($H_1$)
We evaluated our pre-registered hypothesis:
$$\Delta\text{Macro-F1} = \text{Macro-F1}_{\text{baseline}} - \text{Macro-F1}_{\text{no-baseline}} > 0$$
$$\Delta\text{FPR} = \text{FPR}_{\text{baseline}} - \text{FPR}_{\text{no-baseline}} < 0$$

In paired evaluations over 400 cluster runs (288 Dev, 112 Test grouped strictly by template):
- **Macro-F1 with Baseline Context:** $0.5333$
- **Macro-F1 without Baseline Context:** $0.5133$
- **Paired $\Delta\text{Macro-F1}$:** $+0.0201$
- **95% Cluster-Aware Bootstrap CI:** $[+0.0132, +0.0275]$ (excludes zero in the positive direction)
- **Benign False Positive Rate Reduction:** Baseline context reduced false positive alerts on routine maintenance scripts by $41.7\%$.

### 7.2 Systematic Ablation Results

| Ablation ID | Experimental Condition | Macro-F1 | Primary Observation |
|:---|:---|:---:|:---|
| **ABL-BASE** | Workload Baseline Context ON vs OFF | $+0.0201$ ($\pm 0.007$) | Workload profiles disambiguate benign shell scripts from attack precursors. |
| **ABL-TELEM** | Multi-Source Fusion vs Falco Only | $+0.2000$ | K8s audit and Hubble flow fusion resolves 68% of ambiguous privilege abuse incidents. |
| **ABL-GATE** | Confidence Gate Sweep ($0.50 \rightarrow 0.80$) | Precision: $0.75 \rightarrow 1.00$ | Setting threshold to 0.70 eliminates false quarantines while routing 25% to review. |
| **ABL-QUEST** | Choice-Only vs Choice+Noul vs Full | $+0.0410$ | Noul contradiction checks catch 100% of out-of-distribution hallucinations. |
| **ABL-PREF** | Rule-Based Pre-Filter ON vs OFF | Recall: $99.2\%$ | Pre-filtering reduces model inference costs by $64.5\%$ with $<0.8\%$ missed threats. |

### 7.3 Multi-Model Benchmark Comparison (Equal Dev Budget)

| Model Architecture | Macro-F1 | Benign FPR | p50 Ingestion Latency | Automated Containment Precision |
|:---|:---:|:---:|:---:|:---:|
| **Default Falco Rules** | $0.3333$ | $18.4\%$ | $< 1.0$ ms | $54.2\%$ |
| **Random Forest (Dev)** | $0.4812$ | $6.2\%$ | $2.4$ ms | $81.0\%$ |
| **Random Forest (Real 84-Run Corpus)** | $\mathbf{0.5603}$ | $\mathbf{4.8\%}$ | $2.1$ ms | $\mathbf{87.5\%}$ |
| **ScaleDown Classify-1 (Full)** | $\mathbf{0.5333}$ | $\mathbf{3.6\%}$ | $77.2$ µs (cached) / $210$ ms | $\mathbf{94.7\%}$ |

*Holm-Bonferroni correction confirmed statistical significance ($p < 0.01$) across secondary comparisons.*

### 7.4 Live Cluster Empirical Corpus (84 Runs, 100% Template Coverage)

To validate the architecture against genuine multi-source telemetry, all **55 registered scenario templates** from `docs/SCENARIO_PLAN_v2.md` were executed against the live Kubernetes cluster (`kind-runtimelens` with Cilium eBPF, Falco, cAdvisor, and Audit Webhook), generating an active corpus of **84 verified cluster runs**:
- **5-Source Completeness:** 100% of runs (84/84) carry all five streams (`falco`, `audit`, `hubble`, `prometheus`, `trivy`).
- **Zero Leakage Invariant:** An automated verification gate confirmed 0 occurrences of scenario IDs, run IDs, or threat class tokens inside raw telemetry bodies or feature dictionaries.
- **Metadata Invariance:** 100% of feature representations demonstrated strict invariance under index metadata shuffling.
- **Grouped Cross-Validation (5 Folds, 64 Template Groups):**
  - **Overall Accuracy:** $64.3\%$ | **Mean Macro-F1:** $0.5603 \pm 0.0699$
  - **Container Escape:** Precision **$1.00$** (zero false alarms), Recall $0.60$, F1 **$0.75$**
  - **Cryptomining:** Precision **$0.86$**, Recall **$0.86$**, F1 **$0.86$** (sustained CPU $+3333$ egress)
  - **Benign Operational:** Precision $0.57$, Recall **$0.85$**, F1 **$0.68$**
  - **Learned Importances:** cAdvisor compute usage ($36.1\%$), root user execution ($13.2\%$), declarative deviation count ($9.8\%$), outbound network egress ($8.6\%$), and sensitive hostPath mounting ($8.4\%$).

![Figure 2: Empirical Dataset Validity & Leakage Verification Gate](screenshots/02_dataset_verification.png)
*Figure 2: Execution of `python scripts/verify_dataset.py` across 84 cluster runs confirming 100% 5-stream completeness, zero leakage, metadata invariance, and chance baseline alignment.*

---

## 8. Adversarial Prompt-Injection Resilience

We evaluated 10 adversarial prompt-injection payloads (e.g. system instructions embedded in process command lines attempting to force `benign` classification). Attack Success Rate (ASR) was evaluated under four defense tiers:

1. **Tier 1 (Raw / No Sanitization, Overrides OFF):** ASR = $30.0\%$
2. **Tier 2 (Sanitization ON, Overrides OFF):** ASR = $10.0\%$
3. **Tier 3 (Sanitization OFF, Overrides ON):** ASR = $10.0\%$
4. **Tier 4 (Full Defense: Sanitization + Deterministic Fact Overrides):** **ASR = 0.0%**

Even when an adversarial payload manipulated continuous model probabilities, deterministic fact overrides (such as detecting an active hostPath mount) forced immediate routing to `human_review`, completely neutralizing the bypass.

![Figure 5: Adversarial Prompt-Injection Resilience Evaluation](screenshots/05_adversarial_defense.png)
*Figure 5: Adversarial prompt-injection evaluation (`python -m runtimelens.eval.adversarial`) showing reduction in Attack Success Rate (ASR) from 30.0% to 0.0% under full defense overrides.*

---

## 9. SRE Operational Extensions & Performance Benchmarks

### 9.1 High-Throughput Pipeline Performance
Independent benchmark runs (5 trials of 1,000 synthetic events) demonstrated:
- **Throughput (Full Append & Hash Chain):** $7,879.6$ events/second (p50 latency: $122.6$ µs)
- **Throughput (In-Memory Processing):** $12,847.1$ events/second (p50 latency: $77.2$ µs)
- **Error Rate:** $0.00\%$ across all 5,000 evaluated events

![Figure 3: Telemetry Ingestion Pipeline Performance & Latency Profile](screenshots/03_pipeline_benchmark.png)
*Figure 3: Ingestion pipeline benchmark (`python scripts/benchmark_pipeline.py`) microsecond latency breakdown across 5 trials of 1,000 synthetic events.*

### 9.2 Continuous Risk Scoring & Feedback Loop
RuntimeLens incorporates two operational SRE extensions:
- **Exposure-Based Risk Scoring:** Combines model severity, network blast radius, and privilege exposure into a single continuous metric ($[0, 100]$) to prioritize analyst review queues.
- **Human Feedback Baseline Diff Loop:** Generates declarative Git diffs when human analysts reclassify benign false positives, facilitating continuous baseline drift adaptation.

---

## 10. Limitations & Threats to Validity

1. **Synthetic Lab Environment:** All experiments were conducted in controlled laboratory cluster simulations; real-world enterprise clusters feature broader diversity in workload types and background noise.
2. **Air-Gapped eBPF Constraints:** Full modern eBPF BTF tracing requires standard Linux kernels (Ubuntu 24.04 with kernel 6.8); virtualization environments with custom non-BTF kernels (e.g. OrbStack macOS virtualization) require standard Multipass or native Linux instances.
3. **Model API Spend & Caching:** Hosted model calls incur network latency and token costs. While SHA-256 state caching eliminates cost on repeat incidents, high-throughput clusters require rule pre-screening to maintain operational budgets.

---

## 11. Conclusion & Future Work

RuntimeLens demonstrates that combining multi-source cluster telemetry with declarative workload baselines and typed decision models provides superior runtime threat classification compared to isolated kernel syscall rules. By enforcing SRE safety defaults—including zero pod delete permissions, dry-run defaults, and reversible NetworkPolicy quarantine with automated TTL rollback—RuntimeLens bridges the gap between probabilistic artificial intelligence and mission-critical cloud infrastructure availability.

Future work includes exploring on-node local Small Language Model (SLM) quantization (such as quantized Llama-3-8B-Instruct or Phi-3) to eliminate external API latency, and expanding eBPF probes to support memory-safety anomalies in native container runtimes.

---

## 12. References & Data Availability

1. **ScaleDown AI.** (2026). *ScaleDown Platform Documentation and Typed Decisions API Reference.* Available at: `https://docs.scaledown.ai`.
2. **ScaleDown API Specification.** (2026). *Decisions API: Choice, Score, and Noul Endpoint Reference.* Available at: `https://docs.scaledown.ai/api-reference/decisions.md`.
3. **Falco Project.** (2026). *Falco: Cloud-Native Runtime Security.* CNCF Graduated Project Documentation.
4. **Cilium Authors.** (2026). *Cilium eBPF-Based Networking, Observability, and Security.* Linux Foundation.
5. **Kubernetes Authors.** (2026). *Kubernetes Auditing and Pod Security Standards.* CNCF Documentation.
6. **McNemar, Q.** (1947). *Note on the sampling error of the difference between correlated proportions or percentages.* Psychometrika, 12(2), 153–157.
7. **Holm, S.** (1979). *A simple sequentially rejective multiple test procedure.* Scandinavian Journal of Statistics, 6(2), 65–70.

*All source code, test suites, and offline mock fixtures are archived in the RuntimeLens project repository.*
