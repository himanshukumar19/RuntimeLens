# REPORT_DELTA.md — Architectural & Implementation Discrepancy Log

This document records every concrete discrepancy between the original submitted project report (`docs/source/Intelligent_Security_Project_Report (1).pdf` and `docs/source/architecture_poster.jpeg`) and the real, empirically verified implementation codebase.

---

## 1. Primary Model Identity: ScaleDown Classify-1 vs. TypeSafe Jev

### 1.1 Scope of the Discrepancy
The original project report and architecture poster describe the decision model as **"Jev"**, a proprietary "System One" foundation model reported to be released by **TypeSafe AI** in September 2026. The implementation adapter (`src/runtimelens/classifiers/scaledown.py`), verification tests (`tests/contract/test_scaledown_adapter.py`, `tests/live/test_smoke.py`), and documentation (`docs/MODEL_API.md`) exclusively evaluate and integrate **ScaleDown Classify-1** (hosted at `https://api.scaledown.xyz/v1/scaledown`), authorized under Decision D-00.

### 1.2 Exhaustive Catalog of "Jev" Occurrences in Academic Artifacts

#### A. Project Report (`docs/source/Intelligent_Security_Project_Report (1).pdf`)
1. **Title Page (p. 1):** Main title: *"Intelligent Security for Containers: ML-Based Runtime and Orchestration Threat Classification Using the Jev Model"*.
2. **Table of Contents (p. 2):** Section 3 title: *"3. The Jev Model"*; Section 6 title: *"6. Classification Design with Jev"*.
3. **Abstract (p. 3):**
   - Line 12: *"...submits that state to Jev, a System One decision model released by TypeSafe AI in September 2026."*
   - Line 14: *"Jev answers a fixed set of typed questions in a single parallel pass..."*
   - Line 20: *"The report explains the system architecture, the internal working of the Jev model..."*
   - Keywords (p. 3): *"Jev; System One;"*.
4. **Section 1.4 Objectives (p. 5):**
   - Bullet 3: *"To use the Jev model as the classification step..."*
   - Bullet 5: *"To plan an evaluation that compares Jev with a rule-based baseline..."*
5. **Section 1.5 Scope and Assumptions (p. 5):**
   - Paragraph 1: *"...access to the hosted Jev API has not yet been obtained..."*
6. **Section 3: The Jev Model (pp. 6–8):**
   - Section 3.1: Entire section titled *"What Jev Is"*, detailing TypeSafe AI, System One, and Reinforcement Learning for Calibrated Decisions (RLCD).
   - Section 3.2: Entire section titled *"Anatomy of a Request"*, detailing requests to Jev.
   - Section 3.3: Entire section titled *"Question Types"*, Table 1 (*"Jev question types"*), and references to Jev.
   - Section 3.4: Discussion of Jev confidence and probability calculations.
   - Section 3.5: Entire section titled *"Versioning and Access"*, referencing `jev-1.13.0`, `jev-latest`, and TypeSafe API access.
   - Section 3.6: Entire section titled *"Suitability and Limitations"*, stating *"Jev fits this project..."* and discussing vendor-reported properties.
7. **Section 4: System Architecture (pp. 8–10):**
   - Section 4.1: *"...the Jev classification step..."*
   - Figure 1 (p. 7): Diagram caption and graphic: *"Internal working of the Jev model..."*
   - Figure 2 (p. 9): Box: *"Jev step: Questions -> Jev model (State + questions) -> Typed output"*.
   - Table 2 (p. 10): Row 5: Component *"Jev step"*, Planned tooling *"Hosted Jev API (access pending)"*.
8. **Section 6: Classification Design with Jev (pp. 11–14):**
   - Section 6 Title: *"Classification Design with Jev"*.
   - Section 6.1: *"The options and their descriptions are given to Jev with every request..."*
   - Table 4 (p. 12): Column 2: *"Description given to Jev (summary)"*.
   - Section 6.2: *"Jev returns a score that can fall between levels..."*
   - Section 6.3: Table 5: Column 2: *"Claim posed to Jev"*.
   - Section 6.4: Figure 3 caption: *"Worked example of one event passing through the Jev step"*; Box: *"Jev model Parallel pass 70 to 500 ms"*.
   - Listing 1 (p. 13): JSON snippet field `"model": "jev-1.13.0"`.
9. **Section 8: Evaluation Methodology (pp. 14–15):**
   - Section 8.1: *"Jev will be compared with two baselines on the same held-out events."*
   - Figure 4 (p. 15): Box: *"Run classifiers: Rules, forest, Jev"*.
10. **Section 9: Risks and Limitations (p. 16):**
    - Paragraph 2: *"...the vendor-reported properties of Jev are not yet independently verified..."*
11. **Section 11: Conclusion (p. 16):**
    - Paragraph 2: *"...the Jev model classifies each suspicious event through typed Choice, Score, and Noul questions in a single parallel pass..."*
12. **Section 12: References (p. 17):**
    - CometAPI. (2026). *Jev by TypeSafe AI: Model specifications and how it works.*
    - Composio. (2026). *TypeSafe Jev guide: How it works and 6 best practical use cases.*
    - Opentweet. (2026). *Jev Choice vs Score vs Noul.*
    - WPS. (2026). *What is Jev? TypeSafe's System One model and its best use cases.*

#### B. Architecture Poster (`docs/source/architecture_poster.jpeg`)
1. **Section 2 Header (Top Banner):** *"Collect runtime and orchestration signals, classify threats using the Jev model, and take automated response actions with human oversight."*
2. **Workflow Step 2:** State generation output box: *"Event State (to Jev)"*.
3. **Workflow Step 3:** Pre-filtering description box: *"Only suspicious events are sent to Jev"*.
4. **Workflow Step 4:** Central classification block header: *"Classification with Jev (Typed Questions)"*; Central graphic badge: *"Jev (System One Model)"*.
5. **Workflow Step 5:** Decision Engine description box: *"Combine Jev's answers with confidence values"*.
6. **Tech Stack Sidebar:** Row 6 entry: *"Jev Model (threat classification)"*.

---

### 1.3 Real Service Contract: ScaleDown Classify-1

ScaleDown Classify-1 implements a specialized Decisions API that evaluates multiple typed questions in a single forward pass over a unified text state.

#### A. Verified Request Format (`POST /v1/scaledown`)
```json
{
  "model": "classify-1",
  "state": {
    "text": "=== RUNTIMELENS INCIDENT STATE ===\nWORKLOAD: tenant-a / payment-style (uid: 91eee01e5c65)\nIMAGE: docker.io/library/alpine:3.19\nPROCESS: nc (parent: sh, pid: 1420)\nCOMMAND: nc -w 1 127.0.0.1 8888\nCPU_USAGE: 0.23 mcores (baseline: 0.15 mcores)\n..."
  },
  "questions": {
    "attack_type": {
      "type": "choice",
      "instructions": "Which single threat category best describes the observed Kubernetes activity?",
      "criteria": {
        "benign": "Expected workload operation, routine maintenance, or normal deployment activity.",
        "container_escape": "Suspicious interaction with the host kernel, access to container runtime sockets, host file paths, or privileged capabilities.",
        "privilege_abuse": "Misuse of Kubernetes orchestration permissions, unexpected service-account token reads, unauthorized Secret access, or execution into adjacent pods.",
        "cryptomining": "Sustained abnormal compute consumption coupled with unexpected outbound network flows to non-standard ports or suspicious binaries running from temporary directories.",
        "unknown": "Telemetry is conflicting, truncated, degraded, or insufficient to confidently determine an attack category."
      }
    },
    "severity": {
      "type": "score",
      "instructions": "Evaluate the operational and security severity of this runtime event.",
      "criteria": [
        "Informational: Standard expected activity or benign baseline event.",
        "Low: Minor anomaly or unusual action with high likelihood of benign intent.",
        "Medium: Suspicious policy violation or unexpected process requiring human investigation.",
        "High: Clear indicator of compromise, sensitive host exposure, or unauthorized credential access.",
        "Critical: Active confirmed container breakout, cluster-wide compromise, or severe denial of service."
      ]
    },
    "baseline_deviation": {
      "type": "noul",
      "instructions": "Is this activity inconsistent with the workload's documented baseline profile?"
    },
    "shell_unexpected": {
      "type": "noul",
      "instructions": "Is an interactive shell execution unexpected for this workload?"
    },
    "resource_exposure": {
      "type": "noul",
      "instructions": "Does this event grant the container unauthorized access to host or cluster resources?"
    },
    "resource_abuse": {
      "type": "noul",
      "instructions": "Is the observed compute and network behaviour consistent with unauthorized resource hijacking or mining?"
    }
  }
}
```

#### B. Verified Response Format (Excerpted from `docs/MODEL_API.md` and Live Call 04)
```json
{
  "model": "classify-1",
  "answers": {
    "attack_type": {
      "type": "choice",
      "choice": "privilege_abuse",
      "probabilities": {
        "benign": 0.0484,
        "container_escape": 0.2346,
        "privilege_abuse": 0.6195,
        "cryptomining": 0.0234,
        "unknown": 0.0741
      },
      "confidence": 0.6195
    },
    "severity": {
      "type": "score",
      "score": 2.4060,
      "confidence": 0.4855,
      "legend": {
        "0": "Informational: Standard expected activity...",
        "1": "Low: Minor anomaly...",
        "2": "Medium: Suspicious policy violation...",
        "3": "High: Clear indicator of compromise...",
        "4": "Critical: Active confirmed container breakout..."
      },
      "probabilities": {
        "0": 0.0234,
        "1": 0.0523,
        "2": 0.4290,
        "3": 0.4855,
        "4": 0.0098
      }
    },
    "baseline_deviation": { "type": "noul", "noul": 0.8286 },
    "shell_unexpected": { "type": "noul", "noul": 0.7131 },
    "resource_exposure": { "type": "noul", "noul": 0.6604 },
    "resource_abuse": { "type": "noul", "noul": 0.0554 }
  },
  "usage": {
    "input_tokens": 1910,
    "output_tokens": 6,
    "cost": 0.0000955
  }
}
```

### 1.4 Support for Typed Choice, Score, and Flags with Probabilities
- **Choice Questions:** Fully supported. Returns the discrete top choice, full probability distribution over all defined keys, and an explicit `confidence` field equal to $\max P(\text{class})$.
- **Score Questions:** Fully supported. Evaluates an ordered list of criteria (levels 0 to 4). Returns level probabilities, an explicit `confidence` field ($\max P(\text{level})$), and a continuous `score` computed as the mathematical expected value:
  $$\text{Score} = \sum_{i=0}^{4} i \cdot P(\text{level}_i) \in [0.0, 4.0]$$
- **Noul (Flag) Questions:** Fully supported. Evaluates a binary proposition and returns a scalar probability `noul` $\in [0.0, 1.0]$.

### 1.5 Required Corrections in Report Sections

#### Corrections to Section 6 (Classification Design)
1. **Schema Field Names:**
   - Listing 1 and Section 6.1 must be updated: ScaleDown uses `"criteria"` for Choice options (mapping label $\rightarrow$ description) and `"criteria"` for Score rubrics (ordered array of level strings). The report's `"options"` and `"levels"` keys must be changed to `"criteria"`.
   - ScaleDown accepts state as a single unified text string under `"state": {"text": "..."}`, rather than nested JSON keys (`"event"`, `"facts"`, `"baseline"`).
2. **Confidence Gating Mechanics:**
   - Section 6.2 and 6.4 imply confidence measures distribution "peakedness/spread". Empirically, ScaleDown sets `confidence` identically to the top-class probability ($\max P$). The confidence gate threshold (provisional 0.70) operates directly as a minimum top-class probability filter.
3. **Severity Value Range:**
   - Report Section 6.2 states severity is 1 to 5. ScaleDown natively scores levels 0 to 4 (producing expected values in $[0.0, 4.0]$). The decision engine maps this via continuous transformation $\text{Severity} = \text{Score} + 1.0 \in [1.0, 5.0]$. This formula must be documented explicitly in Section 6.2.

#### Corrections to Section 8 (Evaluation, Latency, and Cost)
1. **Model Latency:**
   - Section 3.2 and Section 8 cite unverified vendor latency claims of "70 to 500 ms".
   - Measured real ScaleDown latency across live smoke test calls is **895.8 ms to 1056.8 ms (median: 1048.2 ms)**. Section 8.5 must reflect measured ~1.05s latency percentiles.
2. **Cost Economics:**
   - Section 8.2 must report measured ScaleDown API token costs: a full 6-question evaluation consumes ~1,910 input tokens and 6 output tokens, costing **$0.0000955 per event** (~$0.095 per 1,000 evaluated incidents).

---

## 2. Additional Architectural & Implementation Differences

| # | Topic / Component | Report Statement (`docs/source/`) | Implementation (`src/` & `scripts/`) | Impact | Proposed Fix |
|:---|:---|:---|:---|:---|:---|
| **1** | **Attack Scope** | Scoped to 3 attack classes (`container_escape`, `privilege_abuse`, `cryptomining`) plus `benign` and `unknown` (Section 1.5, Section 6.1, Table 4). | Implementation initially added `exfiltration` as a 4th attack class in pilot scripts. | Expands class taxonomy beyond pre-registered scope; exfiltration under default-deny netpol required artificial loopback listeners. | **Change Code:** Formally drop `exfiltration` as a threat class (Decision D-24). Scope dataset to 3 attack classes + benign + unknown. |
| **2** | **Metrics Ingestion Architecture** | "Prometheus metrics" scraped via sliding-window PromQL queries (Table 2, Figure 2, Section 4.3). | Collector directly queries kubelet cAdvisor Summary API (`/api/v1/nodes/.../proxy/stats/summary`). | Bypasses deploying full Prometheus server in early stages; Ticket 14 still requires Prometheus metrics exporter. | **Change Report:** Clarify in Section 4.3 that raw per-run capture utilizes kubelet cAdvisor summary endpoints directly, while Prometheus server is deployed in Phase 9 (Ticket 14). |
| **3** | **Trivy Vulnerability Scans** | "Image scan Trivy results" collected per event (Section 4.1, Table 2). | One static cached vulnerability report (`docker.io/library/alpine:3.19`) is attached to each run directory. | Avoids redundant CLI execution on identical base image; static CVE data does not vary dynamically per run. | **Change Report:** Clarify in Section 5.3 that static image vulnerability profiles are cached by image digest rather than dynamically re-scanned on every alert. |
| **4** | **Egress Probing Realism** | Outbound mining pool traffic and exfiltration connections are observed dynamically on external networks (Section 5.2, Table 4). | Containers establish an in-pod loopback listener (`127.0.0.1:<port>`) and send a UDP datagram to `198.51.100.22` (Decision D-21). | In real attacks, traffic routes to remote WAN pools; loopback connect is a safe simulation compromise required by isolated Kind networking. | **Change Report:** Disclose in Section 9 (Risks and Limitations) that network egress probing uses in-pod loopback and inert UDP targets to prevent external network exposure. |
| **5** | **Falco Rule Naming & Anti-Leakage** | Uses rules like `Suspicious Mining Port Egress`, `Read Sensitive Host Information Untrusted` (Section 4.3). | Rule names and tags were sanitized in Stage 1 remediation (e.g., tags `cryptomining` changed to `egress_anomaly`) to prevent label leakage. | Prevents feature extractor from cheating on ground-truth class names embedded in Falco alert tags. | **Change Report:** Document in Section 5.4 that rule tags and names were sanitized as an anti-leakage control. |
| **6** | **Pod Termination** | "Terminate the pod and alert" listed as an automated SRE response tier (Abstract, Table 2, Table 6). | Termination is strictly NOT implemented. Zero delete verbs exist in RBAC, controller code, or manifests (Decision D-13). Reversible quarantine is the maximum automated action. | Eliminates catastrophic risk of automated cluster bricking; satisfies SRE principle of reversible containment. | **Change Report:** Update Abstract, Table 2, and Table 6: reframe pod termination as "Design and future work only; zero delete permissions implemented". |
| **7** | **Workload Tenant Names** | Figures show varied naming (e.g. `payments` in Tenant B). | Strictly standardized across 3 namespaces (`tenant-a`, `tenant-b`, `tenant-c`) each running 4 workloads: `web`, `api`, `database`, `payment-style`. | Guarantees consistent evaluation across all paired counterfactuals. | **Change Report:** Harmonize tenant naming across Section 5.1 and Figure 2. |
| **8** | **Audit Telemetry Filtering** | Generic Kubernetes audit logs expose role changes and execs (Section 4.3). | Collector matches by target namespace (`obj_ns == ns`), source service account (`system:serviceaccount:<ns>:*`), and pod UID to capture cross-namespace events. | Captures authentic cross-namespace authorization failures (`list secrets` in adjacent tenants). | **Change Report:** Detail cross-namespace service account audit correlation in Section 4.3. |

---

### Summary of Required Actions
- **Code Changes:** Drop `exfiltration` class (Decision D-24), enforce pod cooldown rules, make sustained-CPU gate variant-aware.
- **Report Changes:** Replace all 55+ occurrences of Jev with ScaleDown Classify-1, update API request/response schemas in Section 6, update measured latency/cost in Section 8, and record architectural disclosures (cAdvisor, loopback egress, design-only termination).
