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

**Raw measurement file path:** `tests/fixtures/scaledown/live_smoke_responses.json`
**Producer:** `tests/live/test_smoke.py` (live smoke test, calls 01–14, call count cap 20)
**Execution date (fixture metadata):** `2026-10-17T21:28:27Z`
**Endpoint:** `https://api.scaledown.xyz/v1/scaledown`
**Total calls executed:** `14`

1. **Model Latency — measured, not vendor-reported**
   - The report (Section 3.2 / Section 8) cites unverified vendor claims of **"70 to 500 ms"** for the decision step. These must be removed entirely.
   - Raw per-call latency, all 10 successful 6-question calls, sorted ascending:

     | # | Call ID | Latency (ms) | Input tokens | Cost (USD) |
     |:--|:--|--:|--:|--:|
     | 1 | `call_12_latency` | 895.78 | 1820 | 0.0000910 |
     | 2 | `call_13_paired_debug_authorized` | 925.45 | 1952 | 0.0000976 |
     | 3 | `call_14_paired_payment_unauthorized` | 979.46 | 1934 | 0.0000967 |
     | 4 | `call_05_cache_bypass` | 1031.67 | 1910 | 0.0000955 |
     | 5 | `call_10_latency` | 1039.29 | 1808 | 0.0000904 |
     | 6 | `call_11_latency` | 1047.32 | 1808 | 0.0000904 |
     | 7 | `call_07_latency` | 1049.02 | 1808 | 0.0000904 |
     | 8 | `call_08_latency` | 1050.91 | 1856 | 0.0000928 |
     | 9 | `call_09_latency` | 1056.78 | 1808 | 0.0000904 |
     | 10 | `call_04_all_three` | 1159.86 | 1910 | 0.0000955 |

     **Full observed range: 895.78 ms – 1159.86 ms. Median: 1043.30 ms.**
   - The fixture's own summary block (`latency_summary_ms`) reports `{min: 895.78, median: 1048.17, max: 1056.78}`. Per `tests/live/test_smoke.py` lines 345–355, that block is computed from the **six dedicated latency-probe calls (07–12 only)**, not from all 6-question calls. Recomputing over all ten 6-question calls yields min 895.78 / median 1043.30 / max 1159.86. **The report must quote the wider range (895.78–1159.86 ms) so the cold-start outlier `call_04` is not hidden.**
   - Single-question calls are faster and must be reported separately: `call_01_choice_only` 1680.99 ms (first call, includes connection setup), `call_02_score_only` 945.21 ms, `call_03_noul_only` 1014.17 ms. `call_06_deliberate_invalid` returned HTTP 422 in 824.34 ms.
   - Section 8.5 must therefore state: decision-step latency **≈ 0.90–1.16 s (median ≈ 1.04 s)**, i.e. roughly **2× the report's claimed 500 ms ceiling**, and the 5.0 s hard timeout in `docs/MODEL_API.md` Section 6 leaves only ~4× headroom.

2. **Cost Economics — measured token costs**
   - Measured per 6-question decision: **1,808–1,952 input tokens**, 1–6 output tokens, **$0.0000904 – $0.0000976**.
   - Mean across the ten 6-question calls: **$0.00009307 per incident**, i.e. **≈ $0.093 per 1,000 evaluated incidents**.
   - Single-question reference points from the same fixture: `call_01_choice_only` 448 in-tokens / $0.0000224; `call_02_score_only` 440 / $0.0000220; `call_03_noul_only` 257 / $0.0000129.
   - For the proposed 400-run dataset with **one decision per run**, the projected API spend at the 6-question configuration is **≈ $0.037** for a full single pass, and **≈ $0.093 per 1,000 incidents** for any larger evaluation loop. Section 8.5 must use these measured figures rather than vendor pricing claims.

3. **Determinism caveat that Section 8 must not omit**
   - The two paired calls (`call_13_paired_debug_authorized` 925.45 ms / $0.0000976 vs `call_14_paired_payment_unauthorized` 979.46 ms / $0.0000967) show non-deterministic latency and token counts for near-identical request shapes. Section 8 must not claim reproducible per-call cost or latency; only distribution-level statistics are supportable.

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
| **9** | **Container-Escape HostExposure Is Simulated, Never a Real Host Escape** | Report Section 3, Section 5.2 and Table 4 describe container escape as an attacker reaching the host kernel, container runtime socket or host filesystem. | Escape scenarios mount an **inert 0-byte regular file** at `/opt/runtimelens-dummy/docker.sock` (and `/opt/runtimelens-dummy/containerd.sock`) on the kind control-plane node via `hostPath`, executed only in the ephemeral `sandbox-workloads` namespace with `pod-security.kubernetes.io/enforce: privileged`. `scripts/scenario_safety_lint.py` hard-blocks `/var/run/docker.sock`, `/run/containerd`, `/var/run/containerd`, `/var/run/crio`, `/run/crio`, any hostPath outside the two-entry allowlist, `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `privileged: true` outside `sandbox-workloads`, and class-leak tokens in any name or label. | The escape class is **behaviourally simulated, not a real breakout**. No runtime socket, no host filesystem write, and no privileged container ever touches the kind node beyond reading one inert file. Feature `host_runtime_socket_mounted` is set by matching the *documented dummy path*, not by observing a real socket handshake. Section 5 must disclose that escape telemetry proves *detector and policy* behaviour, not exploitability. | **Change Report:** Add an explicit "Simulated vs. real escape" limitation note in Section 9 (Risks and Limitations) and in the escape scenario row of Table 4, naming the two allowed dummy paths and the linter that enforces them. |

---

### Summary of Required Actions
- **Code Changes:** Drop `exfiltration` class (Decision D-24), enforce pod cooldown rules, make sustained-CPU gate variant-aware.
- **Report Changes:** Replace all 55+ occurrences of Jev with ScaleDown Classify-1, update API request/response schemas in Section 6, update measured latency/cost in Section 8, and record architectural disclosures (cAdvisor, loopback egress, design-only termination).

---

## 3. What Can and Cannot Be Made Real Inside the Kind Lab (Escape & Privileged Scenarios)

The question "can a real `hostPath` mount or a real privileged pod be run safely inside the kind node?" has a precise, auditable answer: **yes for both, but only under the sandbox conditions already enforced by the repository's safety linter.** The kind control-plane node is itself a Docker container (`runtimelens-control-plane`), so anything a pod can reach through `hostPath` or `privileged: true` is already confined inside that container's mount namespace — not the macOS host, and not the VM's systemd namespace.

### 3.1 Real `hostPath` mount of a harmless path — SAFE, and already exercised

**Exactly what is mounted today** (`docs/SCENARIO_SAFETY_SHEET.md` lines 20–41, `docs/SCENARIOS.md` line 16):

```yaml
volumes:
- name: system-socket-link
  hostPath:
    path: /opt/runtimelens-dummy/docker.sock
    type: File
```

The target is provisioned on the node as a **0-byte regular file with mode 0644** — not a socket, not a directory, not a device node:

```bash
docker exec runtimelens-control-plane mkdir -p /opt/runtimelens-dummy
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/docker.sock
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/docker.sock
```

This is a **genuine Kubernetes `hostPath` mount** — the API server performs a real bind mount and the kubelet performs a real mount into the container. Only the *content* is inert. Rationale recorded in the repo: `/var/run` on the node is an active symlink to `/run`, so nothing is ever created there.

**Extension that is also safe (proposed, not yet run):** a real `hostPath` mount of a harmless *directory* with `type: Directory`, containing only non-sensitive node-side scratch content, e.g. `/opt/runtimelens-dummy/etc` (already referenced by `TMPL-ESC-04`). This exercises the `sensitive_host_path_mounted` (feature 01) branch with a real directory mount rather than a file mount. It requires adding one path to `ALLOWED_DUMMY_HOSTPATHS` in `scripts/scenario_safety_lint.py` line 21 and nothing else.

### 3.2 Real privileged pod — SAFE inside kind, already linter-gated

`privileged: true` inside the kind control-plane node container grants device and capability access scoped to that container. The linter enforces it can only appear in one namespace:

```python
# scripts/scenario_safety_lint.py:144-150
if sec_ctx.get("privileged") is True and namespace not in ALLOWED_LAB_NASESPACES:
    errors.append(
        f"privileged: true forbidden in namespace '{namespace}' "
        f"(Must be in {sorted(ALLOWED_LAB_NAMESPACES)})"
    )
```

with `ALLOWED_LAB_NAMESPACES = {"sandbox-workloads"}` (line 19). The namespace is created per run and deleted immediately after, so `privileged` never coexists with a tenant workload or with the default-deny NetworkPolicies that govern `tenant-a`/`b`/`c`.

### 3.3 Invariants the linter already blocks (raw excerpt, `scripts/scenario_safety_lint.py`)

```python
ALLOWED_DUMMY_HOSTPATHS: Final[frozenset[str]] = frozenset(
    {
        "/opt/runtimelens-dummy/docker.sock",
        "/opt/runtimelens-dummy/containerd.sock",
    }
)

FORBIDDEN_RUNTIME_SOCKET_PATTERNS: Final[tuple[str, ...]] = (
    "/var/run/docker.sock",
    "/run/containerd",
    "/var/run/containerd",
    "/var/run/crio",
    "/run/crio",
)
```

```python
# lines 101-107 — host namespaces are unconditionally forbidden
if pod_spec.get("hostPID") is True:
    errors.append("Forbidden hostPID: true")
if pod_spec.get("hostNetwork") is True:
    errors.append("Forbidden hostNetwork: true")
if pod_spec.get("hostIPC") is True:
    errors.append("Forbidden hostIPC: true")
```

```python
# lines 116-136 — real sockets blocked, allowlist enforced, lab-namespace-only
if any(real_sock in hp_path.lower() for real_sock in FORBIDDEN_RUNTIME_SOCKET_PATTERNS):
    errors.append(f"Forbidden real runtime socket hostPath: '{hp_path}'")
if hp_path not in ALLOWED_DUMMY_HOSTPATHS:
    errors.append(
        f"hostPath outside dummy allowlist: '{hp_path}' "
        f"(Allowed: {sorted(ALLOWED_DUMMY_HOSTPATHS)})"
    )
if namespace not in ALLOWED_LAB_NAMESPACES:
    errors.append(
        f"hostPath volume forbidden in tenant namespace '{namespace}' "
        f"(Violates Pod Security Standards baseline; must use "
        f"{sorted(ALLOWED_LAB_NAMESPACES)})"
    )
```

### 3.4 The four hard "never" rules

| Rule | Enforcement |
|:--|:--|
| Never mount a real runtime socket (`/var/run/docker.sock`, `/run/containerd`, `/var/run/containerd`, `/var/run/crio`, `/run/crio`) | `FORBIDDEN_RUNTIME_SOCKET_PATTERNS`, linter lines 28–34 + 116–120 |
| Never use `hostPID`, `hostNetwork`, or `hostIPC: true` | Linter lines 101–107, unconditional |
| Never set `privileged: true` or any `hostPath` outside the `sandbox-workloads` namespace | Linter lines 129–136 and 146–150 |
| Never reference an external host, domain, or public IP in command/args/env | Linter lines 166–186, with an explicit allowlist for `*.svc`, `*.cluster.local`, `127.`, `10.`, `172.18.`, `localhost` |

**Conclusion:** a real `hostPath` file mount and a real `privileged: true` pod are both runnable inside the kind node under these constraints, and the repository already runs the file-mount form in production lab runs. What remains simulated is the *exploit payload*, not the Kubernetes mechanism. The report must state this distinction rather than implying a real host breakout was achieved.

---

## 4. Stage 4a Part 1 Refinements: Telemetry Grounding & Feature Provenance

### 4.1 Dummy-Path Proxy for the Sensitive Mount Rule
- **Discrepancy:** The custom Falco rule `Launch Sensitive Mount Container` (`lab/falco/rules/lab-rules.yaml`) originally watched only production paths: `(fd.name startswith /var/run/docker.sock or fd.name startswith /run/containerd/containerd.sock or fd.name startswith /etc/kubernetes)`. In the lab cluster, mounting live node container sockets is strictly blocked by the safety linter (`scripts/scenario_safety_lint.py`) to prevent host daemon compromise. Consequently, `TMPL-ESC-03`, `TMPL-ESC-04`, and `TMPL-ESC-06` mounting inert dummy files under `/opt/runtimelens-dummy` failed to trigger the rule.
- **Resolution & Realism Boundary:** The rule condition was updated in `lab/falco/rules/lab-rules.yaml` and `lab/falco/falco-values.yaml` to detect `fd.name startswith /opt/runtimelens-dummy`. In production Kubernetes environments, this rule monitors real container engine sockets; in this safety-gated research lab, it monitors the allowlisted inert dummy path proxy.

### 4.2 NSS Exemption List for Sensitive Identity File Reads
- **Discrepancy:** `Read Sensitive Host Information Untrusted` initially flagged any read of `/etc/passwd` by processes outside `(login, passwd, useradd, groupadd)`. In Linux, standard diagnostic commands (`ls -l`, `id`, `whoami`, `ps aux`) invoke libc Name Service Switch (NSS) functions (`getpwuid`, `getgrgid`) that open `/etc/passwd` to translate numeric UIDs/GIDs into human-readable names. This caused benign self-audits (`TMPL-BEN-11`) and innocuous directory listings (`ls -l` in `TMPL-ESC-03`) to emit high-priority identity-access alerts.
- **Resolution:** The Falco rule was refined to decouple `/etc/shadow` from `/etc/passwd`: reads of `/etc/shadow` (and `/opt/runtimelens-dummy/etc/shadow`) remain unconditionally flagged, while reads of `/etc/passwd` explicitly exempt standard read-only utilities: `ls`, `id`, `whoami`, `ps`, `top`, `w`, `uptime`.

### 4.3 Deterministic Pod-Spec Fact Derivation for Features 00, 01, and 02
- **Discrepancy:** In early pipeline drafts, features `host_runtime_socket_mounted` (Feature 00), `sensitive_host_path_mounted` (Feature 01), and `privileged_container` (Feature 02) were extracted by text matching against Falco event descriptions and rule names. When Falco rules failed to fire (e.g. `Debugfs Launched in Privileged Container` missing from minimal Alpine images), Feature 02 evaluated to `0.0` despite the pod specification explicitly setting `securityContext.privileged: true`.
- **Resolution (Aligning with Report Section 5.3):** Project Report Section 5.3 (Table 3: *"Mounts and privileges — Pod specification"*) states: *"Deterministic facts, such as whether a host runtime socket is mounted, are computed by the normalizer and written into the state as facts rather than left for the model to infer."* The collector (`PerRunTelemetryCapture.attach_pod_spec`) now records the pod's structural configuration into `pod/spec.json` during execution. The feature extractor (`src/runtimelens/features/extractor.py`) derives Features 00–02 directly from `pod/spec.json`:
  - Feature 00 (`host_runtime_socket_mounted`): `1.0` if `spec.volumes[].hostPath.path` contains `docker.sock` or `containerd.sock`.
  - Feature 01 (`sensitive_host_path_mounted`): `1.0` if `spec.volumes[].hostPath.path` references `/etc/kubernetes` or `/opt/runtimelens-dummy/etc`.
  - Feature 02 (`privileged_container`): `1.0` if any container sets `securityContext.privileged: true`.
- **Anti-Leakage Verification:** The stored `pod/spec.json` strips all pod and namespace labels, annotations, scenario IDs, and class names. Feature extraction operates strictly on structural volume types and container security flags, guaranteeing zero metadata leakage.

---

## 5. Stage 4a Part 2 — Measurement Resolution, Expected-Rule Correctness and Length-Bin Confound

### 5.1 Decision D-26 — The `burst` CPU band was narrower than the measurement noise floor
- **Discrepancy:** The `burst` expected-CPU-profile gate required the cAdvisor peak to fall inside `[30, 100]` mcores. The kubelet cAdvisor summary API is polled on an asynchronous ~10 s interval, so a CPU spike shorter than one sampling window is observed as a window average rather than at its true peak.
- **Measured evidence (real telemetry, Stage 4a Part 1):** the *identical* `TMPL-UNK-03` command measured **peak 25.77 mcores** on attempt 1 and **peak 117.34 mcores** on attempt 2 — a ~4.5x spread produced purely by sampling-window alignment. The former band therefore classified the same workload as both "no burst" and "sustained mining", and the dataset gate returned `GATE VERDICT: FAILED` on a run whose behaviour was identical to the passing attempt.
- **Resolution:** Decision D-26 widens the band to **peak in [20, 150] mcores with median < 100 mcores**, defined once in `src/runtimelens/eval/cpu_bands.py` and applied identically by the dataset gate, the per-run gate and the runner. The band remains strictly disjoint from the `high` (full-throttle mining) band. Both attempts of the identical command now pass, and all five pre-existing real mining runs still pass.

### 5.2 Decision D-27 — The sustained-CPU ratio was not robust to the cAdvisor first-sample lag
- **Discrepancy:** The `high` and `throttled` gates computed the *share of samples above the threshold* over **all** cAdvisor samples. The first one or two samples of a run are taken before the container's CPU accounting window has accumulated and report 0.00 mcores regardless of the workload.
- **Measured evidence (real telemetry):** `run-s4a-09` (TMPL-MNR-03, throttled mining) produced 7 samples in both attempts — attempt 1 `[0.00, 75.59, 75.59, 100.58, 100.51, 100.51, 99.78]` and attempt 2 `[0.00, 0.00, 46.64, 102.39, 101.59, 101.59, 89.69]`. The share of samples at or above 40 mcores moved from **85.7%** to **71.4%** purely because the lag window covered one sample in one attempt and two in the other.
- **Resolution:** Decision D-27 computes the ratio over **post-lag samples only** (at least 15 s after the first sample), requires at least 4 post-lag samples, and adds a **strict post-lag median floor** (>= 100 mcores for `high`, >= 40 mcores for `throttled`). Both attempts now yield 5/5 post-lag samples at or above 40 mcores with a post-lag median of 100.51 m and 101.59 m respectively. The gate is **not weaker** than the ratio it replaces: the post-lag median floor rejects a workload that spikes briefly and then idles (e.g. `[0, 90, 90, 2, 1, 0]`, legacy ratio 33%, post-lag median 1.0 m), and every pre-existing real mining run still passes the stricter gate.

### 5.3 Six `Expected Falco Rules` entries in the scenario plan named rules that could never fire
- **Discrepancy:** The master template registry in `docs/SCENARIO_PLAN_v2.md` expected rules that are unreachable under the deployed rule set or the executed command.
  - `TMPL-ESC-02` and `TMPL-ESC-07` expected `Read Sensitive Host Information Untrusted` while reading `/proc/kcore`, `/proc/sys/kernel/hostname` and `/proc/1/root` — none of which is an identity file.
  - `TMPL-ESC-05` expected the same rule while probing the **cgroup v1** `release_agent` file, which does not exist under Linux cgroup v2.
  - `TMPL-ESC-06`, `TMPL-ESC-08` and `TMPL-ESC-10` expected `Launch Sensitive Mount Container` while mounting **no `hostPath` volume at all** (they are `privileged: true` only), so no file descriptor could ever carry a mounted host path.
  - `TMPL-ESC-10` and `TMPL-UNK-07` additionally expected a rule named `Policy Warning`, **which is not a deployed Falco rule in this project at all** (neither a lab custom rule nor a `falco-9.2.0` stock rule) and therefore has never been, and never can be, an observable.
- **Resolution:** All six rows are corrected in `docs/SCENARIO_PLAN_v2.md` §3.6.1. `TMPL-ESC-05`, `TMPL-ESC-08` and `TMPL-ESC-10` are additionally replaced by safe, real, executable alternatives (§3.6.2) that preserve the class's feature coverage: feature 00 is `True` in 2 templates, feature 01 in 2, and feature 02 in 4. The escape budget is unchanged at **10 templates / 80 runs / 58 dev / 22 test** because the three replacements reuse the same template IDs and run counts.
- **Report impact:** Section 5.1 (Table 4) must not claim a "sensitive mount" detection for privileged-only escape scenarios. The class-level signal for those scenarios rests on the pod-spec facts (features 00–02) and the audit verbs, which is exactly the architecture described in Section 5.3 (Table 3).

### 5.4 The `privilege_abuse` class collapses into a single command-length bin (declared confound)
- **Discrepancy:** Anti-confounder rule 2 in `docs/SCENARIO_PLAN_v2.md` requires every class to span all three command-length bins at approximately 2 / 3 / 3 templates per class. Stage 4a Part 2 measured the real command lengths and showed this is **physically impossible** for `privilege_abuse`.
- **Measured evidence:** the audit collector captures an event only when `objectRef.namespace` equals the workload's own namespace, or the requester is `system:serviceaccount:<ns>:*`, or the request carries the workload pod name in the authentication extra. A **cross-tenant** request can therefore only be captured through the ServiceAccount token. The token read costs 57 characters and the authenticated `wget` invocation costs 63 characters, so the shortest cross-tenant, audit-attributable request is 168 characters (174 as `proc.cmdline`). The shortest ServiceAccount-authenticated request that is audited at all (API discovery, `https://10.96.0.1/api`) is 141 characters; the shortest unauthenticated request that is still captured (own-namespace collection `GET`) is 82 characters. **Nothing that produces a captured audit event fits inside the `30–80` bin**, because dropping `--no-check-certificate` makes the TLS handshake fail against the API server's self-signed certificate and the request is never issued.
- **Resolution:** the length bins of `TMPL-PRV-02` (175), `TMPL-PRV-04` (181), `TMPL-PRV-05` (197), `TMPL-PRV-06` (180), `TMPL-PRV-07` (223) and `TMPL-BEN-06` (175) are corrected to their true `151–250+` bin, alongside the Part 1 corrections of `TMPL-PRV-01` (219) and `TMPL-PRV-03` (207). The resulting distribution is `12 / 17 / 26` templates across the three bins, with `privilege_abuse` occupying `0 / 0 / 8`. `command_length` (feature 06) is therefore **declared a confound** for this dataset, and three mandatory compensating controls are specified in §3.6.3: a length-bin coverage assertion in the dataset gate, a feature-ablation report in `docs/EVALUATION_PLAN.md`, and two precisely specified re-scoping options (an unauthenticated own-namespace enumeration at 88 characters and a ServiceAccount-authenticated API-discovery probe at 147 characters) that are documented but **not applied** because they change what a template does and therefore require an approved template-edit round.

---

## 6. Decision D-28 — `command_length` Removed from the Classifier Feature Set (19 -> 18 Features)

### 6.1 The discrepancy
- **Discrepancy:** the classical-ML feature set contained a `command_length` feature (index 06 of 19). Because the master template registry forces every `privilege_abuse` template into the longest command-length bin, this single feature was a near-perfect class marker for the dataset.
- **Proof (not assumption).** The audit collector (`PerRunTelemetryCapture.capture_k8s_audit_events`) captures an event only when `objectRef.namespace` equals the workload's own namespace, or the requester is `system:serviceaccount:<ns>:*`, or the request carries the workload pod name in the authentication extra. A **cross-tenant** request can therefore only be captured through the ServiceAccount token, and the token read (57 characters) plus the authenticated `wget` invocation (63 characters) cost 120 characters before the URL. The shortest cross-tenant, audit-attributable request is 168 characters (174 as `proc.cmdline`); the shortest ServiceAccount-authenticated request that is audited at all is 141 characters; the shortest unauthenticated request that is still captured is 82 characters; and **nothing that produces a captured audit event fits inside 80 characters at all**, because dropping `--no-check-certificate` makes the TLS handshake fail against the API server's self-signed certificate. Every `privilege_abuse` template is consequently in the `151–250+` bin, while `benign`, `container_escape`, `cryptomining` and `unknown` all have templates in the shorter bins.
- **Measured confirmation:** on the Stage 4a Part 1 smoke (ten runs, one per template) a Random Forest trained on `command_length` **alone** reached **Macro-F1 = 1.0000** purely by memorising the non-overlapping length ranges, and the label-permutation baseline on the same ten runs scored 0.9314 — a gap of 0.07 that is itself an artifact of the same shortcut. The `151–250+` band held all four `privilege_abuse` runs and no other run.

### 6.2 The change
- `src/runtimelens/features/extractor.py`: `FEATURE_NAMES` now lists **18** features; `command_length` is removed from the vector returned by `extract_features_from_run_dir()`. The value is still computable, but only through the new diagnostic-only helper `extract_command_length(run_dir)`, exported alongside `EXCLUDED_DIAGNOSTIC_FEATURES = ("command_length",)`.
- `src/runtimelens/eval/train_rf.py` consumes the 18-feature vector unchanged (`n_features` is derived from `len(FEATURE_NAMES)`).
- The **ScaleDown state** never carried a command-length field. That is now enforced rather than assumed: `tests/unit/test_feature_set_exclusions.py::test_scaldown_state_carries_no_command_length_field` asserts that the serialized state contains no `command_length`, `raw_length`, `cmd_len` or `length=` token. The state still carries the *semantic* command text, which is required for the model to reason about the behaviour; that text is truncated to 128 characters by the sanitizer, so all commands longer than 128 characters are length-equivalent in the state. This residual is disclosed rather than hidden.
- `scripts/verify_dataset.py` keeps reporting the confound, explicitly labelled:
  ```text
  Feature 17 (orch_verb_get_secret): Macro-F1 = 0.2333
  Diagnostic (EXCLUDED from classifier feature set, Decision D-28): command_length: Macro-F1 = 1.0000
  ```
- **Feature index shift.** The features that followed `command_length` move down by one position: `is_cpu_abnormal` 07 -> 06, `cpu_usage_mcores` 08 -> 07, ..., `orch_verb_get_secret` 18 -> 17. The new ordering is asserted by `test_feature_indices_after_removal_are_stable`.

### 6.3 Why removal, not regularisation
Removing the feature eliminates the shortcut at its source. Regularising it (for example by bucketing the length, or by keeping it and adding a length-matched benign control) would leave a quantity in the vector that is *provably* correlated with the class label by construction of the template registry, and the label-permutation baseline already shows that the ten-run sample cannot distinguish a real signal from that artifact. Keeping the value as a **diagnostic** preserves the audit trail: the confound stays visible in every gate report instead of being silently dropped, which is what the project's Evidence & Truthfulness Guardrails require.

### 6.4 Consequence for the report's feature claims
- Report Section 5.3 (Table 3) and Section 8 must state that the classical-ML baseline uses **18** deterministic features, and that the raw command length is deliberately excluded.
- `docs/SPEC.md` (State Hardening) and `docs/PREREGISTRATION.md` (deviation draft) have been updated to match.
- The declared-confound controls in `docs/SCENARIO_PLAN_v2.md` §3.6.3 are retained: the length-bin coverage assertion in the dataset gate and the feature-ablation report in `docs/EVALUATION_PLAN.md` must still be implemented before 06c.

---

## 7. Stage 4a Round 2 — Template Re-Scoping and the Escape Replacements

### 7.1 The two `privilege_abuse` re-scopings (proposed template-edit round)
The Stage 4a Part 2 analysis showed that the `privilege_abuse` class could not be spread across the command-length bins, and proposed two re-scopings. Both are now **applied as a proposed template-edit round** (Stage 4a Round 2) and are executed only inside the Round 2 review loop.

| Template | New exact command | `proc.cmdline` | Bin | Class meaning preserved because |
|:---|:---|--:|:---:|:---|
| `TMPL-PRV-02` | `wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-b/pods` | **88** | 81–150 | No credential is presented, so the API server answers **403**; the request is still captured through the `objectRef.namespace == tenant-b` match with the `list` verb on `pods`. A credential-less enumeration of a protected collection is a recognised privilege-abuse reconnaissance pattern, and it is the deliberate credential-presence counterfactual of `TMPL-BEN-06`. |
| `TMPL-PRV-05` | `T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);wget -qO- --no-check-certificate -H "Authorization: Bearer $T" https://10.96.0.1/apis` | **148** | 81–150 | The request is authenticated with the pod's own ServiceAccount, so the audit record is attributed to `system:serviceaccount:tenant-b:default`. The Kubernetes discovery document is world-readable, so the response is **200 rather than 403**; the class signal is the *equivalent audit record* branch — a workload enumerating the complete API group surface with its own identity, which is the reconnaissance step of a privilege-escalation chain. It is the only ServiceAccount-authenticated request that fits the `81–150` band at all (120 characters of overhead leave at most 24 for the URL, and only `/api` and `/apis` exist). |

**Effect on the length-bin table:** `privilege_abuse` moves from `0 / 0 / 8` to `0 / 2 / 6`. The corpus totals are `12 / 18 / 25` after also correcting `TMPL-UNK-03`, whose Stage 4a Part 1 burst command grew from 161 to 185 characters when the compression loop was lengthened and therefore crossed into the `151–250+` bin. The `30–80` band remains unrepresented for this class, which is physically unreachable for a class whose requests must produce a captured audit event.

**Residual confound disclosed:** `TMPL-PRV-02` and `TMPL-BEN-06` issue the *same* own-namespace collection read, differing only in whether a ServiceAccount token is presented, and the audit record therefore distinguishes them by `user.username` (`system:anonymous` vs `system:serviceaccount:tenant-b:default`). This is an intended paired contrast, but it is a deterministic class signal for that pair and must be reported as such rather than presented as a generalisation result.

### 7.2 The three escape replacements and the corrected expectations
`TMPL-ESC-05`, `TMPL-ESC-08` and `TMPL-ESC-10` are replaced (same template IDs, same run counts, escape budget unchanged at 10 templates / 80 runs) and the runner's `ROUND2_TEMPLATES` set now carries their exact commands, pod specifications and expected Falco rules. `TMPL-ESC-06`'s expectation was corrected to `Shell Spawn` only, because a `privileged: true` pod without a `hostPath` volume can never produce a `Launch Sensitive Mount Container` event. `TMPL-ESC-10` gains a `hostPath` File mount of the third already-allowlisted dummy path `/opt/runtimelens-dummy/containerd.sock`, which restores a genuine `Sensitive Mount` expectation and creates the class's only `T/F/T` feature combination.

Four inert, 0-byte dummy identity files (`shadow`, `passwd`, `group`, `hosts`) are now specified in `docs/SCENARIO_SAFETY_SHEET.md` and as prerequisite **P1b** in `docs/STAGE4_RUNBOOK.md`, so that `TMPL-ESC-09`'s multi-file read executes for real.

### 7.3 Round 2 scope
Round 2 runs **thirteen** templates, one run each — exactly the templates that were changed since the Part 1 smoke (`ESC-05`, `ESC-08`, `ESC-09`, `ESC-10`, `PRV-02`, `PRV-04`, `PRV-05`, `BEN-06`) or that have never been run (`BEN-14`, `BEN-16`, `BEN-17`, `PRV-07`, `UNK-R2`) — and then **stops for human review**. No template that was already executed unchanged is repeated, so no telemetry is collected twice. The five `burst` templates in Round 2 are the first measurement of their CPU profiles and are subject to the Decision D-26 band (peak 20–150 mcores, median < 100 mcores) and the Decision D-27 post-lag ratio with a strict post-lag median floor.

---

## 8. Decision D-29 — The Network-Observation Requirement (Gate Unchanged)

### 8.1 The discrepancy
- **Discrepancy:** the per-run gate requires all five telemetry sources to carry at least one event, but a scenario that opens no socket and resolves no name produces **zero** Hubble flows. The Stage 4a Round 2 attempt 1 stopped on its very first run: `TMPL-ESC-05` reported `hubble = 0` (a 0-byte `hubble/flows.jsonl`) and the gate rejected the run with `Missing telemetry from source 'hubble': count=0`.
- **What was *not* wrong:** the Falco rule fired with exactly the expected rule (`Interactive Shell Spawned in Non-Debug Container`), five authentic `pods/exec` audit events were captured, cAdvisor returned two samples, Trivy attached the static report, the safety linter passed the manifest, the cleanup left zero leftovers, and the run was backed up. The captured stdout proves the replacement scenario genuinely executed and is genuinely cgroup **v2**: `0::/kubelet.slice/kubelet-kubepods.slice/…cri-containerd-….scope` followed by a real overlay `mountinfo` line.

### 8.2 The resolution (option 1: gate unchanged)
Decision D-29 leaves the gate **exactly as it is** and makes the scenario speak instead. Every purely local scenario now carries exactly **one declared benign network observation** appended to its command, drawn from a shared four-type vocabulary:

| Type | Observation | Length | Hubble flows observed in Part 1 | Credential |
|:--:|:---|--:|--:|:---|
| **A** | `nslookup kubernetes.default.svc.cluster.local 2>&1 \|\| true` | 58 | 3 | none |
| **B** | `nc -z -w 1 10.96.0.10 53 \|\| true` | 32 | 7–8 | none |
| **C** | `wget -qO- --no-check-certificate https://10.96.0.1/api 2>&1 \|\| true` | 67 | 10 | none (world-readable) |
| **D** | `echo p \| nc -u -w 1 198.51.100.22 8080 \|\| true` | 57 | 1–2 | none |

Type C is **audit-neutral**: an unauthenticated request to the non-resource path `/api` is neither namespace-matching nor ServiceAccount-attributed, so it adds no audit event and does not change any template's expected audit verb set.

### 8.3 The anti-confounder property
The observation type is varied so that it cannot act as a class marker. The per-class mix over the full 55-template registry is:

| Class | A | B | C | D | Templates |
|:---|--:|--:|--:|--:|--:|
| `benign` | 4 | 9 | 6 | 2 | 21 |
| `container_escape` | 3 | 4 | 2 | 1 | 10 |
| `privilege_abuse` | 2 | 1 | 7 | 0 | 8 |
| `unknown` | 3 | 4 | 1 | 1 | 8 |
| `cryptomining` | 0 | 0 | 0 | 8 | 8 |

Every one of the four named classes carries at least one template of types A, B and C. `cryptomining` is uniformly type D, but type D is also used by `TMPL-BEN-04`, `TMPL-ESC-04` and `TMPL-UNK-03`, so the type itself is not exclusive to mining; the mining class is separated by its CPU time series, not by its observation.

### 8.4 Why the privilege class was not widened inside Round 2
All eight `privilege_abuse` templates already produce Hubble flows through their own API request (type C), so none of them is in the "predicted zero flows" set. Adding a *second* observation to the four Round 2 privilege templates was considered and **rejected**: their API request already yields 10–17 flows, so a second observation would push their totals into the `HIGH` Hubble band (>= 12 flows) and concentrate the class's flow-count distribution — a **new** confound of exactly the kind D-28 exists to remove. Two templates that are not in Round 2 (`TMPL-PRV-06`, `TMPL-PRV-08`) do receive an observation so that the class carries the full A / B / C mix.

### 8.5 Length-bin consequence
Two Round 2 templates change bin because their command grew: `TMPL-ESC-08` moves from `30–80` to `81–150` (57 -> 91 characters) and `TMPL-UNK-R2` moves from `81–150` to `151–250+` (95 -> 155 characters). `TMPL-PRV-06` (180 -> 214) and `TMPL-PRV-08` (216 -> 276) stay in `151–250+`. The rebalanced registry becomes `11 / 18 / 26` templates across the three bins. Per Decision D-28, `command_length` remains a **diagnostic only** and is never a classifier feature, so the bin reshuffle cannot become a model shortcut.

### 8.6 A second, independent defect found by the same round: BusyBox `wget` has no `-H` option
- **Finding (Round 2 attempt 2, run 6 — `TMPL-PRV-04`):** the run produced `hubble = 0` flows, **no** audit event for the API request, and `wget` exit code 1. A direct diagnostic in the cluster gave the exact cause:
  ```text
  $ kubectl exec -n tenant-a deploy/payment-style -- /bin/sh -c "T=$(cat .../token); wget -qO- --no-check-certificate -H \"Authorization: Bearer $T\" https://10.96.0.1/api/v1/namespaces/tenant-b/configmaps"
  wget: unrecognized option: H
  BusyBox v1.36.1 (2025-08-05 16:46:20 UTC) multi-call binary.
  Usage: wget [-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header STR] ...
  ```
  BusyBox `wget` accepts **only** `--header`; the short `-H` option that the Stage 4a Part 2 re-scoping introduced makes the command abort **before any network request is made**. The same defect was latent in `TMPL-PRV-05`, `TMPL-BEN-06` and `TMPL-PRV-07`.
- **Fix:** all four templates were restored to the verified `--header="Authorization: Bearer $T"` form, which is 5 characters longer than the invalid `-H` form. The corrected lengths are `TMPL-PRV-04` (187), `TMPL-PRV-05` (153), `TMPL-BEN-06` (181) and `TMPL-PRV-07` (229).
- **Consequence for the plan — a factual correction, not a design change.** The Stage 4a Part 2 claim that "`TMPL-PRV-05` fits the `81–150` bin at 148 characters" was **wrong**: it was derived from the invalid `-H` form. With the working `--header=` form the overhead is 126 characters (57 for the token read + 69 for the authenticated `wget` invocation), the `81–150` bin allows at most 144 characters of command, and the shortest URL the API server actually answers is `https://10.96.0.1/api` (21 characters). **No ServiceAccount-authenticated request fits inside the `81–150` band.** `TMPL-PRV-05` therefore moves to `151–250+` (153 characters) and the `privilege_abuse` class becomes `0 / 1 / 7`, with the corpus totals `11 / 17 / 27`.
- **Regression control:** `tests/unit/test_stage4a_runner_templates.py::test_no_busybox_incompatible_wget_options` and `::test_service_account_templates_use_the_verified_header_form` pin the option form for every template, so the defect cannot be reintroduced.
- **Note on the earlier `PRV-05` re-scoping rationale:** the claim that the Kubernetes discovery document is "world-readable" is only true for *unauthenticated* requests to `/api`; the 403 observed in the sandbox came from an anonymous request, while an authenticated request to `/api` returns 200 and an authenticated request to `/` returns 403. The template's audit record is attributed to the ServiceAccount either way, so the class signal is unchanged.

### 8.7 The failed attempts
Two attempts produced failed runs, and both are retained verbatim as **"failed gate, kept for audit"** and are never reused as dataset runs:

| Attempt | Run | Stop reason | Quarantine |
|:--:|:---|:---|:---|
| 1 | `run-s4a-r2-01` | `Missing telemetry from source 'hubble': count=0` — the scenario was purely local (Decision D-29) | `data/raw/failed_runs/run-s4a-r2-01` |
| 2 | `run-s4a-r2-06` | `Missing telemetry from source 'hubble': count=0` — the BusyBox `-H` option aborted before the request | `data/raw/failed_runs/run-s4a-r2-06` |

The working copies were moved out of `data/raw/runs/` into `data/raw/failed_runs/` so that `scripts/verify_dataset.py --runs-dir data/raw/runs` cannot pick them up and so that a re-run cannot overwrite them. The raw telemetry of every failed attempt is preserved and nothing is deleted.

---

## 9. Stage 4a Round 2 — Three Further Findings From Real Telemetry

Round 2 attempt 3 executed 9 of the 13 templates before the per-run gate stopped it. Three findings are recorded here. **None of the three is a gate defect; no gate or threshold was changed.**

### 9.1 The `Launch Sensitive Mount Container` rule **shadows** the identity-file rule on the dummy paths (Falco first-match-wins precedence)
- **Observed (Round 2 attempt 3, `TMPL-ESC-09`):** the plan expects `Shell Spawn`, `Launch Sensitive Mount Container` **and** `Read Sensitive Host Information Untrusted`. The run produced `Shell Spawn` + `Launch Sensitive Mount Container` **twice** and **no** identity-file event.
- **Evidence from the raw Falco events:** the same `open_read` event on `fd.name = /opt/runtimelens-dummy/etc/shadow` (opened by `head -n 2`) and on `fd.name = /opt/runtimelens-dummy/etc/passwd` (opened by `dd if=`) produced two `Launch Sensitive Mount Container` events. The deployed identity rule (read from the live `falco-rules` ConfigMap) does contain the dummy paths in its condition:
  ```text
  condition: container and (open_read) and (fd.name in (/etc/shadow, /opt/runtimelens-dummy/etc/shadow)
             or (fd.name in (/etc/passwd, /opt/runtimelens-dummy/etc/passwd) and not proc.name in (...)))
  ```
  so the condition was satisfied and the rule still did not fire.
- **Root cause:** Falco evaluates the rules **in file order and stops at the first matching rule for an event**. The D-29-era mount-rule change extended `Launch Sensitive Mount Container` to the whole `/opt/runtimelens-dummy` prefix, so it now matches *before* the identity rule can. The same mechanism is visible in the Part 1 evidence: the identity rule fired for `/etc/passwd` in `TMPL-BEN-11` only because the mount rule did **not** match that path at the time.
- **Proposed fix (not applied):** make the more specific rule win — move `Read Sensitive Host Information Untrusted` **above** `Launch Sensitive Mount Container` in `lab/falco/rules/lab-rules.yaml` and `lab/falco/falco-values.yaml`, or equivalently add `and not fd.name in (/opt/runtimelens-dummy/etc/shadow, /opt/runtimelens-dummy/etc/passwd)` to the mount rule. The first option is preferred: it expresses the general precedence principle ("the more specific rule matches first") and needs no exception list that has to track the dummy files. A Helm upgrade would be required to deploy it, so it needs explicit review.

### 9.2 `TMPL-ESC-10`'s expected `Launch Sensitive Mount Container` cannot fire — `ls -l` only `stat()`s the file
- **Observed (Round 2 attempt 3, `TMPL-ESC-10`):** the plan expects `Shell Spawn` + `Launch Sensitive Mount Container`; the run produced **only** `Shell Spawn`.
- **Root cause:** the mount rule requires an `open_read` or `open_write` event. `ls -l <file>` performs a `stat()` (and `lstat()`), which is **not** an open, so no open event is generated. `TMPL-ESC-03` fires the rule because its command contains `head -n 1`, which *does* open the file for reading; `TMPL-ESC-09` fires it because `head` and `dd` open the files.
- **Proposed fix (not applied):** either correct the expectation of `TMPL-ESC-10` to `Shell Spawn` only, or make the command perform a real read (for example `head -c 1 /opt/runtimelens-dummy/containerd.sock 2>&1 || true`), which restores the intended signal that a mounted runtime socket is *accessed* and not merely listed. The second option is preferable, because the escape scenario is about the socket being *reachable from inside the container*.

### 9.3 The kubelet's cAdvisor collection cadence is ~18–20 s, so a CPU burst shorter than that is **invisible** to the summary API
- **Observed (Round 2 attempt 3, `TMPL-BEN-14`):** the run failed the D-26 burst band with `peak=0.00m`. The command's arithmetic loop demonstrably executed — the captured `ps aux` output shows it running — and an independent diagnostic measured **6 seconds** of wall time for the 800 000 busybox iterations. Yet the cAdvisor **cumulative** counter `usageCoreNanoSeconds` was **frozen at 4.140 s across all three samples** of the 15.15 s run, and the reported rate was `0.00m` throughout.
- **Direct measurement of the cadence** (a controlled 6 s burn in the same pod, polling the summary API every 2 s):
  ```text
  t=  0.0s  rate=0.00m cum=34.400s
  t=  4.1s  rate=0.00m cum=34.400s
  t=  8.3s  rate=0.00m cum=34.400s
  t= 12.4s  rate=78.56m cum=35.749s  delta=1.3495   <-- first collection that closed inside the burn
  t= 20.6s  rate=78.56m cum=35.749s
  t= 30.9s  rate=0.00m cum=35.749s                   <-- next collection closed after the burn
  ```
  The summary API therefore returns the **last completed collection**: a burst can be missing from both the rate and the cumulative counter for up to a full collection interval, and the reported rate is the **average over the collection window that just closed**, not the instantaneous rate.
- **Consequences:** (a) a `burst` scenario must hold its load for **longer than one collection interval** (empirically > 20 s, with margin ≥ 30 s) for the burst to be observable at all; (b) the D-26 band `[20, 150]` is partly a measurement of the **collection phase** rather than of the workload — which is the real, deeper explanation of the `25.77 m` versus `117.34 m` spread of the *identical* `TMPL-UNK-03` command across Part 1 attempts; (c) the `median < 100 m` requirement means the burst must occupy **less than half** of the run's samples, so the total run window must be long enough for the burst to be a minority of the samples.
- **Proposed fixes (not applied, because they change the plan's Duration and CPU Profile columns of templates that have not yet been run):**
  * `TMPL-BEN-14` — lengthen the burn to ≈ 30 s and the total run window to ≈ 90 s, e.g. `for i in $(seq 2000); do j=0; while [ $j -lt 2000 ]; do j=$((j+1)); done; done` (≈ 16 M iterations ≈ 30 s of CPU) with `sleep_after` raised so the burst is a minority of the samples. The container limit is 200 m, so the reported rate over the collection window that closes inside the burn would be ≈ 120–130 m, inside the D-26 band, with a median of 0.
  * `TMPL-BEN-16` — the gzip of two 12 MiB files lasts ≈ 2–3 s, far below the collection interval; it needs a larger workload (for example 4 × 48 MiB) or its CPU profile must be re-declared as `low`.
  * `TMPL-BEN-17` — the current loop is ≈ 50 s of CPU, which is long enough to be captured, but at the 200 m limit it would report a peak **above** the D-26 ceiling of 150 m; it must be throttled (for example a duty cycle of ≈ 60 %) so the reported rate lands inside the band.
  * `TMPL-PRV-07` — the scenario is an I/O-bound `wget` loop and produces **no** meaningful CPU load at all; its `burst` CPU profile is simply wrong and should be re-declared `low`.
  * `TMPL-UNK-R2` — the current loop is ≈ 14 s of CPU, right at the collection interval; it should be extended to ≈ 30 s in a ≈ 90 s window.
- **No gate was changed.** The D-26 band and the D-27 post-lag rule remain exactly as approved; what has to change is the *scenario duration* so that the scenario is long enough for the instrument to see it.

---

## 10. Decision D-30 / D-31 — The Approved Edit Round

### 10.1 D-31 — the identity-file rule is now evaluated before the mount rule
The two lab rule files were reordered so that `Read Sensitive Host Information Untrusted` precedes `Launch Sensitive Mount Container`. Falco stops at the first matching rule for an event, so the mount rule — which the D-29-era change had extended to the whole `/opt/runtimelens-dummy` prefix — had been shadowing the identity rule on the inert dummy paths. The deployed rule order is now:

```text
1. Read Sensitive Host Information Untrusted
2. Launch Sensitive Mount Container
3. Interactive Shell Spawned in Non-Debug Container
4. Suspicious High Port Egress
```

### 10.2 `TMPL-ESC-10` — the pod is now privileged and the socket is really read
The Round 2 attempt 3 review found that the plan's `T/F/T` triple for `TMPL-ESC-10` was **not** what the run produced: the runner's pod specification had no `privileged: true`, so the measured triple was `T/F/F`. The earlier report's "MATCH" line was wrong — it compared the *expectation* with itself rather than with the measurement. The pod is now privileged, and the command performs a **real read** of the mounted dummy socket (`head -c 1` instead of `ls -l`, which only `stat()`s the file and therefore produces no open event for the mount rule to match).

```yaml
# TMPL-ESC-10 pod specification
spec:
  containers:
    - name: worker
      image: docker.io/library/alpine:3.19
      command: ["sleep", "600"]
      resources: {limits: {cpu: 500m, memory: 256Mi}}
      securityContext: {privileged: true}
      volumeMounts:
        - {name: sensitive-mount, mountPath: /opt/runtimelens-dummy/containerd.sock}
  volumes:
    - name: sensitive-mount
      hostPath: {path: /opt/runtimelens-dummy/containerd.sock, type: File}
```

The safety linter accepts it: `privileged: true` is permitted **only** in `sandbox-workloads`, and the host path is one of the three allowlisted dummy paths. The resulting feature triple is `T / F / T` (feature 00 from the `containerd.sock` host path, feature 01 absent, feature 02 from `privileged: true`), which is what the plan states.

### 10.3 D-30 — the burst scenarios are calibrated against the measured collection cadence
The `TMPL-BEN-14` failure was a **measurement** failure, not a gate failure: the kubelet's cAdvisor summary API returns the last completed collection and the collection cadence in this cluster is ~18–20 s, so a 6-second CPU burst never appears in either the reported rate or the cumulative counter. The five `burst`-profile templates were therefore re-calibrated so that their load outlasts the instrument, and `TMPL-PRV-07` — an I/O-bound sequence of HTTPS requests that never burns CPU — was re-declared `low`. **No gate threshold was changed**: the Decision D-26 band (`peak` in `[20, 150]` mcores, `median < 100` mcores) and the Decision D-27 post-lag rule are untouched.

| Template | Change | Expected measured rate |
|:---|:---|:---|
| `TMPL-BEN-14` | 480 iterations of the measured `TMPL-MNR-03` loop shape (~30 s burn) in a ~90 s window | ~90–100 m |
| `TMPL-BEN-16` | a single 12 MiB gzip (~3 s, invisible) replaced by 8 throttled 8 MiB gzip cycles (~36 s, 8 MiB peak disk) | ~65–70 m |
| `TMPL-BEN-17` | the **20-hour** nested loop (1500 × 4000 iterations per outer iteration) replaced by a single-level 400-iteration loop (~25 s, ~60 % duty of the 200 m limit) | ~90 m |
| `TMPL-PRV-07` | CPU profile re-declared `low` — the scenario waits for HTTP responses | ~0 m |
| `TMPL-UNK-R2` | ~14 s of CPU replaced by a ~30 s burn in a ~90 s window | ~90–100 m |

The full derivation, including the direct measurement of the collection cadence, is in `docs/SCENARIO_PLAN_v2.md` §3.6.4.

### 10.4 Round 3 scope
Round 3 re-runs **seven** templates — the four whose command or pod specification changed (`ESC-09` is re-run because the Falco rule order changed, `ESC-10` because its pod and command changed, `BEN-14`/`BEN-16`/`BEN-17`/`UNK-R2` because of the D-30 calibration) plus the templates that Round 2 never reached. The six unchanged Round 2 runs are kept exactly as they are.

---

## 11. Round 3 Results — Two Residual Deviations and One Side Discovery

Round 3 executed the seven changed or never-run templates with no gate failure. Two deviations from the plan remain, and one unrelated degradation was discovered.

### 11.1 `TMPL-ESC-09` — the identity rule now fires, but the mount rule can no longer fire in that scenario
- **Measured:** `TMPL-ESC-09` produced `Interactive Shell Spawned in Non-Debug Container` + `Read Sensitive Host Information Untrusted` **twice** (`fd.name = /opt/runtimelens-dummy/etc/shadow` and `.../passwd`). The plan expected the mount rule as well; it did not fire.
- **Why:** Falco produces **one rule per event** (first match wins). After the Decision D-31 reorder, the identity rule owns the two dummy identity files, and `TMPL-ESC-09` reads **only** identity files (`head` on `shadow`, `dd if=` on `passwd`); the `find` directory walk produces no `open_read` event. The mount rule therefore has no event to match.
- **Proof of the mechanism (read-only diagnostic, outside the dataset):** reading a **non-identity** dummy file in the same mounted directory produced the mount rule:
  ```text
  rule: Launch Sensitive Mount Container   fd.name: /opt/runtimelens-dummy/etc/hosts   cmd: head -c 1 /opt/runtimelens-dummy/etc/hosts
  rule: Launch Sensitive Mount Container   fd.name: /opt/runtimelens-dummy/etc/group   cmd: head -n 1 /opt/runtimelens-dummy/etc/group
  ```
  (`group` is not in the identity rule's file list, so it goes to the mount rule; `hosts` likewise. The diagnostic pod was deleted immediately afterwards.)
- **Proposed fix (not applied — it needs another template edit and a further round):** add one read of a **non-identity** dummy file to `TMPL-ESC-09` and `TMPL-ESC-04`, e.g. `head -n 1 /opt/runtimelens-dummy/etc/hosts 2>&1 || true`. The diagnostic above proves that this single addition makes the mount rule fire while the identity rule continues to fire for the identity files, which is exactly the three-rule expectation the plan states. `TMPL-ESC-04` additionally needs to be **re-run**, because its Part 1 telemetry recorded the mount rule for the dummy `shadow` read, and under the current rule order that same read now produces the identity rule — i.e. the Part 1 data for `TMPL-ESC-04` is stale with respect to the deployed rule set.

### 11.2 `TMPL-PRV-07` — 46 Hubble flows, not the planned MID band
- **Measured:** 46 flows (plan: `MID`, i.e. 7–11) and 15 audit events, 10 of them the five `nodes/…/proxy/metrics` requests of the scenario (each recorded twice, `ResponseStarted` and `ResponseComplete`) with `verb=get`, `user=system:serviceaccount:tenant-a:default`, `status=403`.
- **Why:** the five sequential node-proxy requests each generate a full TCP retry sequence against the API server ClusterIP, so the flow count is an order of magnitude higher than a single request's 10 flows. The band prediction was made from a single-request analogue.
- **Proposed fix (not applied):** correct the plan's Hubble band for `TMPL-PRV-07` from `MID` to `HIGH` (>= 12 flows). The 403 audit record and the rule set are exactly as planned; only the flow-count band was mispredicted.

### 11.3 Side discovery — the live Falco/Audit webhook receivers are refusing every request
- **Observed:** `/tmp/falco_webhook.log` and `/tmp/audit_webhook.log` are being written continuously and contain only:
  ```text
  RuntimeError: Security violation: FALCO_WEBHOOK_SECRET is not configured. Webhook receiver refuses to operate without authentication.
  RuntimeError: Security violation: K8S_AUDIT_WEBHOOK_SECRET is not configured. Audit webhook receiver refuses to operate without authentication.
  ```
- **Impact on the dataset: none.** The per-run capture reads the **Falco pod's own log** (`kubectl logs -n falco`), not the webhook, so every run in this round captured its Falco events normally.
- **Impact on the project: real.** The live "Falco → webhook → HMAC audit record" path, which is a core deliverable of the vertical slice, is currently refusing every event because the two receiver processes were started without their secret environment variables. The receivers are refusing *rather than accepting unauthenticated* traffic, which is the correct fail-safe behaviour, but the pipeline is non-functional and must be restarted with the secrets configured. This is a separate defect from the dataset work and is reported here for a dedicated fix.

### 11.4 Round 4 — the two deviations are closed

After the approved edit round, `TMPL-ESC-04` and `TMPL-ESC-09` were re-run with one read of a **non-identity** dummy file added (`head -n 1 /opt/runtimelens-dummy/etc/hosts`), and `TMPL-PRV-07`'s Hubble band was corrected from `MID` to `HIGH`.

```text
run-s4a-05    TMPL-ESC-04  falco=3  hubble=1  prom=2  cpu[0.0/0.59/0.59]  dur=10.16s  gate=PASSED
  - Interactive Shell Spawned in Non-Debug Container
  - Read Sensitive Host Information Untrusted   fd.name=/opt/runtimelens-dummy/etc/shadow
  - Launch Sensitive Mount Container           fd.name=/opt/runtimelens-dummy/etc/hosts

run-s4a-r2-03 TMPL-ESC-09  falco=4  hubble=9  prom=2  cpu[0.0/0.0/0.0]    dur=7.13s   gate=PASSED
  - Interactive Shell Spawned in Non-Debug Container
  - Read Sensitive Host Information Untrusted   fd.name=/opt/runtimelens-dummy/etc/shadow
  - Read Sensitive Host Information Untrusted   fd.name=/opt/runtimelens-dummy/etc/passwd
  - Launch Sensitive Mount Container           fd.name=/opt/runtimelens-dummy/etc/hosts
```

Both templates now produce **all three** expected rules, and the plan's `Expected Falco Rules` column is realised exactly. The `TMPL-ESC-04` bin moves from `81–150` to `151–250+` (104 -> 161 characters) because of the added read; `TMPL-ESC-09` moves from 252 to 309 characters, still `151–250+`. The escape class length-bin distribution becomes `2 / 5 / 3` and the corpus totals `11 / 16 / 28`.

### 11.5 Round 3 summary against the plan
| Template | Falco rules | Audit verbs | Hubble band | CPU peak/median | Features 00/01/02 | Verdict |
|:---|:---|:---|:---|:---|:---|:---|
| `TMPL-ESC-09` | identity rule now fires; mount rule missing | get, create | 9 MID ✓ | 2.26 / 1.13 ✓ | F/T/F ✓ | **deviation** (§11.1) — **closed in Round 4** |
| `TMPL-ESC-10` | Shell Spawn + Sensitive Mount ✓ | get, create | 7 MID ✓ | 0.00 / 0.00 ✓ | **T/F/T** ✓ | as planned |
| `TMPL-BEN-14` | Shell Spawn ✓ | get, create | 8 MID ✓ | 104.63 / 0.00 ✓ | F/F/F ✓ | as planned |
| `TMPL-BEN-16` | Shell Spawn ✓ | get, create | 10 MID ✓ | 62.31 / 2.11 ✓ | F/F/F ✓ | as planned |
| `TMPL-BEN-17` | Shell Spawn ✓ | get, create | 4 LOW ✓ | 104.22 / 0.00 ✓ | F/F/F ✓ | as planned |
| `TMPL-PRV-07` | Shell Spawn ✓ | get ✓ | **46 HIGH** | 0.00 / 0.00 ✓ | F/F/F ✓ | **deviation** (§11.2) — **band corrected to HIGH in the plan** |
| `TMPL-UNK-R2` | Shell Spawn ✓ | get, create | 4 LOW ✓ | 117.69 / 15.31 ✓ | F/F/F ✓ | as planned |

---

## 12. Decision D-32 — The Diagnostics Now Use a Template-Grouped Cross-Validation

### 12.1 The defect
`scripts/verify_dataset.py` computed both diagnostics by **fitting the classifier on the rows it then scored** (train-on-train). That is an optimistically biased estimate, and it is the mechanism that produced the project's most misleading number: `command_length` reached Macro-F1 = 1.0000 on the ten-run Part 1 smoke, and the permuted-label "chance" baseline scored 0.9314 on the same ten runs — a 0.07 gap that was never a signal at all.

### 12.2 The change
Both diagnostics now use a `GroupKFold` cross-validation whose **groups are the scenario templates** (read from each run's `index.json` `scenario_id`, used *only* to build the folds and never as a feature). Every fold trains on the templates of the other folds and predicts the held-out templates, so no template ever appears in both the training and the evaluation data of the same fold — the same discipline the dataset split uses. The out-of-fold predictions are pooled and the macro F1 is computed over them.

Both sections are now explicitly labelled:

```text
[4/5] Single-Feature Diagnostic Scores (grouped cross-validation by template)
  DIAGNOSTIC ONLY - 13 run(s) in 13 template group(s) across 5 grouped folds; the estimate is NOT a
  valid generalisation figure until the corpus reaches 100 runs and 10 groups.
```

### 12.3 The effect on the numbers (same 13 runs, same features)
| Quantity | Train-on-train (old) | Template-grouped out-of-fold (new) |
|:---|--:|--:|
| `command_length` diagnostic (D-28, excluded from the feature set) | 0.9365 | **0.2937** |
| `cpu_usage_mcores` (feature 07) | 0.9365 | **0.4792** |
| `is_root_user` (feature 03) | 0.4038 | 0.4214 |
| `deviation_count` (feature 13) | 0.3000 | 0.3201 |
| `privileged_container` (feature 02) | 0.3571 | 0.3766 |
| Permuted-label chance baseline | 0.9365 | **0.1042** |

The permuted-label baseline falling from 0.9365 to 0.1042 is the clearest evidence that the old figures were memorisation: a classifier trained on permuted labels and scored on the same rows reproduces the training labels, which is why the "chance" baseline was almost as high as the real one.

### 12.4 The caveat that is now recorded in the code
With very few template groups a fold can train on a single class, which makes the estimate degenerate. The diagnostic sections therefore state their status explicitly and remain labelled **DIAGNOSTIC ONLY** until the corpus reaches **100 runs and 10 template groups**. No number from sections 4/5 may be quoted as a generalisation figure before that.

---

## 13. Stage 4a Round 4 — The Command-Writing Round (offline; nothing executed)

### 13.1 What this round did and what it did not do

This round wrote the **exact commands** of the 32 templates that had never been executed and corrected the master registry against them. **Nothing was run on the cluster.** No pod was created, no telemetry was captured, no gate was evaluated. The deliverables are the command definitions, the corrected registry rows, the two class-level tables and a machine-checked plan-vs-runner consistency check.

The definitions live in `scripts/stage4a_round4.py`; the runner exposes them as `ROUND5_TEMPLATES` with the four batch selectors `5a`–`5d`:

```bash
cd /home/ubuntu/RuntimeLens
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 5a   # 10 templates
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 5b   # 10 templates
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 5c   # 10 templates
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 5d   # 2 templates
```

### 13.2 The rules every command obeys

| Rule | Source | How it is enforced |
|:---|:---|:---|
| Exactly one declared D-29 observation (A/B/C/D) for every scenario with no network activity of its own | D-29 | `scripts/stage4a_round4.py::_append_observations()`; unit test `test_every_local_only_template_carries_exactly_one_observation` |
| The BusyBox `wget` option form is `--header=`, never `-H` | D-29 correction (Round 2 attempt 2) | unit test `test_no_command_uses_the_unsupported_busybox_wget_option` |
| The mining templates use the measured `TMPL-MNR-03` 3000-iteration inner loop; the `high` ones saturate the 200 mcores cgroup cap for ~125 s, the `throttled` ones hold a measured duty cycle | D-22 / D-27 | unit test `test_mining_templates_use_the_verified_inner_loop_shape` |
| A `burst` template holds its load for >= 30 s inside a 90 s window | D-30 | the D-30 burst templates are unchanged in this round |
| No class name, scenario id, template id or run id appears in any command | Rule 10(c) of `AGENTS.md` | unit tests `test_no_command_leaks_a_class_name_or_an_identifier` and `test_no_command_contains_a_scenario_or_template_identifier` |
| Every sandbox manifest passes the safety linter | D-06 / §3.3 of `docs/REPORT_DELTA.md` | unit test `test_sandbox_manifests_pass_the_safety_linter` |

### 13.3 The 32 commands, with their measured properties

`cmd chars` is the measured `proc.cmdline` length (`len(command) + 6` for the `sh -c ` prefix). **Bin** is the registry band that follows from it.

| Template | Class | Batch | cmd chars | Bin | CPU profile | Hubble band | Expected Falco rules | Features | Verbs | Observation |
|:---|:---|:--:|--:|:---|:---|:---|:---|:---|:---|:---|
| `TMPL-MNR-01` | cryptomining | A | 192 | 151-250+ | high | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D + A |
| `TMPL-MNR-02` | cryptomining | A | 192 | 151-250+ | high | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D + A |
| `TMPL-MNR-04` | cryptomining | A | 144 | 81-150 | throttled | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-MNR-05` | cryptomining | A | 192 | 151-250+ | high | LOW | Shell Spawn | F/F/F | create, get | own D + A |
| `TMPL-MNR-06` | cryptomining | A | 143 | 81-150 | throttled | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-MNR-07` | cryptomining | A | 239 | 151-250+ | throttled | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own A |
| `TMPL-MNR-08` | cryptomining | A | 144 | 81-150 | throttled | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-PRV-06` | privilege_abuse | A | 260 | 151-250+ | low | MID | Shell Spawn | F/F/F | create, get | obs A |
| `TMPL-PRV-08` | privilege_abuse | A | 270 | 151-250+ | low | HIGH | Shell Spawn | F/F/F | create, get, list | obs D |
| `TMPL-ESC-01` | container_escape | A | 93 | 81-150 | low | LOW | Shell Spawn, Sensitive File Read | F/F/F | create, get | obs A |
| `TMPL-UNK-04` | unknown | B | 81 | 81-150 | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-UNK-05` | unknown | B | 99 | 81-150 | low | HIGH | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-UNK-07` | unknown | B | 75 | 30-80 | low | MID | Shell Spawn | F/F/F | create, get | own B |
| `TMPL-UNK-R1` | unknown | B | 181 | 151-250+ | low | MID | Shell Spawn | F/F/F | create, get, list | own C |
| `TMPL-UNK-R3` | unknown | B | 52 | 30-80 | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-UNK-R4` | unknown | B | 74 | 30-80 | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-ESC-02` | container_escape | B | 133 | 81-150 | low | MID | Shell Spawn | F/F/F | create, get | obs C |
| `TMPL-ESC-07` | container_escape | B | 74 | 30-80 | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-BEN-02` | benign | B | 68 | 30-80 | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-BEN-03` | benign | B | 57 | 30-80 | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-BEN-05` | benign | C | 52 | 30-80 | low | LOW | Shell Spawn | F/F/F | create, get | own D |
| `TMPL-BEN-07` | benign | C | 84 | 81-150 | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-BEN-08` | benign | C | 84 | 81-150 | low | LOW | Shell Spawn | F/F/F | create, get | obs A |
| `TMPL-BEN-09` | benign | C | 52 | 30-80 | low | LOW | Shell Spawn | F/F/F | create, get | own D |
| `TMPL-BEN-10` | benign | C | 74 | 30-80 | low | LOW | Shell Spawn | F/F/F | create, get | obs D |
| `TMPL-BEN-12` | benign | C | 126 | 81-150 | low | LOW | Shell Spawn | F/F/F | create, get | own A |
| `TMPL-BEN-13` | benign | C | 157 | 151-250+ | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-BEN-15` | benign | C | 264 | 151-250+ | low | MID | Shell Spawn | F/F/F | create, get | obs B |
| `TMPL-BEN-18` | benign | C | 187 | 151-250+ | low | MID | Shell Spawn | F/F/F | create, get, list | own C |
| `TMPL-BEN-19` | benign | C | 129 | 81-150 | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-BEN-20` | benign | D | 52 | 30-80 | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |
| `TMPL-BEN-21` | benign | D | 194 | 151-250+ | low | LOW | Shell Spawn, High Port Egress | F/F/F | create, get | own D |

### 13.4 The two class-level tables

**Table 1 — observation type per class** (effective type: the declared D-29 observation, or the template's own network activity).

| Class | A (DNS) | B (TCP to cluster DNS) | C (API discovery) | D (UDP to inert IP) | Templates |
|:---|--:|--:|--:|--:|--:|
| `benign` | 3 | 5 | 4 | 9 | 21 |
| `container_escape` | 2 | 5 | 2 | 1 | 10 |
| `privilege_abuse` | 1 | 2 | 4 | 1 | 8 |
| `cryptomining` | 4 | 0 | 0 | 4 | 8 |
| `unknown` | 1 | 3 | 1 | 3 | 8 |

All four observation types appear in the `benign`, `container_escape` and `privilege_abuse` classes. The `cryptomining` class carries only A and D because a mining client resolves a pool name (A) and opens a pool connection (D) and does nothing else; the `unknown` class carries no C beyond the single `TMPL-UNK-R1` API read because no other unknown scenario performs an API-discovery read.

**Table 2 — expected Falco rule sets per class** (only rules that can really fire under the deployed rule set).

| Class | Expected rule set | Templates | Share | Flag |
|:---|:---|--:|--:|:---|
| `benign` | `Shell Spawn` | 15 | 71.4 % | **FLAGGED** |
| `benign` | `Shell Spawn` + `High Port Egress` | 6 | 28.6 % | |
| `container_escape` | `Shell Spawn` | 5 | 50.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive Mount` | 2 | 20.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive Mount` + `Sensitive File Read` | 2 | 20.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive File Read` | 1 | 10.0 % | |
| `privilege_abuse` | `Shell Spawn` | 8 | 100 % | **FLAGGED** |
| `cryptomining` | `Shell Spawn` + `High Port Egress` | 6 | 75.0 % | **FLAGGED** |
| `cryptomining` | `Shell Spawn` | 2 | 25.0 % | |
| `unknown` | `Shell Spawn` | 6 | 75.0 % | **FLAGGED** |
| `unknown` | `Shell Spawn` + `High Port Egress` | 2 | 25.0 % | |

### 13.5 The four flagged classes, and why the flags are not defects

| Flagged class | Share on one rule set | Why it is the intended property |
|:---|--:|:---|
| `benign` | 71.4 % | Most benign scenarios are local work (file touch, `date`, `df`) or a single low-rate probe. A single shared rule set across the class means the rule set carries **no** class information for the benign majority — exactly the anti-shortcut property D-28 was created for. |
| `privilege_abuse` | 100 % | A privilege attempt in this lab is a **ServiceAccount-authenticated API request**: it is low-CPU, opens no host path and reads no identity file, so no Falco rule describes it. The class is discriminated by the **audit record** (own vs adjacent namespace, credential present or absent) and the **Hubble flow count**, not by Falco. |
| `cryptomining` | 75 % | Six of the eight mining templates connect to an **in-list** high port and therefore trip `Suspicious High Port Egress`; the two `out-of-list` templates (`MNR-03` on 8080, `MNR-05` on 6379) deliberately do not, so that the class cannot be identified by the port. Mining is discriminated by the **CPU band** (the `high` / `throttled` profiles) plus the port. |
| `unknown` | 75 % | The unknown class is *ambiguous by design*; three of its six new templates are local or single-probe and therefore fire one rule. Its ambiguity is the scientific point, not an accident. |

`container_escape` is the one class that is **not** flagged (50 % on one rule set): it is the only class whose templates span three distinct rule sets, because the escape scenarios differ in whether they mount a host path, whether they read an identity file, or neither.

### 13.6 The length bins had to be re-derived — and the two anti-confounder controls collide

The `Length Bin` column of the registry was a **design intent** recorded before these 32 commands existed. With the commands written, the bins are re-derived from the measured `proc.cmdline` length, and the corpus totals move from `11 / 16 / 28` to:

| Class | `30–80` | `81–150` | `151–250+` | Templates | (was) |
|:---|--:|--:|--:|--:|:---|
| `benign` | 8 | 5 | 8 | 21 | `5 / 6 / 10` |
| `container_escape` | 1 | 6 | 3 | 10 | `2 / 5 / 3` |
| `privilege_abuse` | **0** | **1** | 7 | 8 | `0 / 1 / 7` |
| `cryptomining` | **0** | 4 | 4 | 8 | `2 / 3 / 3` |
| `unknown` | 3 | 2 | 3 | 8 | `2 / 1 / 5` |
| **Total** | **12** | **18** | **25** | **55** | `11 / 16 / 28` |

The "was" column is the registry state at commit `30449e2`, recomputed from the same registry rows so that the comparison is like-for-like.

**The tension is real and is disclosed rather than engineered away.** Decision D-29 requires a purely local scenario to carry a network observation of at least 32 characters (type B), which leaves only ~40 characters of a `30–80` band for the scenario itself. Consequently `privilege_abuse` and `cryptomining` **cannot** reach the `30–80` band at all:

* a ServiceAccount-authenticated request costs 126 characters before its URL (57 for the token read, 69 for the authenticated `wget`);
* a *bounded* busy loop costs at least 50 characters — an unbounded `while :; do :; done` would never terminate the scenario.

Two consequences follow, and both are stated rather than hidden:

1. The residual length↔class association is real but is **not** a live shortcut, because Decision D-28 already removes the raw command length from the classifier feature set (19 → 18 features). The association is reported in the diagnostic output, not exploited.
2. The `81–150` band is the largest (18 of 55) and the `30–80` band the smallest (12 of 55); the plan's original `11 / 16 / 28` is not recoverable, because the D-29 observation requirement did not exist when the bins were first assigned. **No template was padded to hit a bin**: every command is the shortest honest form of its scenario.

### 13.7 The plan-vs-runner consistency check

`scripts/check_plan_consistency.py` parses all 55 registry rows of `docs/SCENARIO_PLAN_v2.md` and compares each of them against the runner's template definition on **seven** fields — class, length bin, CPU profile, expected Falco rules, the feature triple, the audit verbs and the Hubble band:

```text
$ PYTHONPATH=src:. python3 scripts/check_plan_consistency.py
templates checked: 55
mismatches: 0  (class, length bin, cpu profile, falco rules, features, verbs, band)
```

**Zero mismatches across 55 templates and 385 field comparisons.**

### 13.8 What this round did **not** establish

* **No command was executed.** Every "expected" value in §13.3 is a *prediction* from the plan and from the measured facts of the earlier rounds. The Hubble bands in particular are predictions: a type-D UDP datagram produced 1–2 flows in the Part 1 corpus, a type-B TCP probe produced 7–8, a type-C API read produced 10 and a cross-tenant read 16–17, and the two templates that add a *second* network activity to a scenario that already has one (`TMPL-PRV-08`, `TMPL-UNK-05`) are predicted to land in the `HIGH` band. These predictions are **not** measurements and are labelled as such.
* **The mining intensities are predictions**, computed from the measured `TMPL-MNR-03` anchor (89.69 / 100.51 / 100.58 mcores for the 3000-iteration inner loop with a 50 ms pause) by scaling only the pause and the outer iteration count. **Decision D-34** recomputed them from the Round 5a attempt-1 measurement (5.87 / 6.00 ms of CPU per 3000-iteration inner loop) and **Decision D-35** re-derived them from the *measured* throttled run `TMPL-MNR-04` (80.17 m, 7.26 ms of CPU per iteration at a 75 ms pause): `MNR-04` ~80 m (measured), `MNR-06` ~69 m, `MNR-07` ~80 m, `MNR-08` ~96 m (derived). The `high` templates are expected to saturate the 200 mcores cgroup cap — the plan's earlier "cgroup-capped at 500m" note was **wrong** and is corrected to 200 m, the measured tenant limit.
* **The `30–80` band is under-populated relative to the plan's intent** (§13.6). This is a design tension, not a data defect, and it is disclosed in `docs/SCENARIO_PLAN_v2.md` §3.6.6 and in Decision D-33.
* **The four flagged classes have not been "fixed"**, because the degeneracy is the intended anti-shortcut property (§13.5). Fixing it would mean adding Falco rules that describe privilege attempts or mining CPU, which would make the rule set class-discriminative and destroy the comparison the whole project is built on.

---

## 14. Stage 4a Round 5a — Attempt 2 (after Decision D-34): 3 of 10, hard stop at run 3

### 14.1 What the attempt produced

| Run | Template | Duration (wall) | Falco | Audit | Hubble | Prom | Trivy | Per-run gate (runner output) |
|:---|:---|--:|--:|--:|--:|--:|--:|:---|
| `run-s4a-r4-01` | `TMPL-MNR-01` | **126.03 s** | 2 | 8 | 4 | 13 | 1 | `PASS: CLEAN` |
| `run-s4a-r4-02` | `TMPL-MNR-02` | **124.55 s** | 2 | 7 | 4 | 13 | 1 | `PASS: CLEAN` |
| `run-s4a-r4-03` | `TMPL-MNR-04` | 78.42 s | 2 | 5 | **0** | 9 | 1 | **`FAIL: Missing telemetry from source 'hubble': count=0`** |

The Decision D-34 duration target is confirmed by measurement: the two `high` runs lasted **126.03 s** and **124.55 s** against the predicted ~130 s (a −3 % deviation), and their cAdvisor series is at the 200 mcores cap (median 198.34 and 199.59 m, 100 % and 90.9 % of the post-lag samples >= 100 m, post-lag medians 199.82 and 199.74 m — the D-27 floor is 100 m). The D-34 **capture fix also works**: `run-s4a-r4-01` and `run-s4a-r4-02` both captured 2 Falco events, and the absolute `--since-time` window is what made that possible for a 126 s run.

The run that stopped the batch, `run-s4a-r4-03` (`TMPL-MNR-04`), was **quarantined automatically** into `data/raw/failed_runs/run-s4a-r4-03` by the runner (the D-34 change), with the authoritative copy in `data/raw_backup/run-s4a-r4-03`.

### 14.2 The root cause of the 0-flow run: the pool probe sends no packet

`TMPL-MNR-04` produced **zero** Hubble flows, and the relay confirms the flows do not exist (a direct relay query over the run window and over a ±5 min window returns no flow for `tenant-a` in that period). The Falco events are present and correct:

```text
2026-10-20T01:39:44.783825460Z | Interactive Shell Spawned in Non-Debug Container
2026-10-20T01:39:44.785341335Z | Suspicious High Port Egress   (rport=5555 rip=198.51.100.22)
```

The cause is in the **command**, not in the instrumentation. The Round 4 mining commands use a payload-less probe:

```sh
nc -u -w 1 198.51.100.22 5555 || true
```

`nc` in UDP mode copies **stdin** to the socket. Under `kubectl exec` without `-i` the pod's stdin is at EOF, so `nc` sends **no datagram at all** and exits. The socket is still `connect()`ed, which is why the Falco `Suspicious High Port Egress` rule fires (its condition is `evt.type in (connect, sendto)` and `fd.rport` is set by the `connect`), but no packet leaves the pod, so Cilium records **no flow**.

The verified corpus anchor does not have this defect — `TMPL-MNR-03` pipes a payload:

```sh
echo p | nc -u -w 1 198.51.100.22 8080 || true; for i in $(seq 875); do ...
```

and its captured telemetry contains the two expected dropped flows:

```text
run-s4a-02 (TMPL-BEN-04): DROPPED UDP dport=3333 10.244.0.195 -> 198.51.100.22   (x2)
run-s4a-10 (TMPL-UNK-03): DROPPED UDP dport=8080 10.244.0.81  -> 198.51.100.22   (x2)
```

The Round 4 rewrite of the mining templates dropped the `echo p | ` prefix (9 characters) that the corpus anchor has. The consequence is confined to the templates whose **only** network activity is the pool probe:

| Template | Network activity | Flows captured | Outcome |
|:---|:---|--:|:---|
| `TMPL-MNR-01`, `MNR-02`, `MNR-05` | pool probe **+ type-A DNS observation** | 4 (all DNS, dport 53) | the gate passes, but the pool egress is **invisible in Hubble** — a deviation from the plan's scenario |
| `TMPL-MNR-07` | pool probe **+ periodic DNS in the loop** | (not reached) | the same deviation |
| `TMPL-MNR-04`, `MNR-06`, `MNR-08` | pool probe only | **0** | the per-run gate fails |

Every other Round 4 template that probes a port still carries a payload (`echo p | nc -u ...` or `printf '...' | nc -u ...`), including the D-29 type-D observation, so **batches 5b, 5c and 5d are not affected by this defect**.

### 14.3 Proposed fix — **APPROVED AND APPLIED (Decision D-35)**

Restore the corpus anchor's payload to the mining pool probe, i.e. change the `connect` prefix of `mining_high()` and `mining_throttled()` in `scripts/stage4a_round4.py`:

```diff
-    connect = f"{prefix}nc -u -w 1 198.51.100.22 {port} || true; "
+    connect = f"{prefix}echo p | nc -u -w 1 198.51.100.22 {port} || true; "
```

Effects that follow from that one-line change and would have to be applied with it:

* the seven mining commands grow by 9 characters (MNR-01/02/05 183 -> 192, MNR-04 135 -> 144, MNR-06 134 -> 143, MNR-07 230 -> 239, MNR-08 135 -> 144). **Every length bin is unchanged** (`151-250+` for MNR-01/02/05/07, `81-150` for MNR-04/06/08), so the bin table and the plan-vs-runner consistency check are unaffected;
* the two runs already collected in this attempt (`run-s4a-r4-01`, `run-s4a-r4-02`) become **stale** and would have to be re-run and moved to `data/raw/superseded_runs/`;
* `run-s4a-r4-03` (the failed attempt) would be re-run as well;
* the D-34 duration calibration is **unaffected** (a 1-byte datagram costs ~1 ms and does not change the CPU cost per inner loop);
* the expected Hubble band for the mining templates changes from "4 flows (DNS only)" to "6 flows (4 DNS + 2 dropped pool egress)" for the four templates that carry the type-A DNS observation, and from "0 flows" to "2 flows (dropped pool egress)" for the three whose only network activity is the pool probe — all still the `LOW` band, so the plan's `Hubble Band` column does not change. The expected count is now declared per template in `scripts/stage4a_round4.py` (`expect_hubble_flows`) and printed in the registry's `Safety Notes`;
* the four throttled mining intensities are re-derived **only from measurements** (Decision D-35): `MNR-04` is the measured 80.17 m, and `MNR-06` (~69 m), `MNR-07` (~80 m) and `MNR-08` (~96 m) are derived from that measurement by the pause length, each labelled with its basis in the registry.

### 14.4 A second, smaller deviation: the throttled mining intensity

`TMPL-MNR-04` measured a cAdvisor median of **80.17 m** (max 88.90 m) against the D-34 prediction of ~64 m, and a wall time of **78.42 s** against the declared 70 s (+12 %). Both stay far inside the Decision D-27 throttled band (post-lag median >= 40 m, >= 60 % of post-lag samples >= 40 m): the measured post-lag median is 80.24 m with 100 % of the 7 post-lag samples >= 40 m. The cause is that the per-iteration wall time of the throttled shape is ~15.5 ms rather than the 12.4 ms extrapolated from the `TMPL-MNR-03` anchor (the `sleep` overshoot and the loop cost are larger than the model). **Proposed correction, not applied:** the `Intensity` column of `TMPL-MNR-04` would move from `~64m` to the measured `~80m` once the template is re-run, and the same correction would be checked for `MNR-06`/`MNR-07`/`MNR-08`.

### 14.5 Two test-hygiene defects found while collecting the evidence

**(a) A unit test wrote into the real dataset directory.** `tests/unit/test_capture_windows.py` (added with Decision D-34) called `PerRunTelemetryCapture().prepare_run_dir("t")` with the *default* base directory, so it created `data/raw/runs/t/` — an empty run directory inside the dataset. The new dataset gate immediately flagged it (`GATE VERDICT: FAILED ... empty_source=1`), which is exactly the behaviour D-34 was meant to produce, but the offending directory was a test artefact. The test now uses a `tmp_path` base directory, and the stray directory was removed from the host and the VM (it was never a dataset row; the VM and host copies of the dataset were reconciled by sha256 afterwards).

**(b) A pre-existing flaky test.** `tests/unit/test_audit_webhook_security.py::test_audit_webhook_logging_never_records_tokens` failed **once in ~15** full-suite runs during this round and passed in 14 others. The cause is a race in the *product's* response/log ordering, not in the assertion: `AuditWebhookHandler.do_POST` writes the HTTP response (`wfile.write(response)`) **before** it emits the request log (`log_request_event(200, request_id)`), so the client can be answered before the log record exists and can assert on an empty `caplog`. The fix is test-only and preserves the assertion exactly: a bounded poll (5 s) waits for the expected record before the assertions run. The product code was **not** changed. Ten consecutive full-suite runs were clean after the fix (193 passed each time).

### 14.6 Round 5a attempt 3 (after Decision D-35): 1 of 10, hard stop at run 1

`run-s4a-r4-01` (`TMPL-MNR-01`) was executed with the Decision D-35 command and **the probe fix worked exactly as predicted**: the captured Hubble source holds **6 flows — 2 `DROPPED UDP dport=3333 10.244.0.93 -> 198.51.100.22` (the pool egress) + 4 DNS flows**, and both expected Falco rules fired (`Interactive Shell Spawned in Non-Debug Container`, `Suspicious High Port Egress`).

The per-run gate nevertheless reported **`FAIL: High-CPU duration too short: 111.52s < 120s`**. The cause is the **duration calibration**, not the telemetry:

| measurement | iterations | ms per 3000-iteration inner loop | cAdvisor window (the gate's measure) | verdict |
|:---|--:|--:|--:|:---|
| Round 5a attempt 1 (`run-s4a-r4-01`, 10 000 iterations) | 10 000 | 28.84 ms | 293.57 s | pass |
| Round 5a attempt 2 (`run-s4a-r4-01`, 4200 iterations) | 4 200 | 28.07 ms | 123.04 s | pass |
| Round 5a attempt 3 (`run-s4a-r4-01`, 4200 iterations) | 4 200 | **25.33 ms** | **111.52 s** | **fail** |

The wall time of the identical inner loop varies by **13.9 %** between runs (environmental, the VM's vCPU performance), and the Decision D-34 count of 4200 was derived from the mean of the first two measurements. It therefore landed exactly on the gate boundary: 123.04 s in the slow case (passing) and 111.52 s in the fast case (failing by 3.5 s). Decision D-36 sets the count for the **fastest** observed case (4950 iterations, the same principle as D-26: a band must exceed the measured noise floor), which gives a 130.5 s window in the fast case and 147.9 s in the slow one.

**A note on the gate's own message, which is not changed here.** `scripts/stage2_pilot.py` rejects the run with `if calc_dur < 115.0` but prints `"< 120s"`, so the message states a stricter threshold than the code enforces. The Decision D-20 text says "120 s for cryptomining" and the code enforces 115 s. The gap between the two is a pre-existing cosmetic inconsistency; the Decision D-36 count clears **both** (130.5 s > 120 s), so the run is valid under either reading. **The gate was not modified.**

---

## 15. Stage 4a Round 5a — Attempt 4 (after Decisions D-35 and D-36): 10 of 10, batch complete

### 15.1 The result

The runner's own summary line:

```text
================ STAGE 4a ROUND 5a SUMMARY ================
run-s4a-r4-01 TMPL-MNR-01  cryptomining     dur= 133.05s falco=2 audit=5 hubble=6  prom=14 trivy=1 cpu[0.0/199.41/200.55] profile=high      gate=PASSED
run-s4a-r4-02 TMPL-MNR-02  cryptomining     dur= 133.26s falco=2 audit=5 hubble=6  prom=14 trivy=1 cpu[0.0/198.03/199.97] profile=high      gate=PASSED
run-s4a-r4-03 TMPL-MNR-04  cryptomining     dur=  76.18s falco=2 audit=5 hubble=2  prom=9  trivy=1 cpu[0.0/71.38/74.12]  profile=throttled gate=PASSED
run-s4a-r4-04 TMPL-MNR-05  cryptomining     dur= 132.96s falco=1 audit=5 hubble=6  prom=14 trivy=1 cpu[0.0/198.05/200.33] profile=high      gate=PASSED
run-s4a-r4-05 TMPL-MNR-06  cryptomining     dur=  76.28s falco=2 audit=5 hubble=2  prom=9  trivy=1 cpu[0.0/59.32/60.30]  profile=throttled gate=PASSED
run-s4a-r4-06 TMPL-MNR-07  cryptomining     dur=  84.34s falco=2 audit=6 hubble=71 prom=9  trivy=1 cpu[0.0/73.96/81.63]  profile=throttled gate=PASSED
run-s4a-r4-07 TMPL-MNR-08  cryptomining     dur=  94.55s falco=2 audit=6 hubble=2  prom=10 trivy=1 cpu[0.0/86.63/94.03]  profile=throttled gate=PASSED
run-s4a-r4-08 TMPL-PRV-06  privilege_abuse  dur=   7.14s falco=1 audit=8 hubble=13 prom=2  trivy=1 cpu[0.0/0.0/0.0]     profile=low       gate=PASSED
run-s4a-r4-09 TMPL-PRV-08  privilege_abuse  dur=   9.22s falco=1 audit=8 hubble=30 prom=2  trivy=1 cpu[0.0/4.69/4.69]   profile=low       gate=PASSED
run-s4a-r4-10 TMPL-ESC-01  container_escape dur=   7.16s falco=3 audit=5 hubble=3  prom=2  trivy=1 cpu[0.0/0.44/0.44]   profile=low       gate=PASSED
completed=10/10 stop_reason=None
EXIT=0
```

Both fixes are confirmed by the telemetry: **every** mining run carries exactly **2 `DROPPED` pool-egress flows** to its own port (3333, 4444, 5555, 6379, 7777, 9999, 8888) — the Decision D-35 payload — and the three `high` runs last **133.05 / 133.26 / 132.96 s** against the Decision D-22 target of ~130 s, i.e. the Decision D-36 count holds the duration in the fast case as designed.

The Decision D-27 post-lag statistics (the gate's own quantities): `MNR-01` 199.81 m / 91.7 % / 12 post-lag samples, `MNR-02` 198.10 m / 83.3 %, `MNR-05` 198.05 m / 91.7 % (floor 100 m, 80 % required); `MNR-04` 71.38 m / 100 %, `MNR-06` 59.64 m / 85.7 %, `MNR-07` 76.25 m / 100 %, `MNR-08` 86.69 m / 100 % (floor 40 m, 60 % required). Every mining run is `OK`.

### 15.2 Deviations from the plan (proposed corrections, NOT applied)

| # | Template | Plan says | Measured | Proposed correction |
|:--|:---|:---|:---|:---|
| 1 | `TMPL-MNR-01`, `MNR-02`, `MNR-05` | Hubble band `LOW` | **6 flows = `MID`** (2 dropped pool egress + 4 DNS) | the `Hubble Band` column becomes `MID`; the Decision D-35 flow count of 6 was already correct |
| 2 | `TMPL-MNR-07` | Hubble band `LOW`, 6 flows | **71 flows = `HIGH`** | the `Hubble Band` column becomes `HIGH`; the expected count becomes ~71 (the scenario resolves the pool name every 50 iterations, i.e. 18 lookups x 4 flows, plus the 2 pool-egress flows) — the Decision D-35 declaration of 6 for this template was wrong |
| 3 | `TMPL-PRV-06` | Hubble band `MID` | **13 flows = `HIGH`** | the `Hubble Band` column becomes `HIGH` |
| 4 | `TMPL-ESC-01` | expected rules `Shell Spawn, Sensitive File Read` | **3 rules**: `Interactive Shell Spawned in Non-Debug Container` (the spawn), **`Read sensitive file untrusted`** (the Falco *default* rule, for `/etc/shadow`) and `Read Sensitive Host Information Untrusted` (the lab rule, for `/etc/passwd`) | the `Expected Falco Rules` column adds the default rule; the two identity reads are read by two different rules because the lab rule and the Falco default rule both cover identity files |
| 5 | `TMPL-MNR-04`, `MNR-06`, `MNR-07`, `MNR-08` | intensity `~80m`, `~69m`, `~80m`, `~96m` | **71.38**, **59.32**, **73.96**, **86.63** m (post-lag medians 71.38 / 59.64 / 76.25 / 86.69) | the `Intensity` column takes the measured values; the Decision D-35 derivation from the attempt-2 measurement of `MNR-04` (80.17 m) is 9-11 % high because of the same 14 % run-to-run spread that Decision D-36 had to accommodate |
| 6 | `TMPL-MNR-04`, `MNR-06`, `MNR-07`, `MNR-08` | duration `70s`, `70s`, `80s`, `90s` | **76.18**, **76.28**, **84.34**, **94.55** s | the `Duration` column becomes the measured values (+6-9 %), or the column stays a target and the safety notes carry the measured duration |
| 7 | `TMPL-MNR-01`, `MNR-02`, `MNR-05` | duration `130s` | 133.05 / 133.26 / 132.96 s | no correction needed (+2.4 %, inside the variance) |

### 15.3 The gate's own message is inconsistent with its code (not changed)

`scripts/stage2_pilot.py` rejects a `high` run with `if calc_dur < 115.0` but prints `"High-CPU duration too short: {calc_dur}s < 120s"`, and Decision D-20's text says "120 s for cryptomining". The code therefore enforces 115 s while the message and the decision text say 120 s. The Decision D-36 count clears **both** (130.5 s in the fast case), so every run of this batch is valid under either reading. The gate was **not** modified; the discrepancy is recorded here for the reviewer.
