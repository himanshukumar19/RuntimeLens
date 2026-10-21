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
