# ARCHITECTURE SPECIFICATION: RuntimeLens

## 1. Architectural Philosophy
RuntimeLens is structured as a **modular single package** (`src/runtimelens`) rather than distributed microservices. This design satisfies all CORE requirements with minimal operational overhead, eliminates network serialization latency between internal modules, and runs comfortably within a 6 GB Linux VM. Every architectural seam is defined via pure interfaces and strict data models.

```
                           +----------------------------------------+
                           |       Kubernetes Lab Cluster           |
                           |   (kind + Cilium CNI + 3 Tenants)     |
                           +----------------------------------------+
                             |           |           |           |
                           Falco       Audit       Hubble      Trivy
                          (Webhook)   (File)      (Stream)     (CLI)
                             |           |           |           |
                             v           v           v           v
    +-----------------------------------------------------------------------+
    |                    Telemetry Collectors & Sanitizers                  |
    |  - Size-capped rotated raw JSONL capture                              |
    |  - Secret redaction (tokens, credentials, env vars)                   |
    |  - Heartbeat & watermark tracking                                     |
    +-----------------------------------------------------------------------+
                                        |
                                        v
    +-----------------------------------------------------------------------+
    |               Normalizer & Correlation Engine (Window +-30s)          |
    |  - Pydantic v1.0.0 Canonical Schema Enforcement                       |
    |  - Deterministic Fact Extraction (root, mounts, capabilities)         |
    |  - Workload Baseline Store (Declarative Git YAML)                     |
    +-----------------------------------------------------------------------+
                                        |
                                        v
    +-----------------------------------------------------------------------+
    |                       Optional Rule Pre-Filter                        |
    |  - Cheap deterministic drop of routine benign events (ablation-tested)|
    +-----------------------------------------------------------------------+
                                        |
                                        v
    +-----------------------------------------------------------------------+
    |                     Universal Classifier Interface                    |
    |             classify(state) -> Unified ClassificationResult           |
    |    +--------------------+--------------------+-------------------+   |
    |    |  Rule-Based Engine |  Random Forest ML  | ScaleDown Adapter |   |
    |    | (Falco defaults)   | (scikit-learn)     | (classify-1)      |   |
    |    +--------------------+--------------------+-------------------+   |
    +-----------------------------------------------------------------------+
                                        |
                                        v
    +-----------------------------------------------------------------------+
    |                  Deterministic Decision Policy Engine                 |
    |  - Precedence 1: Safety Overrides (critical facts, degraded mode)     |
    |  - Precedence 2: Choice-Noul Conflict Resolution                      |
    |  - Precedence 3: Calibrated Confidence Gate (provisional 0.70)        |
    |  - Extension 4: Exposure-Based Risk Score (low cut priority)          |
    +-----------------------------------------------------------------------+
                     |                                       |
                     v                                       v
    +---------------------------------+     +-------------------------------+
    |       Human Review Queue        |     |  Response Controller (Dry-Run)|
    |  - Append-only JSONL            |     |  - Pod label patching         |
    |  - Blind CLI review tool        |     |  - Pre-installed NetworkPolicy|
    |  - Extension 5: Proposed Diffs  |     |  - Auto-rollback TTL timer    |
    |    (low cut priority)           |     |  - Pod Delete: ZERO PERMISSION|
    +---------------------------------+     +-------------------------------+
                     \                                       /
                      v                                     v
    +-----------------------------------------------------------------------+
    |             Tamper-Evident Audit Log & Metrics Store                  |
    |  - Hash-chained JSONL audit records                                   |
    |  - Prometheus metrics exporter (latencies, class counts, drops)       |
    |    [Note: ECE is an offline evaluation metric, not in exporter]       |
    +-----------------------------------------------------------------------+
```

## 2. Component Subsystems & Boundary Justifications

### 2.1 Laboratory Environment Subsystem
- **Runtime:** `kind` cluster running on an Ubuntu 24.04 VM (Apple M1 host, 4 vCPUs, 6 GB RAM).
- **Network CNI:** Cilium with eBPF host routing, `kubeProxyReplacement=true`, and Hubble observability enabled.
- **Tenancy:** 3 isolated namespaces (`tenant-a`, `tenant-b`, `tenant-c`) each running 4 ARM64 workloads: `web` (reverse proxy), `api` (FastAPI), `database` (Redis), and `payment-style` (transaction worker).
- **Cluster Boundary Isolation:** All lab management endpoints (API server, Hubble, Grafana) bind exclusively to `127.0.0.1`.

### 2.2 Telemetry Ingestion Subsystem (Live Cluster Capture)
- **Falco Collector:** Ingests live runtime syscall events via HTTP JSON webhook receiver bound to localhost. Pinned default Falco rules mapped to classes; any custom lab rules explicitly labeled `custom_lab_rule`.
- **Kubernetes Audit Collector:** Tails dedicated audit log generated by `kubeadmConfigPatches` with a targeted `AuditPolicy` capturing RBAC and pod exec events while omitting secret payloads.
- **Hubble Collector:** Streams flow metadata filtered to tenant egress, cross-tenant, and dropped packets.
- **Trivy Collector:** Executes static CLI vulnerability scans cached by image digest in the baseline store.
- **Prometheus Collector:** Scrapes container CPU/memory usage to detect sustained resource spikes.
- **Sanitization Boundary:** Automated scrubbing of secrets, tokens, credentials, and environment variables occurs *immediately* at collection before data enters storage or normalization.

### 2.3 Normalization & Correlation Engine
- **Schema Enforcement:** Strict Pydantic model (`v1.0.0`) forbidding unknown fields.
- **Sliding Window:** Configurable $\pm 30$ second window keyed by `(namespace, pod_uid, owner_workload, container_id)`.
- **Fact Extraction:** Computes unambiguous booleans (e.g. `host_runtime_socket_mounted`, `is_root`, `is_shell_exec`).
- **Baseline Context:** Ingests declarative Git-versioned YAML baselines defining permitted binaries, parent processes, and expected peers. Discrepancies flag `baseline_deviation=True`.

### 2.4 Classifier Subsystem
Encapsulates threat classification behind a single typed contract:
```python
def classify(state: CanonicalState) -> ClassificationResult:
    ...
```
- **Rule-Based Baseline:** Maps default Falco and audit rules directly to threat classes, with custom lab rules segregated and labeled.
- **Classical ML Baseline:** Scikit-learn Random Forest trained on engineered numerical/categorical feature vectors (sanitized of all identifiers).
- **ScaleDown Classify-1 Adapter:** Encapsulates HTTP calls to `https://api.scaledown.xyz/v1/scaledown`, passing a hardened `state.text` with delimited untrusted inputs, accompanied by Choice, Score, and Noul questions. Handles retries, timeout, and response caching.
- **Fair Tuning Budget:** All three classifiers are given an identical tuning budget on the Dev split.

### 2.5 Policy & Containment Subsystem
- **Pure Function:** `evaluate_policy(result, facts, telemetry_health, baseline_status) -> (action, reason_codes, policy_version)`.
- **Precedence Hierarchy:** Safety overrides strictly supersede model outputs. Degraded telemetry, API failures, or critical deterministic facts bypass model predictions and force human review or low-priority alerts.
- **Response Actions:**
  - `log`: Recorded for confident benign activity.
  - `alert`: Low or high-priority notifications (webhook/local JSONL).
  - `human_review`: Dedicated queue for ambiguous, low-confidence, or contradictory events.
  - `quarantine`: Controlled patching of `quarantine=true` label triggering pre-installed default-deny `NetworkPolicy` with automated TTL rollback.
  - `terminate`: **Not implemented; design and future work only.** Zero pod delete permissions exist in RBAC, controller code, or manifests.

### 2.6 Audit, Observability & Feedback Subsystem
- **Storage:** Atomic append-only JSONL files with single-writer lock.
- **Tamper-Evident Audit Logging:** Every decision logs input state hash, raw response reference, model version, latency, policy version, reason codes, and previous record hash.
- **Metrics:** `prometheus_client` exporter exposing decision counts, class distributions, latency histograms, and degradation rates (ECE is computed offline in the evaluation harness, not exposed at runtime).
- **Feedback Loop (Extension 5):** Human analyst verdicts generate proposed Git diffs for baseline adjustments; updates require manual PR approval and apply solely to the dev split. Lowest priority in scope-shedding order.
