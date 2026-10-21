# SPECIFICATION: RuntimeLens (Product Requirements Document)

## Problem Statement

Multi-tenant Kubernetes clusters share a single operating system kernel and orchestration control plane across distinct applications and tenants. While static container security tools (such as image vulnerability scanners) identify pre-deployment flaws, they provide zero visibility into post-launch runtime behavior or active orchestration manipulation.

High-impact container threats—such as container escape, privilege abuse, and cryptomining—manifest across heterogeneous, uncoordinated event streams (kernel system calls, Kubernetes API audit logs, pod-to-pod network flows, and resource utilization spikes). Existing security tools fall short in two critical ways:
1. **Rule-based intrusion detection systems (such as default Falco engines)** rely on rigid, hand-authored patterns that lack workload context. An action that is routine for a developer maintenance container (e.g., launching an interactive shell) is flagged identically to the same action occurring within an unprivileged payments service.
2. **Classical machine learning approaches** require manual feature engineering, depend on large labeled training corpora, and struggle to incorporate evolving contextual workload policies without complete retraining.

Furthermore, deploying automated AI response mechanisms in SRE environments presents acute availability risks: false-positive automated pod terminations cause catastrophic service outages, while uncalibrated probabilistic models lack deterministic containment safety guardrails.

## Solution

RuntimeLens provides a context-aware runtime threat detection, classification, and containment pipeline for multi-tenant Kubernetes environments.

The system collects heterogeneous security telemetry from live cluster workloads across four layers:
- Runtime system calls via Falco eBPF
- Orchestration control-plane operations via Kubernetes API audit logs
- Inter-workload and egress network flows via Cilium and Hubble
- Static vulnerability profiles via Trivy, combined with Prometheus CPU/memory metrics

Rather than evaluating raw events in isolation, RuntimeLens pairs each event with a declarative, Git-versioned workload baseline profile and extracts verified deterministic facts in code. The enriched state is evaluated by a constrained typed-decision model (ScaleDown Classify-1 via a Jev-compatible Decisions API) that simultaneously resolves:
- Threat class (`benign`, `container_escape`, `privilege_abuse`, `cryptomining`, `unknown`)
- Continuous severity score (mapped to a 1–5 rubric)
- Four independent binary verification evidence flags (`baseline_deviation`, `shell_unexpected`, `resource_exposure`, `resource_abuse`)

Downstream from the classifier, a pure deterministic policy engine enforces strict safety precedence: verified deterministic facts override model outputs, Choice-Noul contradictions route to human review, and automated containment is restricted to reversible, label-based `NetworkPolicy` quarantine with automatic TTL rollback. Workload pod deletion is explicitly prohibited. Every decision, probability distribution, and state transition is captured in a tamper-evident, hash-chained audit log.

## User Stories

1. As a Security Operations Center (SOC) Analyst, I want multi-source container telemetry (Falco, Audit, Hubble, Trivy) correlated within a temporal window, so that I can observe the full attack lifecycle of an incident rather than triaging isolated alerts.
2. As a Site Reliability Engineer (SRE), I want interactive shell executions in dedicated debug pods to be classified as benign, so that routine on-call maintenance does not generate false alarms.
3. As a Security Engineer, I want unexpected shell spawns in critical payment pods to trigger immediate high-severity alerts, so that potential container breakouts are halted instantly.
4. As an SRE, I want automated incident containment to operate via reversible label-based `NetworkPolicy` quarantine rather than pod deletion, so that healthy services experiencing transient false positives are not terminated.
5. As an SRE, I want automated pod quarantines to feature an automatic TTL expiration timer, so that isolated workloads cleanly recover if an analyst does not explicitly confirm the containment.
6. As a Security Auditor, I want every classification decision and containment action recorded in a tamper-evident, hash-chained audit log, so that all automated security interventions are forensically verifiable.
7. As an SRE, I want the response controller to have strictly zero pod deletion permissions in its Kubernetes RBAC Role, so that a software defect or model hallucination can never terminate running workloads.
8. As a Machine Learning Researcher, I want threat classification benchmarked across three separate paradigms (Falco rules, Random Forest ML, and ScaleDown Classify-1) on the exact same frozen held-out test dataset, so that comparative claims are scientifically valid.
9. As an Academic Evaluator, I want statistical significance evaluated using cluster-aware bootstrap resampling grouped by cluster run ID, so that intra-run event correlation does not produce artificially inflated confidence intervals.
10. As a SOC Analyst, I want a human review queue with a blind review mode, so that I can review raw incident telemetry without bias before seeing model predictions.
11. As an SRE, I want high-volume routine benign events filtered by a lightweight pre-filter before invoking hosted decision models, so that cloud API costs and processing latencies are minimized.
12. As a Security Engineer, I want untrusted command-line arguments and container labels sanitized, truncated, and delimited inside `<untrusted_args>` tags, so that prompt-injection attacks cannot deceive the decision model.
13. As an SRE, I want critical deterministic facts (such as host socket mounts) to strictly override model predictions, so that verified high-risk misconfigurations trigger alerts even if a model outputs a benign label.
14. As an SRE, I want the pipeline to enter a degraded mode when external decision APIs timeout or return errors, so that incidents are routed to human review rather than silently dropped or assumed benign.
15. As a Security Operations Engineer, I want contradictions between the predicted threat class and binary evidence flags (e.g. benign class predicted with high baseline deviation) to route to human review, so that model uncertainties are safely escalated.
16. As a DevOps Engineer, I want workload baselines stored as human-readable, Git-versioned YAML files, so that baseline changes require formal pull request reviews and cannot be poisoned by attackers.
17. As an SRE, I want the response controller to verify cluster context and namespace allowlists before taking any action, so that containment never touches system or pipeline namespaces.
18. As a Software Engineer, I want all CI unit and contract tests to run completely offline using mock JSON fixtures, so that tests never require live API keys or incur vendor costs.
19. As an Academic Evaluator, I want the primary hypothesis (baseline context on vs off) pre-registered with a minimum meaningful effect size, so that research conclusions are protected against p-hacking.
20. As a SOC Analyst, I want alert notifications grouped and rate-limited by incident ID, so that an alert storm does not overwhelm incident response channels.
21. As a Security Researcher, I want paired counterfactual scenarios where only baseline context differs, so that the causal impact of workload baseline context can be experimentally proven.
22. As an SRE, I want pipeline performance metrics (latencies, drop rates, decision counts) exported to Prometheus, so that the operational reliability of the security system can be continuously monitored.
23. As a Compliance Officer, I want client-side redaction of secrets, tokens, and credentials before data leaves the cluster, so that sensitive data is never exposed to third-party model providers.
24. As an SRE, I want the entire laboratory cluster, workloads, and telemetry collectors rebuildable via a single idempotent command, so that experimental environments are 100% reproducible.
25. As a SOC Analyst, I want analyst feedback on legitimate baseline deviations to format proposed Git diffs rather than auto-applying changes, so that the system avoids slow-boil baseline poisoning.

## Implementation Decisions

### Architectural Seams & Core Interfaces
The architecture avoids distributed microservices in favor of a single modular Python package structured around four primary testing and operational seams:

1. **Ingestion & Normalization Seam:**
   - Raw JSON/streaming inputs from Falco, Kubernetes Audit logs, Hubble flows, and Trivy scans are ingested into a uniform Pydantic model (`CanonicalEvent`, semantic version `1.0.0`).
   - Rejects unknown fields (`extra = "forbid"`), normalizes UTC timestamps, deterministic UUIDv4 identifiers, and tracks missing/degraded sensors explicitly.
   - Computes unambiguous deterministic facts (`facts`) directly in code.

2. **Workload Baseline Seam:**
   - Ingests declarative Git-versioned YAML files defining allowlisted executables, parent processes, permitted mounts, expected network peers, and CPU/memory envelopes.
   - Evaluates deviations deterministically, populating `baseline_deviation_detected` and explicit deviation lists.
   - Enforces zero automated learning: all baseline updates require reviewed Git commits.

3. **Universal Classifier Seam:**
   All detection engines implement a single polymorphic interface:
   ```python
   def classify(state: CanonicalState) -> ClassificationResult
   ```
   - `ClassificationResult` encapsulates predicted class, class probability distribution, continuous severity score (1–5), level confidence, four binary Noul evidence probabilities, model identifier, version, execution latency, and degraded mode flags.
   - Implementations:
     - Rule-Based Baseline (Falco default rules mapped to classes; custom lab rules explicitly tagged).
     - Classical ML Baseline (Scikit-learn Random Forest trained on sanitized numerical/categorical feature vectors).
     - ScaleDown Classify-1 Adapter (HTTP client calling `/v1/scaledown` with retry backoff, hard timeouts, and local response caching).

4. **Deterministic Policy & Containment Seam:**
   - Implemented as a pure, side-effect-free function:
     ```python
     def evaluate_policy(
         classification: ClassificationResult,
         facts: ExtractedFacts,
         telemetry_health: TelemetryHealth,
         baseline_status: BaselineStatus,
     ) -> PolicyDecision
     ```
   - Enforces a strict precedence hierarchy: Safety Overrides $\rightarrow$ Table-Driven Choice-Noul Conflict Checks $\rightarrow$ Calibrated Confidence Gating.
   - Dispatches containment actions: `log`, `alert`, `human_review`, and `quarantine`.
   - **Pod termination is not implemented; it is design and future work only.** Zero pod delete permissions exist across RBAC, controller code, or manifests.

### State Hardening & Sanitization
- Untrusted text (process arguments, container image names, pod labels) is normalized under Unicode NFC, stripped of control, zero-width, and bidi characters, truncated to 128 characters, and wrapped in `<untrusted_args>` tags.
- Deterministic security features (shell metacharacters, runtime-socket reference, sensitive-path reference, identity-file reference) are computed from the full raw string *before* truncation and passed as trusted factual booleans. The raw string's character count is recorded in the audit record for forensics but is **not** a classifier feature: Decision D-28 excludes `command_length` from the 18-feature classifier feature set and from the ScaleDown state.
- A SHA-256 hash of the complete raw string is retained in the audit record for forensic traceability.

### Containment Mechanics & Safety Guardrails
- **Label-Based Quarantine:** The response controller isolates pods exclusively by patching `quarantine=true` metadata labels. Pre-installed Kubernetes `NetworkPolicies` in tenant namespaces enforce default-deny ingress and egress (preserving `kube-dns`).
- **Auto-Rollback:** Automated quarantine actions initiate an asynchronous TTL countdown (default 15 minutes). If an analyst does not confirm or extend the containment, the label is removed automatically.
- **Least-Privilege RBAC:** The response controller operates under a dedicated namespaced ServiceAccount with permissions strictly limited to `get`, `list`, `watch`, and `patch` on `pods`. Pod `delete` is prohibited.
- **Dry-Run by Default:** The engine generates execution diffs and writes would-do records to audit logs by default. Live actuation is strictly opt-in.

### Evaluation & Statistical Rigor
- **Pre-Registration:** Primary metric is Macro-F1 across 5 classes (`benign`, `container_escape`, `privilege_abuse`, `cryptomining`, `unknown`) with a pre-registered minimum meaningful effect size to be set after a real pilot.
- **Dataset Partitioning:** 400 live cluster scenario runs partitioned into Dev (72%, 288 runs) and Held-Out Test (28%, 112 runs). Grouped strictly by `run_id` and scenario variant to eliminate data leakage.
- **Cluster-Aware Statistics:** 95% Confidence Intervals are computed via cluster bootstrap resampling by `run_id` (1,000 iterations). Paired model comparisons use an incident-level McNemar test with Holm-Bonferroni multi-hypothesis corrections.
- **Ablation Suite:** Evaluates 6 core ablations: Baseline Context (Primary), Pre-Filter, Discriminating Descriptions, Confidence Threshold Sweep, Telemetry Fusing, and Question Combinations.
- **Included Extensions & Scope-Shedding Hierarchy:** Exposure-based risk score (Extension 4) and human feedback loop diff generation (Extension 5) are included in scope but designated lowest priority in the cut order.

## Testing Decisions

### What Makes a Good Test
Tests in RuntimeLens focus strictly on external behavior, interface contracts, and security invariants rather than private implementation details:
- **Contract Fidelity:** External API adapters are tested against real recorded HTTP response payloads rather than manual mocks.
- **Invariance Under Adversarial Inputs:** Input sanitizers are tested via property-based fuzzing to guarantee that no input string can produce unescaped tags or control characters.
- **Zero-Secret CI:** Standard unit and integration test suites run 100% offline without live network dependencies or API keys.

### Module Test Coverage
1. **Canonical Schema & Fact Extraction (`tests/unit/test_schema.py`, `test_facts.py`):**
   - Validates JSON schema adherence, field absence, and correct boolean fact extraction across 20+ synthetic pod specs and syscall payloads.
2. **Policy Engine & Conflict Matrix (`tests/unit/test_policy.py`):**
   - Exhaustively validates the pure `evaluate_policy` function across every cell of the Choice-Noul conflict matrix and safety override conditions.
3. **Property-Based Sanitizer Fuzzing (`tests/unit/test_sanitizer.py`):**
   - Uses `hypothesis` to fuzz the string sanitizer with arbitrary Unicode, delimiter break sequences, and long buffers.
4. **Leakage Assertion Test (`tests/unit/test_leakage.py`):**
   - Asserts that model feature vectors and serialized `state.text` contain zero occurrences of `run_id`, pod-name suffixes, IP addresses, absolute timestamps, or seeds.
5. **ScaleDown Adapter Contract Tests (`tests/contract/test_scaledown_adapter.py`):**
   - Evaluates offline parsing of recorded fixtures: Choice, continuous Score, Noul probabilities, HTTP 402, 422, 429 backoff, and 502/504 fallback handling.
6. **RBAC Security Negative Tests (`tests/integration/test_rbac.py`):**
   - Verifies via `kubectl auth can-i` that the response controller is forbidden from deleting pods or accessing non-tenant namespaces.
7. **Quarantine & Rollback Integration (`tests/integration/test_quarantine.py`):**
   - Verifies label patching, NetworkPolicy egress blocking in Cilium, and automated TTL rollback expiration.

### Prior Art
- **Kubernetes E2E Testing Framework:** Mirrors upstream Kubernetes patterns for ephemeral test namespace isolation and RBAC permission checks.
- **VCR / Recorded HTTP Fixtures:** Adopts standard recorded contract testing practices for LLM/SLM API clients.
- **Hypothesis Property-Based Testing:** Standard academic and industrial approach for formally proving string sanitization bounds.

## Out of Scope

1. **Unsupervised Pod Termination:** Automated pod deletion is not implemented; it is design and future work only. Zero pod delete permissions exist in RBAC or controller code.
2. **Real Exploits or Live Malware:** No kernel exploits, weaponized breakout payloads, or public cryptocurrency mining pools will be used. All scenarios rely on benign-intent simulated indicators.
3. **Heavy Infrastructure Operators:** Kafka, Redis message brokers, Elasticsearch/Kibana, and PostgreSQL are excluded in favor of single-process modular pipelines and atomic JSONL storage.
4. **Multi-Model Provider Benchmarking:** Comparisons against other hosted decision providers (such as TypeSafe Jev) or fine-tuned self-hosted models are deferred to future work.
5. **External System-Call Datasets:** Public intrusion detection datasets (e.g., DARPA, ADFA) are excluded to maintain 100% data fidelity with our multi-tenant Kubernetes laboratory environment.
6. **Production Enterprise Multi-Cluster Management:** The scope is strictly bounded to an isolated, single-cluster laboratory environment.

## Further Notes

- **AI-Assistance Academic Disclosure:** In accordance with academic integrity guidelines, generative AI tools (Antigravity) were utilized under Mode A pair programming: the AI assistant authored implementation code, test suites, configurations, and automation scripts under direct human direction, review, and specification. All phase gate verification tests are executed, inspected, and approved directly by the human authors.
- **Zero Data Retention Compliance:** ScaleDown operates under a published Zero Data Retention (ZDR) posture and does not train models on customer API requests. Sensitive tokens and environment variables are redacted client-side prior to transmission.
- **Predefined Outcome Commitment:** All experimental outcomes—whether positive, inconclusive, or negative—will be published and defended in the final report, poster, and viva.
