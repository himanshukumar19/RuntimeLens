# PROJECT BRIEF: RuntimeLens

## 1. Project Identity
- **Working Title:** RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model
- **Course & Institution:** Cloud Security and SRE, Indian Institute of Information Technology Dharwad
- **Faculty Guide:** Malay Kumar
- **Core Team:**
  - Himanshu Kumar (23BCS055) — Technical Lead & Sole Developer
  - Altaf Raja (23BCS011) — Documentation, Scenario Validation & Poster Redesign
  - Kamal Nayan Kumar (23BDS026) — Documentation, Statistical Proofreading & Report Revision

## 2. Executive Summary
RuntimeLens extends multi-tenant container security from static image scanning to runtime and orchestration layers. Modern container workloads share a single OS kernel, where runtime compromises (container escapes, privilege abuse, resource hijacking) unfold across heterogeneous event streams. Existing rule-based engines lack workload-specific context, while classical ML requires complex manual feature engineering and large training sets.

RuntimeLens investigates whether a fast, constrained typed-decision model (ScaleDown Classify-1 via a Jev-compatible Decisions API) can accurately classify runtime and orchestration threats when provided with structured event facts and declarative per-workload behavioural baselines. Every model decision is evaluated against deterministic safety gates, triggering reversible containment actions with complete tamper-evident audit logging.

## 3. Core Research Claim & Pre-Registration
> **Primary Hypothesis:** Incorporating per-workload behavioural baseline context into a typed-decision model produces a statistically significant change in Macro-F1 ($\Delta\text{Macro-F1} \neq 0$) and/or benign false-positive rate compared to the same classifier operating without baseline context.

Both positive and honest negative results are scientifically reportable. The formal pre-registration protocol is locked in `docs/PREREGISTRATION.md`.

## 4. Key Architectural Pillars
1. **Four Telemetry Streams from Live Cluster:** Ingestion from Falco (syscalls/eBPF), Kubernetes Audit Logs (control plane API events), Cilium/Hubble (L3/L4/L7 network flows), and Trivy (static image vulnerability context), plus Prometheus resource metrics.
2. **Deterministic Fact Extraction:** Explicit code-level verification of ground facts (e.g. sensitive mounts, privileged containers, root execution) before classifier invocation.
3. **Multi-Model Benchmark:** Fair evaluation across three classifiers on an identical frozen held-out test split with equal dev-set tuning budgets:
   - Default Falco Rule-Based Baseline (with custom lab rules explicitly labeled)
   - Scikit-Learn Classical ML Baseline (Random Forest)
   - Hosted ScaleDown Classify-1 Typed-Decision Adapter
4. **Constrained Typed Questions:**
   - **Choice:** Threat class (`benign`, `container_escape`, `privilege_abuse`, `cryptomining`, `unknown`).
   - **Score:** Continuous 5-level severity rubric (1: Informational to 5: Critical).
   - **Noul:** 4 independent binary evidence verification flags (`baseline_deviation`, `shell_unexpected`, `resource_exposure`, `resource_abuse`).
5. **Deterministic Policy & SRE Containment:** Pure functional decision policy with explicit precedence: safety overrides first, table-driven Choice-Noul conflict resolution, provisional confidence gating (calibrated on dev split), and dry-run by default. Automated containment applies label-based `NetworkPolicy` quarantine with automatic TTL rollback.
6. **Pod Termination Status:** **Not implemented; design and future work only.** Zero pod delete permissions exist in RBAC, controller code, or manifests.
7. **Included Extensions & Scope Cut Order:**
   - **Extension 4 (Exposure-Based Risk Score):** Deterministic risk formula combining model output with workload exposure metadata.
   - **Extension 5 (Human Feedback Tuning Loop):** Analyst review queue generating proposed Git diffs for Dev-set baseline tuning.
   - **Scope-Shedding Hierarchy (Lowest Priority / First to Cut):**
     1. Extension 5 (Human feedback loop diff generation)
     2. Extension 4 (Exposure-based risk score)
     3. Live quarantine enforcement (retain dry-run)
     4. Grafana dashboards (retain Prometheus metrics export)
     5. Hubble network telemetry (retain Falco + Audit)
     6. Trivy static image scans
8. **Scientific Rigor & Leakage Prevention:** Cluster-aware bootstrap confidence intervals (grouped by `run_id` across 400 total live cluster runs), paired counterfactual scenarios, separate tuning/test splits, and hash-verified split manifests.
9. **Disclosure:** The dataset is generated through live scenario executions in an isolated Kubernetes lab cluster running controlled, benign-intent simulations (no real malware, no weaponized exploits, no external mining pools).
