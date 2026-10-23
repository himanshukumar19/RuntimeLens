# RuntimeLens Academic Poster Specification (Ticket 16b)

This directory contains the redesigned academic poster assets for **RuntimeLens**, resolving all discrepancies cataloged in `docs/REPORT_DELTA.md` and executing items 1.1–1.9 of `docs/REPORT_REVISION_CHECKLIST.md`.

## Title & Attribution
- **Title:** RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model
- **Authors:** Altaf Raja (23BCS011), Kamal Nayan Kumar (23BDS026), Himanshu Kumar (23BCS055)
- **Institution:** Department of Computer Science & Engineering, Final Year Capstone Project, 2026

## Stage 1 Structural & Factual Corrections Applied
1. **Model Identity Replaced:**
   - All references to "TypeSafe Jev" and "System One" replaced with **ScaleDown Classify-1** accessed via the hosted Decisions API (`https://api.scaledown.xyz/v1/scaledown`).
   - Latency claims of "70 to 500 ms" corrected to measured distribution: **0.90–1.16 s (median 1.04 s)** based on real smoke calls (`tests/fixtures/scaledown/live_smoke_responses.json`).
2. **Workload and Tenant Harmonization:**
   - Workloads harmonized across all 3 namespaces (`tenant-a`, `tenant-b`, `tenant-c`).
   - Each namespace runs identical workload types: `web`, `api`, `database`, and `payment-style`.
3. **Telemetry Ingestion Expanded to 5 Sources:**
   - 1. Falco (eBPF syscall events)
   - 2. Kubernetes Audit Logs (API server webhook)
   - 3. Hubble / Cilium (pod-to-pod and egress network flows)
   - 4. cAdvisor / Prometheus (CPU and memory utilization)
   - 5. Trivy (cached image vulnerability CVE profiles)
4. **Pod Termination Reclassified:**
   - Marked explicitly as **"Design Only / Future Work"**.
   - Noted that **zero pod delete verbs** exist in RBAC, controller code, or manifests. Reversible NetworkPolicy quarantine is the primary automated containment.
5. **Score Formulation Corrected:**
   - ScaleDown Classify-1 natively evaluates Score criteria levels 0 to 4 ($[0.0, 4.0]$).
   - Expected score is mapped via continuous formula $\text{Severity} = \text{Score} + 1.0 \in [1.0, 5.0]$.
6. **Academic Disclosures:**
   - ScaleDown Zero Data Retention (ZDR) policy cited.
   - Mode A AI-assistance disclosure added.

## Directory Structure
- `README.md`: This specification and checklist.
- `poster.html`: Self-contained, responsive, high-resolution (3840x2160 UHD) interactive poster presentation.
- `poster.svg`: Vector diagram of the complete redesigned architecture poster.
- `diagrams/pipeline_flow.mermaid`: End-to-end 7-step pipeline flow in Mermaid.
- `diagrams/decision_policy.mermaid`: Pure deterministic decision policy tree in Mermaid.
