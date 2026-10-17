# REPORT & POSTER REVISION CHECKLIST

## 1. Overview & Team Ownership
- **Lead Authors / Editors:** Altaf Raja (23BCS011) & Kamal Nayan Kumar (23BDS026)
- **Technical Sign-Off:** Himanshu Kumar (23BCS055)
- **Document Versioning:** The original submitted report is frozen in `docs/source/`. All edits are tracked in `docs/report/` to produce Version 2.0.

---

## 2. Stage 1: Structural & Factual Corrections (Immediate)

| # | Document & Section | Original Content / Defect | Revised Requirement | Assigned | Status | Sign-off |
|:---|:---|:---|:---|:---:|:---:|:---:|
| **1.1** | Report Title Page & Headers | "Intelligent Security for Containers: ML-Based Runtime and Orchestration Threat Classification Using the Jev Model" | Update title to: **"RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model"** | Altaf | TODO | [ ] |
| **1.2** | Report Abstract & Section 3 | "Jev, a System One decision model released by TypeSafe AI..." | Replace with: **"ScaleDown Classify-1, evaluated via a Jev-compatible Decisions API"**. State that API access is secured and functional. | Kamal | TODO | [ ] |
| **1.3** | Report Section 3.1 & 3.2 | Unverified vendor claims of Jev (e.g. 70 to 500 ms latency, RLCD training claims). | Explicitly label as: "Vendor-reported specifications for TypeSafe Jev; empirical latency, calibration, and determinism for ScaleDown Classify-1 are independently measured in this study." | Kamal | TODO | [ ] |
| **1.4** | Report Abstract, Table 2 & Table 6 | "Terminate the pod and alert" listed as a direct automated response tier. | Reframe termination as: **"Not implemented; design and future work only. Zero pod delete permissions exist in RBAC, controller code, or manifests."** Reversible NetworkPolicy quarantine is elevated as primary containment. | Altaf | TODO | [ ] |
| **1.5** | Report Section 6.4 & Figures | Worked example lists probabilities (0.91, 0.88, 4.7 score) without qualification. | Add explicit callout banner: **"ILLUSTRATIVE WORKED EXAMPLE (Not Measured Empirical Data)"**. | Kamal | TODO | [ ] |
| **1.6** | Report Section 5.1 & Poster | Mismatched tenant workload labels across figures and text. | Harmonize across all sections: three namespaces (`tenant-a`, `tenant-b`, `tenant-c`) each running `web`, `api`, `database`, and `payment-style` workloads. | Altaf | TODO | [ ] |
| **1.7** | Report Section 12 (References) | Missing ScaleDown citations and privacy posture. | Add official references: ScaleDown AI documentation (`https://docs.scaledown.ai`), Decisions API specification (`https://docs.scaledown.ai/api-reference/decisions.md`), and document Zero Data Retention (ZDR) policy. | Kamal | TODO | [ ] |
| **1.8** | Report Front Matter | Missing disclosure. | Add standardized AI-Assistance disclosure line: *"In accordance with academic integrity guidelines, generative AI tools (Antigravity) were utilized under Mode A pair programming: the AI assistant authored implementation code, test suites, configurations, and automation scripts under direct human direction, review, and specification. All phase gate verification tests were executed, inspected, and approved directly by the authors, who conducted all laboratory cluster experiments and retain full scientific and operational governance."* | Altaf | TODO | [ ] |
| **1.9** | Architecture Poster (Image) | Poster displays Jev branding, direct pod termination, and pending API status. | Update poster graphics: replace Jev with ScaleDown Classify-1 branding, add "Design Only / Future Work" badge to Terminate box, and harmonize tenant names. | Altaf | TODO | [ ] |

---

## 3. Stage 2: Empirical Results & Findings (Post-Phase 11)

| # | Document & Section | Description of Required Empirical Data | Dependencies | Assigned | Status | Sign-off |
|:---|:---|:---|:---:|:---:|:---:|:---:|
| **2.1** | Report Abstract & Section 8 | Insert measured Macro-F1, per-class F1, and benign False Positive Rates with 95% cluster-aware bootstrap CIs. | Phase 8 Evaluation | Kamal | BLOCKED | [ ] |
| **2.2** | Report Section 8.2 | Insert empirical Confusion Matrices comparing Rules (Falco defaults), Random Forest, and ScaleDown Classify-1 under equal tuning budgets. | Phase 8 Evaluation | Kamal | BLOCKED | [ ] |
| **2.3** | Report Section 8.3 | Populate the 6 systematic ablation tables (Baseline ON vs OFF, Pre-filter ON vs OFF, Question combinations). | Phase 8 Evaluation | Altaf | BLOCKED | [ ] |
| **2.4** | Report Section 8.4 | Insert calibration reliability curves, binned ECE values, and Brier scores across models (computed offline). | Phase 8 Evaluation | Kamal | BLOCKED | [ ] |
| **2.5** | Report Section 8.5 | Insert end-to-end vs model latency percentiles (p50, p95, p99) and cost per 1,000 events. | Phase 8 Evaluation | Altaf | BLOCKED | [ ] |
| **2.6** | Report Section 9 & 11 | Update Limitations and Conclusion with honest discussion of primary findings (positive, inconclusive, or negative). | Phase 11 Wrap-up | Both | BLOCKED | [ ] |
