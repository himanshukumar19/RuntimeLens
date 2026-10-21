# STUDY PRE-REGISTRATION: RuntimeLens

**Registration Date:** 2026-10-17
**Status:** COMMITTED & LOCKED PRIOR TO TEST-SET ACCESS
**Study Title:** RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model
**Principal Investigator:** Himanshu Kumar (23BCS055)
**Co-Investigators:** Altaf Raja (23BCS011), Kamal Nayan Kumar (23BDS026)
**Faculty Guide:** Malay Kumar

---

## 1. Research Question & Primary Hypothesis
- **Core Research Question:** Does providing per-workload behavioural baseline context to a constrained typed-decision model improve detection accuracy and reduce false positives for runtime and orchestration threats in multi-tenant Kubernetes?
- **Primary Hypothesis ($H_1$ - Paired Evaluation):** Evaluating container runtime incidents with workload baseline context yields a statistically significant improvement in Macro-averaged F1 score ($\Delta\text{Macro-F1} = \text{Macro-F1}_{\text{baseline}} - \text{Macro-F1}_{\text{no-baseline}} > 0$) and/or benign False Positive Rate ($\Delta\text{FPR} < 0$) compared to the identical classifier evaluated on the exact same runs without baseline context.
- **Minimum Meaningful Effect Size Protocol:**
  - The minimum meaningful effect size (preliminarily targeted at a meaningful positive shift in Macro-F1 or a $\ge 50\%$ benign FPR reduction) is **to be set after a real pilot** (calibrated after analyzing empirical variance on the real 20–30 run pilot dataset under Remediation Plan A-006).
  - **Exploratory Designation:** If simulation on the real pilot dataset indicates that statistical power is insufficient ($< 0.80$) to detect the calibrated effect size within the 400-run budget, the primary research claim is **pre-committed to be marked as exploratory**, with full reporting of confidence intervals and sample size limitations.

## 2. Metric Hierarchy

### 2.1 Primary Metric
- **Macro-Averaged F1 Score ($\text{Macro-F1}$):**
  $$\text{Macro-F1} = \frac{1}{|C|} \sum_{c \in C} F1_c$$
  where $C = \{\text{benign}, \text{container\_escape}, \text{privilege\_abuse}, \text{cryptomining}, \text{unknown}\}$.
  *Rationale:* Macro-averaging treats each threat class with equal weight, preventing the dominant benign class from inflating overall system accuracy.

### 2.2 Secondary Metrics
1. **Benign False Positive Rate (FPR):** $\frac{\text{FP}_{\text{benign}}}{\text{FP}_{\text{benign}} + \text{TN}_{\text{benign}}}$.
2. **Expected Calibration Error (ECE):** 10-bin binned probability error computed offline.
3. **Detection Latency:** p50 and p95 end-to-end decision latency (milliseconds).
4. **Cost per 1,000 Events:** Token and compute expenditure in USD.

## 3. Planned Comparisons & Statistical Tests

| Comparison | Model A | Model B | Primary Statistical Test | Multiple Testing Correction |
|:---|:---|:---|:---|:---|
| **Primary ($H_1$)** | ScaleDown Classify-1 (with Baseline Context) | ScaleDown Classify-1 (without Baseline Context) | Cluster-aware paired 95% Bootstrap CI of $\Delta\text{Macro-F1}$ (resampled by `run_id`, 1,000 iterations) + Paired McNemar test | None (pre-registered primary paired comparison) |
| **Secondary 1** | ScaleDown Classify-1 (with Baseline) | Scikit-Learn Random Forest Baseline | Incident-level McNemar test on paired held-out predictions | Holm-Bonferroni |
| **Secondary 2** | ScaleDown Classify-1 (with Baseline) | Default Falco Rule-Based Engine | Incident-level McNemar test on paired held-out predictions | Holm-Bonferroni |

## 4. Dataset Partitioning, Pilot & Air-Gap Enforcement
1. **Pilot Study & Calibration Protocol (Remediation A-006):** A genuine live pilot of **20–30 runs** will be executed across all classes and paired counterfactuals with genuine duration execution (including 120s sustained CPU for mining) and verified live multi-source capture before running the full dataset.
   - **Empirical 400-Run Budget:** To be set after a real pilot.
   - **Bootstrap Power & CI Width Simulation:** To be set after a real pilot.
   - **Calibrated Effect Size:** To be set after a real pilot.
   - **Design Freeze:** Frozen only after human review and approval of the real pilot empirical budget.
2. **Total Sample Size:** **400 independent live cluster runs** (yielding 400 incidents, 1 per run). Raw data from all 5 sources (Falco, audit, Hubble, Prometheus, Trivy) is archived from run 1.
3. **Partitioning:** Grouped strictly by **template** (every run of a given `TMPL-*` stays on one side of the split) and by run within that template:
   - **Dev Split:** **proposed** 72.25% (**289 runs**), used for training classical ML, prompt tuning, and threshold calibration. *(Working draft — not frozen. Source: `docs/SCENARIO_PLAN_v2.md` §1.)*
   - **Held-Out Test Split:** **proposed** 27.75% (**111 runs**), to be frozen with a tamper-evident SHA-256 hash in `datasets/splits/manifest_v2.json`. *(Working draft — not frozen. `manifest_v1.json` is the manifest of the **invalidated** synthetic dataset and must not be reused.)*
4. **Equal Tuning Budget:** All three classifiers receive the exact same dev-set exposure and compute budget.
5. **Air-Gap Rule:** The test split is evaluated exactly ONCE per final model configuration. All access is logged to `data/audit/test_eval_access.log`.

## 5. Outcome Criteria
- **Positive:** 95% paired bootstrap CI for $\Delta\text{Macro-F1}$ strictly excludes zero in the positive direction and exceeds the post-pilot calibrated effect size.
- **Inconclusive:** 95% paired bootstrap CI spans zero.
- **Negative:** Point estimate $\Delta\text{Macro-F1} \le 0$ or benign FPR increases.
- **Exploratory:** If power analysis on pilot indicates insufficient power, results are formally reported as exploratory findings with transparent disclosure of CI bounds.
*All outcomes are pre-committed to be published transparently in the final course report and poster.*

---

## 6. Pre-Registration Deviation Draft (Stage 3 Draft — NOT FROZEN)

- **Deviation Context:** Following Decision D-20 (invalidation of synthetic log shortcuts) and the Stage 2/3 real multi-source 25-run pilot, the original scenario manifest and split (`manifest_v1.json`) are formally superseded.
- **Proposed Manifest Architecture (`manifest_v2.json`):**
  - Will govern 400 genuine live multi-source runs across 5 threat classes (**proposed** 140 benign / 80 container_escape / 80 privilege_abuse / 60 cryptomining / 40 unknown) over **55 templates**, with per-run directory isolation (`data/raw/runs/<run_id>/<source>/`).
  - Incorporates paired look-alike confounders (benign shells, legitimate high-port services, authorized secret reads, and batch CPU load) to prevent trivial feature shortcuts. **Decision D-28:** the `command_length` feature is *excluded from the classifier feature set* (18 features, not 19) and retained only as a diagnostic, because the template registry proves that command length is a near-perfect class marker for this dataset (every `privilege_abuse` template is necessarily in the longest length bin). See `docs/SCENARIO_PLAN_v2.md` §3.6.3 and `docs/REPORT_DELTA.md` §6.
  - Implements varied attack vectors (throttled mining, diverse path traversals, multi-port exfiltration, cross-tenant API requests).
  - The `exfiltration` class is **not** part of the corpus (Decision D-24). The 5 historical exfiltration pilot runs are retained for audit traceability, marked `pilot only, class dropped`, and are excluded from every class-level statistic.
- **Proposed Split Architecture (`manifest_v2_split.json`):**
  - Grouped 72/28 split (**proposed** 289 Dev, 111 Test) grouped strictly by **template** and by run within that template, so no template's command text or Falco signature appears on both sides.
  - Frozen with a new SHA-256 air-gap lock after human scenario review.
- **Strict Single-Access Test Protocol:**
  - The held-out test split (**proposed** 111 runs) remains air-gapped and will be evaluated strictly ONCE at Ticket `12c`.
  - All dev tuning (Random Forest, prompt templates, policy thresholds) operates exclusively on the **proposed** 289 Dev runs.
- **Governance Note:** This deviation is currently a **working draft**. It will not be frozen or locked until Stage 4 scenario review and formal user authorization.
