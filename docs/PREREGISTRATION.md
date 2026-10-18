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
3. **Partitioning:** Grouped strictly by `run_id` and scenario variant:
   - **Dev Split:** 72% (~288 runs), used for training classical ML, prompt tuning, and threshold calibration.
   - **Held-Out Test Split:** 28% (~112 runs), frozen with a tamper-evident SHA-256 hash in `datasets/splits/manifest_v1.json`.
4. **Equal Tuning Budget:** All three classifiers receive the exact same dev-set exposure and compute budget.
5. **Air-Gap Rule:** The test split is evaluated exactly ONCE per final model configuration. All access is logged to `data/audit/test_eval_access.log`.

## 5. Outcome Criteria
- **Positive:** 95% paired bootstrap CI for $\Delta\text{Macro-F1}$ strictly excludes zero in the positive direction and exceeds the post-pilot calibrated effect size.
- **Inconclusive:** 95% paired bootstrap CI spans zero.
- **Negative:** Point estimate $\Delta\text{Macro-F1} \le 0$ or benign FPR increases.
- **Exploratory:** If power analysis on pilot indicates insufficient power, results are formally reported as exploratory findings with transparent disclosure of CI bounds.
*All outcomes are pre-committed to be published transparently in the final course report and poster.*
