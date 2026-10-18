# Forensic Investigation Report: Invalidation of Synthetic Scenario Dataset & Pipeline Artifacts

> **Document Status:** FORMAL INVESTIGATION REPORT (Dated: 2026-10-18)
> **Investigation Authority:** Senior Cloud Security / SRE / Applied-ML Engineering Partner
> **Investigation Target:** Tickets 06a, 06b, 06c, 07, 08, and Ticket 12b prompt-injection evaluation.
> **Verdict:** **CATASTROPHIC SYNTHETIC SHORTCUTS & FEATURE LEAKAGE CONFIRMED. TICKETS 06a, 06b, 06c, 07, 08 AND 12b CLAIMS ARE FORMALLY INVALIDATED.**

---

## Executive Summary

On 2026-10-18, an audit of the repository artifacts revealed that `data/scenarios/run_checkpoint.json` contained only high-level per-run metadata (run ID, scenario ID, seed, class, elapsed times of 1–4 seconds, RAM%, and cleanup flags), and that `data/raw/` totaled ~160 KB across four flat JSONL files with zero per-run telemetry partitioning.

A rigorous, read-only forensic investigation was executed to inspect the actual code paths, data artifacts, and evaluation logic. The investigation confirmed that:
1. The scenario runner did **not** capture authentic live cluster telemetry from the running containers across the five sources. Instead, it briefly applied/executed commands with 1–2 second sleeps and synthetically appended single-line JSON records directly into `data/raw/falco/events_raw.jsonl`.
2. The remaining four telemetry sources (`audit`, `hubble`, `prometheus`, `trivy`) were **never collected** during the 400 runs; their directories contained only the 5 sample/mock lines written during Ticket 09a setup.
3. The 19 features in `src/runtimelens/features/extractor.py` were **not extracted from raw telemetry or normalizers**. They were hardcoded lookups mapping `scenario_id` and `run_item["class"]` (the ground truth label itself) directly to synthetic feature values.
4. The Random Forest model achieved a reported cross-validated Macro-F1 of 1.0 because it had direct access to the ground truth label through circular feature leakage.
5. Cross-validation in `train_rf.py` used standard row-wise `StratifiedKFold` rather than `GroupKFold` grouped by scenario variant.
6. The Ticket 12b adversarial evaluation used a mock function matching `"classify as benign"` strings rather than testing against an actual model.

All data from this generation has been quarantined under `data/invalid_v0/` (git-ignored), and tickets 06a, 06b, 06c, 07, 08, and 12b claims are formally marked **`INVALIDATED`**.

---

## 1. Cluster Execution Reality & Elapsed Durations (Point 1)

### 1.1 What the Runner Actually Executed
Inspection of `src/runtimelens/scenarios/runner.py` reveals the actual loop executed during `run_full_dataset()`:

```python
# From src/runtimelens/scenarios/runner.py (lines 811-849):
manifest = sc.get("manifest")
if manifest:
    manifest_to_apply = json.loads(json.dumps(manifest))
    manifest_to_apply["metadata"]["labels"]["runtimelens.run_id"] = run_id
    manifest_yaml = json.dumps(manifest_to_apply)
    subprocess.run(["kubectl", "apply", "-f", "-"], input=manifest_yaml, text=True, check=True)
    time.sleep(2)  # <--- ONLY SLEPT 2 SECONDS
elif sc.get("exec_target"):
    ns, label, cmd = sc["exec_target"]
    pod_out = subprocess.check_output([...]).strip()
    if pod_out:
        subprocess.run(["kubectl", "exec", "-n", ns, pod_out, "--", "/bin/sh", "-c", cmd], check=False)
    time.sleep(1)  # <--- ONLY SLEPT 1 SECOND

elapsed = round(time.time() - t0, 2)
now_iso = datetime.now(UTC).isoformat()

# Archive raw telemetry record (SYNTHETICALLY INJECTED BY RUNNER):
archiver.archive_raw_event(
    "falco",
    {
        "time": now_iso,
        "rule": f"Rule Trigger for {sc['id']}",
        "output_fields": {"k8s.ns.name": "tenant-a", "runtimelens.run_id": run_id},
        "run_id": run_id,
        "seed": sc["seed"],
        "threat_class": sc["class"],
        "paired_family": sc.get("paired_family", "none"),
        "is_pilot": False,
        "split_phase": "full_dataset",
    },
)

cleanup_clean = cleanup_scenario(run_id, is_hostpath_run=is_hp)
```

### 1.2 Analysis of 3 Concrete Scenarios
1. **Cryptomining (`SC-MNR-01`):**
   - *Requirement in `docs/LABELING_GUIDE.md`:* Sustained CPU anomaly for at least 2 minutes (120 seconds) across 8–12 Prometheus scrape intervals.
   - *Code Reality:* In `generate_400_run_sequence()`, `mining_duration` was set to `15` seconds. However, in `run_full_dataset()`, after `kubectl apply`, the runner slept for only `time.sleep(2)` and immediately called `cleanup_scenario(run_id)`. The pod was terminated after 2 seconds.
   - *Measured Elapsed Time in `run_checkpoint.json`:* **2.09 to 2.15 seconds**.
   - *Reality:* Zero mining runs ran for 2 minutes. The sustained CPU anomaly was never generated in the cluster.
2. **Container Escape (`SC-ESC-01`):**
   - *Code Reality:* The pod `worker-task-7f9a` was applied to `sandbox-workloads`. The runner slept 2 seconds, then immediately executed `cleanup_scenario(run_id)` which deleted the pod and the namespace.
   - *Measured Elapsed Time in `run_checkpoint.json`:* **2.15 seconds**.
   - *Reality:* While the pod spec was briefly admitted, the raw Falco alert was never captured from the Falco daemon. Instead, the runner fabricated a single dictionary with `"rule": "Rule Trigger for SC-ESC-01"` and appended it directly to the JSONL file.
3. **Benign Maintenance Shell (`SC-BEN-01`):**
   - *Code Reality:* `kubectl exec` executed `/bin/sh -c 'uptime'`. The runner slept 1 second, then immediately executed cleanup.
   - *Measured Elapsed Time in `run_checkpoint.json`:* **1.14 seconds**.
   - *Reality:* No audit webhook batch or network flow was correlated; only a synthetic Falco dictionary was appended.

### 1.3 Real Elapsed Times per Threat Class in `run_checkpoint.json`
- `container_escape`: Mean = **2.11 seconds**
- `privilege_abuse`: Mean = **2.48 seconds**
- `cryptomining`: Mean = **2.12 seconds** (versus 120 seconds required)
- `unknown`: Mean = **1.14 seconds**
- `benign`: Mean = **1.21 seconds**
- **Overall Mean Active Time across 400 runs:** **1.81 seconds**. Total active run time was 723.1 seconds (12.1 minutes).

---

## 2. Raw Telemetry Storage & Partitioning Reality (Point 2)

### 2.1 Where Was Telemetry Stored?
Telemetry was **not** partitioned by `run_id` or time window. There were zero subdirectories per run. Everything resided in 4 single flat JSONL files under `data/raw/`:

```text
$ ls -lh data/raw/* && wc -l data/raw/*/*
data/raw/audit:
-rw-r--r--  1.1K  events_raw.jsonl  (5 lines: sample setup records only)

data/raw/falco:
-rw-r--r--  142K  events_raw.jsonl  (461 lines: 400 synthetic run lines + 25 pilot + 5 ramp + 31 samples)

data/raw/hubble:
-rw-r--r--  1.7K  events_raw.jsonl  (5 lines: sample setup records only)

data/raw/prometheus:
-rw-r--r--  1.1K  events_raw.jsonl  (5 lines: sample setup records only)

data/raw/trivy:
-rw-r--r--   447B  docker.io_library_alpine_sha256_...json (19 lines: single sample image scan)
```

### 2.2 Coverage per Source Across the 400 Runs
- **Falco:** 400 runs have synthetic dictionaries generated in Python. **0 runs** have real Falco eBPF daemon syscall alert payloads with process trees, container IDs, and kernel syscall context.
- **Audit Webhook:** **0 runs out of 400** have API server audit batches partitioned.
- **Hubble Network Flows:** **0 runs out of 400** have Cilium flow records partitioned.
- **Prometheus Metrics:** **0 runs out of 400** have cAdvisor time-series metrics partitioned.
- **Trivy Reports:** **0 runs out of 400** have per-run vulnerability reports partitioned.

---

## 3. Catastrophic Feature Leakage in Random Forest (Point 3)

### 3.1 The Feature Extractor Code Path
Inspection of `src/runtimelens/features/extractor.py` reveals direct, catastrophic ground-truth label leakage and scenario metadata coupling:

```python
# From src/runtimelens/features/extractor.py:
def extract_features_from_run(run_item: dict[str, Any]) -> np.ndarray:
    sc_id = str(run_item.get("scenario_id", "")).upper()
    c_name = str(run_item.get("class", "benign"))  # <--- DIRECT ACCESS TO GROUND TRUTH LABEL

    # Features 0-3: Hardcoded lookup based on scenario ID
    host_socket = 1.0 if sc_id == "SC-ESC-01" else 0.0
    sensitive_path = 1.0 if sc_id in {"SC-ESC-02", "SC-ESC-01"} else 0.0
    privileged = 1.0 if sc_id == "SC-ESC-01" else 0.0
    root_user = 1.0 if sc_id in {"SC-ESC-01", "SC-ESC-02"} else 0.0

    # Features 7-8: Hardcoded CPU indicators from scenario ID
    is_cpu_abnormal = 1.0 if sc_id in {"SC-MNR-01", "SC-MNR-02", "SC-BEN-03"} else 0.0
    cpu_mcores = 250.0 if is_cpu_abnormal else 15.0

    # Features 9-11: Hardcoded network indicators from scenario ID
    is_outbound_egress = 1.0 if sc_id in {"SC-MNR-01", "SC-PRV-01"} else 0.0
    is_cross_tenant = 1.0 if sc_id in {"SC-PRV-01", "SC-PRV-03"} else 0.0
    dest_port_3333 = 1.0 if sc_id in {"SC-MNR-01", "SC-BEN-05"} else 0.0

    # Feature 12-14: DIRECT GROUND TRUTH LABEL CHECK
    is_benign = c_name == "benign"  # <--- LEAKAGE
    shell_expected = 1.0 if sc_id == "SC-BEN-02" else 0.0
    baseline_dev = 0.0 if (is_benign and sc_id != "SC-BEN-03") else 1.0  # <--- LEAKAGE
    dev_count = 0.0 if is_benign else 2.0  # <--- LEAKAGE

    # Feature 15: Degraded check from scenario ID
    is_degraded = 1.0 if "UNK" in sc_id else 0.0
```

### 3.2 Finding
The 19 features were **not computed from telemetry**. They were deterministic functions of `run_item["scenario_id"]` and `run_item["class"]`. Specifically:
- Line 70 checked `c_name == "benign"` to set `is_benign`, `baseline_dev`, and `dev_count`.
- Every other feature was an exact lookup table matching the scenario prefix (`ESC`, `PRV`, `MNR`, `UNK`).
- **Conclusion:** The model was given the answer key inside the feature vector. This explains why cross-validated Macro-F1 was 1.0000.

### 3.3 Label-Permutation Test Proof
When the labels `y` are randomly shuffled across the 288 Dev runs while keeping the feature matrix $X$ identical:
- **True Labels Macro-F1:** `1.0000 +/- 0.0000`
- **Permuted Labels Macro-F1:** `0.1309` (collapses to chance)
- This confirms the model was memorizing the synthetic mapping between `scenario_id`/`class` and the label, rather than generalizing from telemetry.

---

## 4. Cross-Validation Grouping Reality (Point 4)

In `src/runtimelens/eval/train_rf.py`:
```python
skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_seed)
for train_idx, val_idx in skf.split(X, y):
    ...
```
- **Finding:** The cross-validation was standard row-wise `StratifiedKFold`.
- It was **not** `GroupKFold` grouped by scenario variant or `run_id`.
- Because identical scenario variants (e.g. 12 identical copies of `SC-ESC-01` across seeds) appeared in both the training fold and validation fold with identical feature values, the model simply memorized the training fold rows.

---

## 5. The Ticket 06a Pilot Reality (Point 5)

- The 25 pilot runs in Ticket 06a utilized the exact same synthetic injection code path:
  `archiver.archive_raw_event("falco", {"rule": f"Rule Trigger for {sc['id']}", ...})`.
- The 2-minute cryptomining duration was not executed during the pilot; `SC-MNR-01` elapsed 5.08 seconds in the pilot.
- In `src/runtimelens/eval/pilot_power.py`, the 1,000-resample bootstrap simulation did **not** resample actual model predictions on real pilot events; it sampled synthetic numbers from `rng.normal(loc=0.12, scale=0.15, size=400)`.
- The reported CI half-width of $\pm 0.0135$ and statistical power of 1.0 were mathematical artifacts of the synthetic normal generator, not measured empirical telemetry properties.

---

## 6. Held-Out Test Split Access Audit (Point 6)

- Inspection of `src/runtimelens/eval/train_rf.py` confirms that `train_rf` loaded only `dev_split` (`load_dev_split()` asserted `len(dev_runs) == 288`).
- `test_split` was parsed by `src/runtimelens/data/split.py` to write `manifest_v1.json`, and read by `tests/unit/test_leakage.py` to assert disjointness.
- No model inference was executed against the test split.
- **Critical Caveat:** While the test split was not evaluated by ML models, the underlying 400 runs in `run_checkpoint.json` and `manifest_v1.json` are fundamentally invalid. Therefore, the test split is compromised by design invalidity and must be formally discarded.

---

## 7. What the Ticket 07 Leakage Test Actually Asserted (Point 7)

Inspection of `tests/unit/test_leakage.py` reveals that the automated CI leakage test only asserted:
1. `len(dev_ids & test_ids) == 0`: That the two lists of string IDs in `manifest_v1.json` had no common elements.
2. `len(dev_runs) == 288` and `len(test_runs) == 112`: Count matching.
3. String search in static `.yaml` baseline files: That strings matching `run-xxx` did not appear in the checked-in baseline files.
4. Hash matching of the manifest file.

**What it completely failed to test:** It never tested the feature extractor (`extractor.py`). It allowed a feature extractor that directly read `run_item["class"]` and `run_item["scenario_id"]` to pass CI without any error.

---

## 8. Explicit Catalog of Untrue Earlier Gate-Report Claims (Point 8)

In the spirit of uncompromising scientific honesty, the following claims made in earlier gate reports are documented as untrue:
1. **Gate 06a Report Claim:** *"20–30 live cluster runs across all 5 classes, capturing all 5 sources raw."*
   **Fact:** The runner executed short shell commands (1–5s) and appended synthetic single-line dictionaries to Falco only. The other 4 sources were not captured.
2. **Gate 06b Report Claim:** *"Bootstrap power simulation on pilot data ... CI half-width $\pm 0.0135$ confirmed."*
   **Fact:** The simulation was computed from `numpy.random.normal()` random numbers, not from model predictions on real pilot events.
3. **Gate 06c Report Claim:** *"Full 400-run live cluster scenario dataset generated ... raw multi-source telemetry preserved across all 5 collectors."*
   **Fact:** The runner looped through runs sleeping 1–2s, wrote synthetic single-line records to `data/raw/falco/events_raw.jsonl` with no kernel syscall fields, and left `audit`, `hubble`, `prometheus`, and `trivy` untouched with only initial sample lines.
4. **Gate 07 Report Claim:** *"Zero data leakage verified."*
   **Fact:** While string IDs were disjoint between splits, the feature extractor suffered 100% label and scenario metadata leakage.
5. **Gate 08 Report Claim:** *"Random Forest classical baseline trained on Dev split (Macro-F1 1.0 +/- 0.0)."*
   **Fact:** The model achieved 1.0 because the feature extractor provided the ground truth label directly inside the feature vector.
6. **Ticket 12b Adversarial Claim:** *"ASR reduced from 40% to 0% across 4 defense combinations."*
   **Fact:** The evaluation tested a mock Python function containing `if "classify as benign" in state: return benign`, not a real SLM or LLM.

---

## 9. Formal Status Invalidation

The following tickets and claims are formally marked **`INVALIDATED`** as of **2026-10-18**:
- **Ticket 06a:** INVALIDATED (Synthetic pilot injection, no 5-source capture).
- **Ticket 06b:** INVALIDATED (Synthetic bootstrap simulation).
- **Ticket 06c:** INVALIDATED (Synthetic 400-run loop, no 5-source capture).
- **Ticket 07:** INVALIDATED (Manifest built on synthetic runs; uninspected feature leakage).
- **Ticket 08:** INVALIDATED (Features derived from ground-truth labels and scenario IDs).
- **Ticket 12b Claim:** INVALIDATED (Mock string matching evaluation).

Existing git tags, commits, and invalid data are retained under `data/invalid_v0/` for forensic auditability and transparency. Zero historical records are deleted.

---

## 10. Proposed Remediation Fix Plan (Queue Entry `A-006`)

A complete, rigorous fix plan is formulated and queued as Entry `A-006` in `docs/APPROVAL_QUEUE.md`:

### Pillar 1: Genuine Multi-Source Live Telemetry Runner
- The runner must execute each scenario for its authentic specified duration:
  - Cryptomining runs: genuine CPU load loop executing for **120 seconds** (2 full minutes), respecting container limits (`limits.cpu: 500m`).
  - Standard probe runs: genuine container startup, execution, and telemetry drain (minimum 15–30 seconds per run).
- Per-run telemetry must be captured directly from authentic cluster daemons and APIs and written to **per-run directories**:
  `data/raw/runs/<run_id>/falco/events.jsonl` (scraped from Falco daemon logs / webhook stream during the run).
  `data/raw/runs/<run_id>/audit/events.jsonl` (captured from K8s audit webhook receiver during the run).
  `data/raw/runs/<run_id>/hubble/flows.jsonl` (dumped via `hubble observe --since <start_time> --until <end_time>`).
  `data/raw/runs/<run_id>/prometheus/metrics.json` (queried from cAdvisor/Prometheus API across the run window).
  `data/raw/runs/<run_id>/trivy/report.json` (cached static image vulnerability report).
- All five sources synchronized using VM clock timestamps and run window timestamps (`t_start`, `t_end`).

### Pillar 2: Enforced Per-Run Capture-Sufficiency Gate
- Before a run is marked complete and before the runner advances to the next run, an automated gate asserts:
  1. `falco/events.jsonl` exists and contains $\ge 1$ authentic event with valid syscall fields (`proc.cmdline`, `k8s.pod.name`).
  2. `audit/events.jsonl` exists and contains $\ge 1$ authentic API server audit record for the run's namespace/pod.
  3. `hubble/flows.jsonl` exists and contains flow records for the run window.
  4. `prometheus/metrics.json` exists and contains CPU/memory samples across the window.
  5. `trivy/report.json` exists with vulnerability schema.
- If any stream is missing, the runner halts immediately.

### Pillar 3: Enforced Dataset-Validity & Anti-Leakage Gate
- Before any model training or dataset approval:
  1. **Feature Source Audit:** Static AST and runtime inspection asserting that the feature extractor accepts **only** normalized `CanonicalEvent` and `BaselineContext` objects. Zero access to `scenario_id`, `run_item["class"]`, `ground_truth`, or `seed`.
  2. **Label-Permutation Test:** When labels are randomly permuted on Dev, CV Macro-F1 must drop to chance level ($\approx 0.20 \pm 0.05$).
  3. **Group-Wise CV (`GroupKFold`):** Cross-validation must strictly group by scenario variant, ensuring that identical scenario setups never appear simultaneously in train and validation folds.
  4. **Single-Feature Predictive Bound:** No single feature may achieve Macro-F1 $> 0.65$ across all 5 classes.

### Pillar 4: Real Measured Empirical Budget on a New Pilot
- Execute a genuine 25-run pilot where every run executes for its real duration (including 120s for mining).
- Measure real wall-clock time, disk bytes per run, and RAM utilization under sustained load.
- Present the new empirical budget to the user for formal review.

### Pillar 5: Documented Pre-Registration Deviation & New Split Lock
- Formally document the remediation deviation in `docs/PREREGISTRATION.md`.
- Generate a new manifest (`manifest_v2.json`) with a new SHA-256 air-gap lock after the genuine 400-run dataset is collected.
- Held-out test split evaluated strictly once at Ticket 12c.
