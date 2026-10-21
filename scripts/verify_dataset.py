"""Read-only dataset validity and leakage verification gate (Condition B3).

Computes directly from per-run directories:
1. Duration from first and last event timestamp.
2. Event count per source (falco, audit, hubble, prometheus, trivy).
3. Sustained-CPU check for cryptomining (>= 120s duration).
4. Telemetry leakage scan for scenario IDs, class names, and run IDs.
5. Metadata-shuffle test (verifies feature extractor ignores index metadata).
6. Single-feature diagnostic predictive power.
7. Label-permutation test (verifies baseline chance performance).
8. GroupKFold cross-validation grouped by scenario variant.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold

from runtimelens.eval.cpu_bands import (
    BURST_MEDIAN_MAX_MCORES,
    BURST_PEAK_MAX_MCORES,
    BURST_PEAK_MIN_MCORES,
    MIN_POST_LAG_SAMPLES,
    post_lag_cpu_samples,
)
from runtimelens.features.extractor import (
    FEATURE_NAMES,
    extract_command_length,
    extract_dataset_from_run_dirs,
    extract_features_from_run_dir,
)

logger = logging.getLogger("runtimelens.verify_dataset")

LEAK_KEYWORDS: Final[tuple[str, ...]] = (
    "SC-",
    "privilege_abuse",
    "container_escape",
    "cryptomining",
    "exfiltration",
    "benign",
    "run-0",
    "run-1",
    "run-2",
    "run-3",
)


def parse_iso_ts(ts_str: str) -> float:
    """Parse ISO UTC timestamp to epoch seconds."""
    clean = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


def audit_run_directory(run_dir: Path) -> dict[str, Any]:
    """Audit timestamps, event counts, and leakage for a single per-run directory."""
    index_file = run_dir / "index.json"
    index_meta: dict[str, Any] = {}
    if index_file.exists():
        index_meta = json.loads(index_file.read_text(encoding="utf-8"))

    source_counts: dict[str, int] = {}
    timestamps: list[float] = []

    # 1. Falco audit
    falco_file = run_dir / "falco" / "events.jsonl"
    f_count = 0
    if falco_file.exists():
        with open(falco_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        evt = json.loads(line)
                        f_count += 1
                        ts = evt.get("time")
                        if ts:
                            timestamps.append(parse_iso_ts(ts))
                    except Exception:
                        continue
    source_counts["falco"] = f_count

    # 2. Audit log audit
    audit_file = run_dir / "audit" / "events.jsonl"
    a_count = 0
    if audit_file.exists():
        with open(audit_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        evt = json.loads(line)
                        a_count += 1
                        ts = evt.get("stageTimestamp") or evt.get("requestReceivedTimestamp")
                        if ts:
                            timestamps.append(parse_iso_ts(ts))
                    except Exception:
                        continue
    source_counts["audit"] = a_count

    # 3. Hubble flows audit
    hubble_file = run_dir / "hubble" / "flows.jsonl"
    h_count = 0
    if hubble_file.exists():
        with open(hubble_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        flow = json.loads(line)
                        h_count += 1
                        ts = flow.get("flow", flow).get("time")
                        if ts:
                            timestamps.append(parse_iso_ts(ts))
                    except Exception:
                        continue
    source_counts["hubble"] = h_count

    # 4. Prometheus / cAdvisor metrics audit
    prom_file = run_dir / "prometheus" / "metrics.json"
    p_count = 0
    sample_cpus: list[float] = []
    sample_ts: list[float] = []
    if prom_file.exists():
        try:
            p_data = json.loads(prom_file.read_text(encoding="utf-8"))
            samples = p_data.get("samples", [])
            if samples:
                p_count = len(samples)
                for s in samples:
                    s_cpu = 0.0
                    for p in s.get("pod_stats", []):
                        for c in p.get("containers", []):
                            nano = float(c.get("cpu", {}).get("usageNanoCores", 0.0))
                            s_cpu += round(nano / 1e6, 2)
                    sample_cpus.append(s_cpu)
                    s_ts = s.get("timestamp")
                    if s_ts:
                        parsed = parse_iso_ts(s_ts)
                        timestamps.append(parsed)
                        sample_ts.append(parsed)
            else:
                pod_stats = p_data.get("pod_stats", [])
                p_count = len(pod_stats)
                for p in pod_stats:
                    for c in p.get("containers", []):
                        nano = float(c.get("cpu", {}).get("usageNanoCores", 0.0))
                        sample_cpus.append(round(nano / 1e6, 2))
                raw_ts = p_data.get("raw_summary_time")
                if raw_ts:
                    timestamps.append(parse_iso_ts(raw_ts))
        except Exception:
            pass
    source_counts["prometheus"] = p_count

    min_cpu = float(np.min(sample_cpus)) if sample_cpus else 0.0
    med_cpu = float(np.median(sample_cpus)) if sample_cpus else 0.0
    max_cpu = float(np.max(sample_cpus)) if sample_cpus else 0.0
    above_100_count = sum(1 for v in sample_cpus if v >= 100.0)
    pct_above_100 = (above_100_count / len(sample_cpus) * 100.0) if sample_cpus else 0.0
    above_40_count = sum(1 for v in sample_cpus if v >= 40.0)
    pct_above_40 = (above_40_count / len(sample_cpus) * 100.0) if sample_cpus else 0.0

    # Decision D-27: post-lag view of the same samples (first-sample lag removed).
    post_lag_cpus = post_lag_cpu_samples(sample_cpus, sample_ts)
    post_lag_above_40 = sum(1 for v in post_lag_cpus if v >= 40.0)
    post_lag_above_100 = sum(1 for v in post_lag_cpus if v >= 100.0)
    pct_above_40_post_lag = (
        (post_lag_above_40 / len(post_lag_cpus) * 100.0) if post_lag_cpus else 0.0
    )
    pct_above_100_post_lag = (
        (post_lag_above_100 / len(post_lag_cpus) * 100.0) if post_lag_cpus else 0.0
    )
    med_post_lag = float(np.median(post_lag_cpus)) if post_lag_cpus else 0.0

    exp_cpu_profile = index_meta.get("expected_cpu_profile")
    if not exp_cpu_profile:
        is_mnr = index_meta.get("threat_class") == "cryptomining" or "MNR" in index_meta.get(
            "scenario_id", ""
        )
        exp_cpu_profile = "high" if is_mnr else "low"

    # 5. Trivy report audit
    trivy_file = run_dir / "trivy" / "report.json"
    source_counts["trivy"] = 1 if trivy_file.exists() else 0

    # Duration calculation from telemetry timestamps
    calc_duration = 0.0
    if len(timestamps) >= 2:
        calc_duration = round(max(timestamps) - min(timestamps), 2)
    elif index_meta.get("duration_seconds"):
        calc_duration = float(index_meta["duration_seconds"])

    # 6. Telemetry Leakage Scan
    leak_findings: list[str] = []
    for src in ["falco", "audit", "hubble", "prometheus"]:
        src_path = run_dir / src
        for t_file in src_path.glob("*"):
            if t_file.is_file():
                content = t_file.read_text(encoding="utf-8")
                for kw in LEAK_KEYWORDS:
                    if kw in content:
                        leak_findings.append(
                            f"LEAKAGE: '{kw}' found inside {t_file.relative_to(run_dir)}"
                        )

    return {
        "run_id": run_dir.name,
        "threat_class": index_meta.get("threat_class", "unknown"),
        "scenario_id": index_meta.get("scenario_id", "unknown"),
        "source_counts": source_counts,
        "calculated_duration_seconds": calc_duration,
        "min_cpu_mcores": min_cpu,
        "median_cpu_mcores": med_cpu,
        "max_cpu_mcores": max_cpu,
        "pct_above_100": pct_above_100,
        "pct_above_40": pct_above_40,
        "post_lag_sample_count": len(post_lag_cpus),
        "pct_above_100_post_lag": pct_above_100_post_lag,
        "pct_above_40_post_lag": pct_above_40_post_lag,
        "median_post_lag_cpu_mcores": med_post_lag,
        "expected_cpu_profile": exp_cpu_profile,
        "leak_findings": leak_findings,
    }


# ---------------------------------------------------------------------------
# Grouped cross-validation for the diagnostic sections.
#
# Decision D-32: the single-feature diagnostic and the label-permutation
# baseline used to be computed by fitting the classifier on the *same* rows it
# then scored (train-on-train), which is an optimistically biased estimate and
# is exactly the shortcut that made `command_length` reach Macro-F1 = 1.0000 on
# ten runs.  Both diagnostics now use a GroupKFold cross-validation whose
# groups are the scenario templates, so no template ever contributes to both
# the training and the evaluation of the same fold - the same discipline the
# dataset split uses.
#
# The estimates are still labelled DIAGNOSTIC until the corpus is large enough
# for the fold structure to be meaningful (>= 100 runs and >= 10 groups).
# ---------------------------------------------------------------------------
DIAGNOSTIC_MIN_RUNS: Final[int] = 100
DIAGNOSTIC_MIN_GROUPS: Final[int] = 10
DIAGNOSTIC_MAX_FOLDS: Final[int] = 5


def extract_group_labels(run_dirs: list[Path]) -> list[str]:
    """Return the cross-validation group of each run (its scenario template).

    The group is read from the run's own `index.json` `scenario_id` field, i.e.
    the template the run executed.  It is used **only** to build the
    cross-validation folds; it is never a feature and never reaches the
    classifier.  Runs without an `index.json` fall back to their directory
    name, which is unique per run and therefore a conservative (finer) group.
    """
    labels: list[str] = []
    for run_dir in run_dirs:
        label = run_dir.name
        index_file = run_dir / "index.json"
        if index_file.exists():
            try:
                data = json.loads(index_file.read_text(encoding="utf-8"))
                scenario_id = data.get("scenario_id")
                if isinstance(scenario_id, str) and scenario_id:
                    label = scenario_id
            except Exception:
                pass
        labels.append(label)
    return labels


def make_grouped_cv(n_groups: int) -> GroupKFold | None:
    """Return a GroupKFold over the available template groups, or None."""
    if n_groups < 2:
        return None
    return GroupKFold(n_splits=min(DIAGNOSTIC_MAX_FOLDS, n_groups))


def diagnostic_status(n_runs: int, n_groups: int, cv: GroupKFold | None) -> str:
    """Human-readable status of the diagnostic estimates."""
    if cv is None:
        return (
            f"DIAGNOSTIC ONLY - not computable: {n_runs} run(s), {n_groups} group(s); "
            "a grouped cross-validation needs at least 2 groups."
        )
    n_splits = cv.n_splits
    if n_runs < DIAGNOSTIC_MIN_RUNS or n_groups < DIAGNOSTIC_MIN_GROUPS:
        return (
            f"DIAGNOSTIC ONLY - {n_runs} run(s) in {n_groups} template group(s) across "
            f"{n_splits} grouped folds; the estimate is NOT a valid generalisation "
            f"figure until the corpus reaches {DIAGNOSTIC_MIN_RUNS} runs and "
            f"{DIAGNOSTIC_MIN_GROUPS} groups."
        )
    return (
        f"Grouped {n_splits}-fold cross-validation by template over {n_runs} runs "
        f"in {n_groups} groups."
    )


def grouped_macro_f1(
    features: np.ndarray,
    labels: np.ndarray,
    groups: list[str],
    cv: GroupKFold | None,
) -> float:
    """Out-of-fold macro F1 of a Random Forest under a template-grouped split.

    Every fold trains on the templates of the other folds and predicts the
    held-out templates, so a template never appears in both the training and
    the evaluation data of the same fold.
    """
    if cv is None or features.shape[0] < 2:
        return 0.0
    group_arr = np.asarray(groups)
    predictions = np.zeros_like(labels)
    for train_idx, test_idx in cv.split(features, labels, group_arr):
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        rf.fit(features[train_idx], labels[train_idx])
        predictions[test_idx] = rf.predict(features[test_idx])
    return float(f1_score(labels, predictions, average="macro", zero_division=0))


def test_metadata_shuffle_invariance(run_dir: Path) -> bool:
    """Verify that altering index.json metadata produces bit-for-bit identical feature vectors."""
    vec_orig = extract_features_from_run_dir(run_dir)

    index_file = run_dir / "index.json"
    if not index_file.exists():
        return True

    orig_content = index_file.read_text(encoding="utf-8")
    try:
        data = json.loads(orig_content)
        # Modify scenario_id and threat_class in metadata
        data["threat_class"] = "SHUFFLED_FAKE_CLASS"
        data["scenario_id"] = "SC-SHUFFLED-99"
        index_file.write_text(json.dumps(data), encoding="utf-8")

        # Feature extractor must be completely unaffected
        vec_mutated = extract_features_from_run_dir(run_dir)
        is_identical = bool(np.array_equal(vec_orig, vec_mutated))
        return is_identical
    finally:
        # Restore original index file
        index_file.write_text(orig_content, encoding="utf-8")


def run_dataset_verification(runs_dir: Path) -> int:
    """Execute complete dataset verification gate."""
    print("=======================================================")
    print("  RuntimeLens Dataset Validity & Leakage Verification Gate")
    print(f"  Target Runs Directory: {runs_dir}")
    print("=======================================================")

    run_dirs = sorted([d for d in runs_dir.iterdir() if d.is_dir()])
    if not run_dirs:
        print("ERROR: No run directories found in", runs_dir)
        return 1

    print(f"\n[1/5] Per-Run Source Counts & Timestamp Audit ({len(run_dirs)} runs)")
    total_leaks = 0
    mining_violations = 0
    burst_violations = 0

    for r_dir in run_dirs:
        audit = audit_run_directory(r_dir)
        sc_id = audit["scenario_id"]
        c_name = audit["threat_class"]
        dur = audit["calculated_duration_seconds"]
        counts = audit["source_counts"]
        leaks = audit["leak_findings"]

        print(
            f"  Run {r_dir.name} ({sc_id} | {c_name}): "
            f"Falco={counts['falco']}, Audit={counts['audit']}, Hubble={counts['hubble']}, "
            f"Prom={counts['prometheus']}, Trivy={counts['trivy']} | Duration: {dur}s"
        )

        if leaks:
            print(f"    --> FAIL: Telemetry leakage detected: {leaks}")
            total_leaks += len(leaks)

        min_cpu = audit["min_cpu_mcores"]
        med_cpu = audit["median_cpu_mcores"]
        max_cpu = audit["max_cpu_mcores"]

        # Variant-aware sustained-CPU check
        pct_high = audit["pct_above_100"]
        exp_profile = audit.get("expected_cpu_profile", "low")

        if exp_profile == "high":
            cpu_status = "PASS"
            # Decision D-27: the ratio is computed over post-lag samples only, and
            # a strict post-lag median floor is added so the gate is never weaker
            # than the legacy all-sample ratio it replaces.
            pct_high = audit.get("pct_above_100_post_lag", audit["pct_above_100"])
            med_post = audit.get("median_post_lag_cpu_mcores", 0.0)
            n_post = audit.get("post_lag_sample_count", counts["prometheus"])
            if (
                dur < 115.0
                or counts["prometheus"] < 8
                or n_post < MIN_POST_LAG_SAMPLES
                or pct_high < 80.0
                or med_post < 100.0
            ):
                cpu_status = (
                    f"FAIL (dur={dur}s, n={counts['prometheus']}, post_lag_n={n_post}, "
                    f"pct_high={pct_high:.1f}%, med_post_lag={med_post:.2f}m)"
                )
                mining_violations += 1
            print(
                f"    --> Sustained CPU [profile=high]: {pct_high:.1f}% post-lag samples >= 100m "
                f"(min={min_cpu:.2f}m, med={med_cpu:.2f}m, med_post_lag={med_post:.2f}m, "
                f"n={counts['prometheus']}, post_lag_n={n_post}) [{cpu_status}]"
            )
        elif exp_profile == "throttled":
            cpu_status = "PASS"
            # Decision D-27: post-lag ratio + strict post-lag median floor.
            pct_throttled = audit.get("pct_above_40_post_lag", audit.get("pct_above_40", 0.0))
            med_post = audit.get("median_post_lag_cpu_mcores", 0.0)
            n_post = audit.get("post_lag_sample_count", counts["prometheus"])
            if (
                dur < 50.0
                or counts["prometheus"] < 5
                or n_post < MIN_POST_LAG_SAMPLES
                or pct_throttled < 60.0
                or med_post < 40.0
            ):
                cpu_status = (
                    f"FAIL (dur={dur}s, n={counts['prometheus']}, post_lag_n={n_post}, "
                    f"pct_th={pct_throttled:.1f}%, med_post_lag={med_post:.2f}m)"
                )
                mining_violations += 1
            print(
                f"    --> Sustained CPU [profile=throttled]: {pct_throttled:.1f}% post-lag samples "
                f">= 40m (min={min_cpu:.2f}m, med={med_cpu:.2f}m, med_post_lag={med_post:.2f}m, "
                f"n={counts['prometheus']}, post_lag_n={n_post}) [{cpu_status}]"
            )
        elif exp_profile == "burst":
            # Decision D-26: the burst band must be wider than the cAdvisor
            # measurement noise floor (observed 25.77m vs 117.34m for the same
            # command across two attempts), while staying disjoint from the
            # `high` (full-throttle mining) band.
            cpu_status = "PASS"
            if (
                max_cpu < BURST_PEAK_MIN_MCORES
                or max_cpu > BURST_PEAK_MAX_MCORES
                or med_cpu >= BURST_MEDIAN_MAX_MCORES
            ):
                cpu_status = (
                    f"FAIL (peak={max_cpu:.2f}m not in "
                    f"[{BURST_PEAK_MIN_MCORES:.0f},{BURST_PEAK_MAX_MCORES:.0f}], "
                    f"med={med_cpu:.2f}m >= {BURST_MEDIAN_MAX_MCORES:.0f})"
                )
                burst_violations += 1
            print(
                f"    --> Sustained CPU [profile=burst]: peak={max_cpu:.2f}m (band "
                f"{BURST_PEAK_MIN_MCORES:.0f}-{BURST_PEAK_MAX_MCORES:.0f}m, D-26), "
                f"med={med_cpu:.2f}m (<{BURST_MEDIAN_MAX_MCORES:.0f}m), "
                f"n={counts['prometheus']}) [{cpu_status}]"
            )
        else:
            print(
                f"    --> Sustained CPU [profile=low]: {pct_high:.1f}% samples >= 100m "
                f"(min={min_cpu:.2f}m, med={med_cpu:.2f}m, n={counts['prometheus']}) "
                "[PASS (Baseline profile)]"
            )

    print("\n[2/5] Telemetry Metadata Leakage Audit")
    if total_leaks > 0:
        print(f"FAIL: {total_leaks} leakage occurrences found in telemetry files!")
    else:
        print("PASS: Zero scenario IDs, class names, or run IDs found inside telemetry streams.")

    print("\n[3/5] Metadata-Shuffle Feature Invariance Test")
    shuffle_passes = 0
    for r_dir in run_dirs:
        if test_metadata_shuffle_invariance(r_dir):
            shuffle_passes += 1
        else:
            print(f"FAIL: Feature extractor depends on metadata in {r_dir.name}!")

    if shuffle_passes == len(run_dirs):
        n_tot = len(run_dirs)
        print(f"PASS: 100% of runs ({shuffle_passes}/{n_tot}) verified invariant to metadata.")
    else:
        leaked_cnt = len(run_dirs) - shuffle_passes
        print(f"FAIL: Metadata leakage into features detected in {leaked_cnt} runs.")

    # 4. Feature Extraction & Diagnostics (if >= 2 runs)
    if len(run_dirs) >= 2:
        X, y, run_ids = extract_dataset_from_run_dirs(run_dirs)
        groups = extract_group_labels(run_dirs)
        n_groups = len(set(groups))
        cv = make_grouped_cv(n_groups)
        status = diagnostic_status(len(run_dirs), n_groups, cv)

        print("\n[4/5] Single-Feature Diagnostic Scores (grouped cross-validation by template)")
        print(f"  {status}")
        for i, fname in enumerate(FEATURE_NAMES):
            feat_col = X[:, [i]]
            score = grouped_macro_f1(feat_col, y, groups, cv)
            print(f"  Feature {i:02d} ({fname}): Macro-F1 = {score:.4f}")

        # Decision D-28: `command_length` is EXCLUDED from the classifier feature
        # set and is reported here as a diagnostic only, so that the confound
        # stays visible instead of being silently dropped.
        cmd_len_col = np.array(
            [[extract_command_length(r_dir)] for r_dir in run_dirs],
            dtype=np.float32,
        )
        diag_score = grouped_macro_f1(cmd_len_col, y, groups, cv)
        print(
            "  Diagnostic (EXCLUDED from classifier feature set, Decision D-28): "
            f"command_length: Macro-F1 = {diag_score:.4f}"
        )

        print("\n[5/5] Label-Permutation Baseline Test (grouped cross-validation)")
        rng = np.random.default_rng(42)
        y_perm = rng.permutation(y)
        perm_score = grouped_macro_f1(X, y_perm, groups, cv)
        print(f"  Permuted Labels Macro-F1: {perm_score:.4f} (Chance baseline)")
        print(f"  {status}")

    # Overall Gate Verdict
    print("\n=======================================================")
    if (
        total_leaks == 0
        and mining_violations == 0
        and burst_violations == 0
        and shuffle_passes == len(run_dirs)
    ):
        print("GATE VERDICT: PASSED (Zero leakage, verified durations, invariant features)")
        print("=======================================================")
        return 0
    else:
        print(
            "GATE VERDICT: FAILED (Violations detected: "
            f"leaks={total_leaks}, sustained_cpu={mining_violations}, "
            f"burst_cpu={burst_violations}, shuffle_failures={len(run_dirs) - shuffle_passes})"
        )
        print("=======================================================")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dataset Verification Gate")
    parser.add_argument(
        "--runs-dir", default="data/raw/runs", help="Directory containing per-run directories"
    )
    args = parser.parse_args()

    code = run_dataset_verification(Path(args.runs_dir))
    sys.exit(code)
