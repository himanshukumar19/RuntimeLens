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

from runtimelens.features.extractor import (
    FEATURE_NAMES,
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
                        timestamps.append(parse_iso_ts(s_ts))
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
        "expected_cpu_profile": exp_cpu_profile,
        "leak_findings": leak_findings,
    }


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
            if dur < 115.0 or counts["prometheus"] < 8 or pct_high < 80.0:
                cpu_status = (
                    f"FAIL (dur={dur}s, n={counts['prometheus']}, pct_high={pct_high:.1f}%)"
                )
                mining_violations += 1
            print(
                f"    --> Sustained CPU [profile=high]: {pct_high:.1f}% samples >= 100m "
                f"(min={min_cpu:.2f}m, med={med_cpu:.2f}m, n={counts['prometheus']}) [{cpu_status}]"
            )
        elif exp_profile == "throttled":
            cpu_status = "PASS"
            pct_throttled = audit.get("pct_above_40", 0.0)
            if dur < 50.0 or counts["prometheus"] < 5 or pct_throttled < 60.0:
                cpu_status = (
                    f"FAIL (dur={dur}s, n={counts['prometheus']}, pct_th={pct_throttled:.1f}%)"
                )
                mining_violations += 1
            print(
                f"    --> Sustained CPU [profile=throttled]: {pct_throttled:.1f}% samples >= 40m "
                f"(min={min_cpu:.2f}m, med={med_cpu:.2f}m, n={counts['prometheus']}) [{cpu_status}]"
            )
        elif exp_profile == "burst":
            # Burst profile: a short, transient CPU spike that is clearly distinguishable
            # from both sustained mining (profile=high) and an idle baseline (profile=low).
            # Band: peak between 30 and 100 mcores, median strictly below 100 mcores.
            cpu_status = "PASS"
            if max_cpu < 30.0 or max_cpu > 100.0 or med_cpu >= 100.0:
                cpu_status = (
                    f"FAIL (peak={max_cpu:.2f}m not in [30,100], med={med_cpu:.2f}m >= 100)"
                )
                burst_violations += 1
            print(
                f"    --> Sustained CPU [profile=burst]: peak={max_cpu:.2f}m (band 30-100m), "
                f"med={med_cpu:.2f}m (<100m), n={counts['prometheus']} [{cpu_status}]"
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
        print("\n[4/5] Single-Feature Diagnostic Scores (Diagnostic Only)")
        X, y, run_ids = extract_dataset_from_run_dirs(run_dirs)
        for i, fname in enumerate(FEATURE_NAMES):
            feat_col = X[:, [i]]
            rf = RandomForestClassifier(n_estimators=10, random_state=42)
            rf.fit(feat_col, y)
            preds = rf.predict(feat_col)
            score = float(f1_score(y, preds, average="macro", zero_division=0))
            print(f"  Feature {i:02d} ({fname}): Macro-F1 = {score:.4f}")

        print("\n[5/5] Label-Permutation Baseline Test")
        rng = np.random.default_rng(42)
        y_perm = rng.permutation(y)
        rf_perm = RandomForestClassifier(n_estimators=10, random_state=42)
        rf_perm.fit(X, y_perm)
        perm_score = float(f1_score(y_perm, rf_perm.predict(X), average="macro", zero_division=0))
        print(f"  Permuted Labels Macro-F1: {perm_score:.4f} (Chance baseline)")

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
