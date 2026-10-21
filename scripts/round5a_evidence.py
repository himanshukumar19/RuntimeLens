"""Round 5a evidence report: per-run telemetry vs the plan.

Read-only. Computes, for each run of the batch:
  * the per-source event counts and the raw `wc -l` of every capture file;
  * the cAdvisor sample series with min / median / max;
  * the Decision D-27 post-lag statistics for the mining runs;
  * the Falco rule set actually fired vs the plan's expected rule set;
  * the Hubble flow band measured vs the plan's expected band;
  * the audit verbs captured vs the plan's expected verbs.

Usage (on the VM, from the repository root):

    PYTHONPATH=src:. python3 scripts/round5a_evidence.py --runs-dir data/raw/runs
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, ".")

import scripts.stage4a_runner as runner  # noqa: E402
from runtimelens.eval.cpu_bands import (  # noqa: E402
    CPU_LAG_EXCLUSION_SECONDS,
    HIGH_CPU_MCORES,
    HIGH_CPU_MIN_PCT,
    HIGH_CPU_MIN_POST_LAG_MEDIAN_MCORES,
    MIN_POST_LAG_SAMPLES,
    THROTTLED_CPU_MCORES,
    THROTTLED_CPU_MIN_PCT,
    THROTTLED_CPU_MIN_POST_LAG_MEDIAN_MCORES,
    median,
    post_lag_cpu_samples,
)

RULE_SHORT = {
    "Interactive Shell Spawned in Non-Debug Container": "Shell Spawn",
    "Launch Sensitive Mount Container": "Sensitive Mount",
    "Read Sensitive Host Information Untrusted": "Sensitive File Read",
    "Suspicious High Port Egress": "High Port Egress",
}

BAND_BOUNDS = ((0, 5, "LOW"), (6, 11, "MID"), (12, 10**9, "HIGH"))


def hubble_band(count: int) -> str:
    for low, high, label in BAND_BOUNDS:
        if low <= count <= high:
            return label
    return "UNKNOWN"


def parse_iso_ts(ts_str: str) -> float:
    """Parse an ISO UTC timestamp to epoch seconds (same logic as verify_dataset)."""
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()


def wc_lines(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    return str(sum(1 for _ in path.open(encoding="utf-8")))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def cpu_series(run_dir: Path) -> tuple[list[float], list[float]]:
    metrics_file = run_dir / "prometheus" / "metrics.json"
    if not metrics_file.exists():
        return [], []
    data = json.loads(metrics_file.read_text(encoding="utf-8"))
    cpus: list[float] = []
    stamps: list[float] = []
    for sample in data.get("samples", []):
        total = 0.0
        for pod in sample.get("pod_stats", []):
            for container in pod.get("containers", []):
                total += float(container.get("cpu", {}).get("usageNanoCores", 0.0)) / 1e6
        cpus.append(round(total, 2))
        raw_stamp = sample.get("timestamp", 0.0)
        if isinstance(raw_stamp, str):
            raw_stamp = parse_iso_ts(raw_stamp)
        stamps.append(float(raw_stamp))
    return cpus, stamps


def falco_rules(run_dir: Path) -> list[str]:
    rules: list[str] = []
    for event in read_jsonl(run_dir / "falco" / "events.jsonl"):
        rule = event.get("rule")
        if rule and rule not in rules:
            rules.append(rule)
    return rules


def audit_verbs(run_dir: Path) -> list[str]:
    verbs: list[str] = []
    for event in read_jsonl(run_dir / "audit" / "events.jsonl"):
        verb = event.get("verb")
        if verb and verb not in verbs:
            verbs.append(verb)
    return verbs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", default="data/raw/runs")
    parser.add_argument("--round", default="5a")
    args = parser.parse_args()

    runs_dir = Path(args.runs_dir)
    templates = runner.select_templates(args.round)

    print("=" * 118)
    print("PER-RUN TABLE")
    print("=" * 118)
    print(
        f"{'run_id':<16} {'template':<14} {'class':<16} {'dur_s':>7} "
        f"{'falco':>5} {'audit':>5} {'hubble':>6} {'prom':>4} {'trivy':>5} {'pod':>4} "
        f"{'cpu_min':>7} {'cpu_med':>7} {'cpu_max':>7} {'profile':<9} gate"
    )
    for template in templates:
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            print(f"{template['run_id']:<16} {template['template_id']:<14} MISSING RUN DIRECTORY")
            continue
        index = json.loads((run_dir / "index.json").read_text(encoding="utf-8"))
        cpus, _ = cpu_series(run_dir)
        counts = {
            "falco": len(read_jsonl(run_dir / "falco" / "events.jsonl")),
            "audit": len(read_jsonl(run_dir / "audit" / "events.jsonl")),
            "hubble": len(read_jsonl(run_dir / "hubble" / "flows.jsonl")),
            "prometheus": len(cpus),
            "trivy": 1 if (run_dir / "trivy" / "report.json").exists() else 0,
            "pod": 1 if (run_dir / "pod" / "spec.json").exists() else 0,
        }
        med = median(cpus) if cpus else 0.0
        gate = index.get("gate_status", "?")
        print(
            f"{template['run_id']:<16} {template['template_id']:<14} "
            f"{template['threat_class']:<16} {index.get('elapsed_seconds', 0):>7} "
            f"{counts['falco']:>5} {counts['audit']:>5} {counts['hubble']:>6} "
            f"{counts['prometheus']:>4} {counts['trivy']:>5} {counts['pod']:>4} "
            f"{min(cpus) if cpus else 0.0:>7.2f} {med:>7.2f} {max(cpus) if cpus else 0.0:>7.2f} "
            f"{template['expected_cpu_profile']:<9} {gate}"
        )

    print()
    print("=" * 118)
    print("RAW LINE COUNTS PER SOURCE (wc -l of every capture file)")
    print("=" * 118)
    for template in templates:
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            continue
        print(f"\n{template['run_id']}  ({template['template_id']})")
        for rel in (
            "falco/events.jsonl",
            "audit/events.jsonl",
            "hubble/flows.jsonl",
            "trivy/report.json",
            "pod/spec.json",
            "index.json",
        ):
            path = run_dir / rel
            size = path.stat().st_size if path.exists() else 0
            print(f"  {rel:<26} lines={wc_lines(path):>6}  bytes={size}")
        metrics = run_dir / "prometheus" / "metrics.json"
        if metrics.exists():
            data = json.loads(metrics.read_text(encoding="utf-8"))
            print(f"  {'prometheus/metrics.json':<26} samples={len(data.get('samples', []))}")

    print()
    print("=" * 118)
    print("CPU SAMPLE SERIES (mcores)")
    print("=" * 118)
    for template in templates:
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            continue
        cpus, _ = cpu_series(run_dir)
        print(
            f"{template['run_id']:<16} {template['template_id']:<14} "
            f"n={len(cpus):<3} min={min(cpus) if cpus else 0.0:>7.2f} "
            f"med={median(cpus) if cpus else 0.0:>7.2f} "
            f"max={max(cpus) if cpus else 0.0:>7.2f}  {cpus}"
        )

    print()
    print("=" * 118)
    print("DECISION D-27 POST-LAG CPU STATISTICS (mining runs)")
    print("=" * 118)
    print(
        f"{'run_id':<16} {'template':<14} {'profile':<10} {'n':>3} {'n_post_lag':>10} "
        f"{'post_lag_median':>15} {'floor':>7} {'share>=thr':>11} {'need':>6} {'verdict':>9}"
    )
    for template in templates:
        if template["threat_class"] != "cryptomining":
            continue
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            continue
        cpus, stamps = cpu_series(run_dir)
        post = post_lag_cpu_samples(cpus, stamps)
        profile = template["expected_cpu_profile"]
        if profile == "high":
            threshold, min_pct, floor = (
                HIGH_CPU_MCORES,
                HIGH_CPU_MIN_PCT,
                (HIGH_CPU_MIN_POST_LAG_MEDIAN_MCORES),
            )
        else:
            threshold, min_pct, floor = (
                THROTTLED_CPU_MCORES,
                THROTTLED_CPU_MIN_PCT,
                THROTTLED_CPU_MIN_POST_LAG_MEDIAN_MCORES,
            )
        med_post = median(post)
        share = (100.0 * sum(1 for c in post if c >= threshold) / len(post)) if post else 0.0
        ok = len(post) >= MIN_POST_LAG_SAMPLES and med_post >= floor and share >= min_pct
        print(
            f"{template['run_id']:<16} {template['template_id']:<14} {profile:<10} {len(cpus):>3} "
            f"{len(post):>10} {med_post:>15.2f} {floor:>7.0f} {share:>10.1f}% {min_pct:>5.0f}% "
            f"{'OK' if ok else 'FAIL':>9}"
        )
        print(f"{'':>16} post-lag samples: {post}")
        print(
            f"{'':>16} lag exclusion: {CPU_LAG_EXCLUSION_SECONDS:.0f}s from the first sample; "
            f"min post-lag samples {MIN_POST_LAG_SAMPLES}"
        )

    print()
    print("=" * 118)
    print(
        "FALCO FIRED vs EXPECTED  |  HUBBLE BAND MEASURED vs EXPECTED"
        "  |  AUDIT VERBS MEASURED vs EXPECTED"
    )
    print("=" * 118)
    for template in templates:
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            continue
        fired = falco_rules(run_dir)
        fired_short = [RULE_SHORT.get(r, r) for r in fired]
        expect_short = [RULE_SHORT[r] for r in template["expect_falco"]]
        falco_match = sorted(fired_short) == sorted(expect_short)
        missing = [r for r in expect_short if r not in fired_short]
        extra = [r for r in fired_short if r not in expect_short]

        flows = len(read_jsonl(run_dir / "hubble" / "flows.jsonl"))
        measured_band = hubble_band(flows)
        band_match = measured_band == template["expect_hubble_band"]

        verbs = sorted(audit_verbs(run_dir))
        expect_verbs = sorted(template["expect_verbs"])
        verbs_match = verbs == expect_verbs

        print(f"\n{template['run_id']}  {template['template_id']}  ({template['threat_class']})")
        print(f"  Falco  expected: {expect_short}")
        print(f"  Falco  fired   : {fired_short}   {'MATCH' if falco_match else 'MISMATCH'}")
        if missing:
            print(f"         MISSING  : {missing}")
        if extra:
            print(f"         EXTRA    : {extra}")
        print(
            f"  Hubble expected band: {template['expect_hubble_band']}  measured band: "
            f"{measured_band} ({flows} flows)  {'MATCH' if band_match else 'MISMATCH'}"
        )
        print(
            f"  Audit  expected verbs: {expect_verbs}  measured verbs: {verbs}  "
            f"{'MATCH' if verbs_match else 'MISMATCH'}"
        )
        if not verbs_match:
            print(f"         missing verbs: {[v for v in expect_verbs if v not in verbs]}")
            print(f"         extra verbs  : {[v for v in verbs if v not in expect_verbs]}")

    print()
    print("=" * 118)
    print("SUMMARY OF MISMATCHES")
    print("=" * 118)
    any_mismatch = False
    for template in templates:
        run_dir = runs_dir / template["run_id"]
        if not run_dir.exists():
            print(f"{template['template_id']}: run directory missing")
            any_mismatch = True
            continue
        fired_short = [RULE_SHORT.get(r, r) for r in falco_rules(run_dir)]
        expect_short = [RULE_SHORT[r] for r in template["expect_falco"]]
        flows = len(read_jsonl(run_dir / "hubble" / "flows.jsonl"))
        measured_band = hubble_band(flows)
        verbs = sorted(audit_verbs(run_dir))
        expect_verbs = sorted(template["expect_verbs"])
        problems = []
        if sorted(fired_short) != sorted(expect_short):
            problems.append(
                f"falco expected={expect_short} fired={fired_short} "
                f"missing={[r for r in expect_short if r not in fired_short]} "
                f"extra={[r for r in fired_short if r not in expect_short]}"
            )
        if measured_band != template["expect_hubble_band"]:
            problems.append(
                f"hubble band expected={template['expect_hubble_band']} measured={measured_band} "
                f"({flows} flows)"
            )
        if verbs != expect_verbs:
            problems.append(f"audit verbs expected={expect_verbs} measured={verbs}")
        if problems:
            any_mismatch = True
            print(f"{template['template_id']}:")
            for problem in problems:
                print(f"  - {problem}")
    if not any_mismatch:
        print("no mismatches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
