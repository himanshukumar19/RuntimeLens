"""Read-only Table F: distinct telemetry signature per threat class.

Signature = (Falco rule set, audit verbs, Hubble flow band, CPU band).

The signature is computed from the REAL captured telemetry in per-run
directories (`data/raw/runs/<run_id>/{falco,audit,hubble,prometheus}/`) plus the
run metadata in `index.json`. This script never writes to, moves or deletes any
telemetry; it only reads.

Usage:
    PYTHONPATH=src:. uv run python scripts/signature_table.py --runs-dir data/raw/runs
    PYTHONPATH=src:. uv run python scripts/signature_table.py --runs-dir data/raw/runs --json

Output is the real counterpart of the paper Table F in
`docs/SCENARIO_PLAN_v2.md` section 7. A class whose largest single signature
covers 60% or more of its runs is FLAGGED, because that means one telemetry
signature would by itself identify the class.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

# Hubble flow-count bands, chosen to match the LOW / MID / HIGH bands used in
# docs/SCENARIO_PLAN_v2.md.
HUBBLE_BANDS: tuple[tuple[str, int, int | None], ...] = (
    ("LOW", 0, 6),
    ("MID", 7, 11),
    ("HIGH", 12, None),
)

# CPU band boundaries in millicores.
CPU_LOW_MAX = 40.0
CPU_MID_MAX = 100.0

FLAGGED_SHARE_PCT = 60.0


def hubble_band(flow_count: int) -> str:
    """Map a Hubble flow count onto its band label."""
    for label, low, high in HUBBLE_BANDS:
        if flow_count >= low and (high is None or flow_count <= high):
            return label
    return "UNBANDED"


def cpu_band(peak_mcores: float, median_mcores: float) -> str:
    """Map CPU statistics onto a band label.

    LOW    - idle baseline
    MID    - moderate load (peak 40-100 mcores)
    HIGH   - sustained load (median at or above 100 mcores)
    """
    if median_mcores >= CPU_MID_MAX:
        return "HIGH"
    if peak_mcores >= CPU_LOW_MAX:
        return "MID"
    return "LOW"


def read_falco_rules(run_dir: Path) -> list[str]:
    """Return the sorted distinct Falco rule names observed in a run."""
    rules: set[str] = set()
    falco_file = run_dir / "falco" / "events.jsonl"
    if not falco_file.exists():
        return []
    with open(falco_file, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rule = json.loads(line).get("rule")
            except Exception:
                continue
            if rule:
                rules.add(str(rule))
    return sorted(rules)


def read_audit_verbs(run_dir: Path) -> list[str]:
    """Return the sorted distinct Kubernetes audit verbs observed in a run."""
    verbs: set[str] = set()
    audit_file = run_dir / "audit" / "events.jsonl"
    if not audit_file.exists():
        return []
    with open(audit_file, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                verb = json.loads(line).get("verb")
            except Exception:
                continue
            if verb:
                verbs.add(str(verb))
    return sorted(verbs)


def read_hubble_flow_count(run_dir: Path) -> int:
    """Return the number of Hubble flow records captured in a run."""
    hubble_file = run_dir / "hubble" / "flows.jsonl"
    if not hubble_file.exists():
        return 0
    count = 0
    with open(hubble_file, encoding="utf-8") as handle:
        for line in handle:
            if line.strip().startswith("{"):
                count += 1
    return count


def read_cpu_stats(run_dir: Path) -> tuple[float, float]:
    """Return (peak_mcores, median_mcores) from the captured cAdvisor samples."""
    prom_file = run_dir / "prometheus" / "metrics.json"
    if not prom_file.exists():
        return 0.0, 0.0
    try:
        data = json.loads(prom_file.read_text(encoding="utf-8"))
    except Exception:
        return 0.0, 0.0

    sample_cpus: list[float] = []
    samples = data.get("samples", [])
    if samples:
        for sample in samples:
            total = 0.0
            for pod in sample.get("pod_stats", []):
                for container in pod.get("containers", []):
                    total += round(
                        float(container.get("cpu", {}).get("usageNanoCores", 0.0)) / 1e6, 2
                    )
            sample_cpus.append(total)
    else:
        for pod in data.get("pod_stats", []):
            total = 0.0
            for container in pod.get("containers", []):
                total += round(float(container.get("cpu", {}).get("usageNanoCores", 0.0)) / 1e6, 2)
            sample_cpus.append(total)

    if not sample_cpus:
        return 0.0, 0.0
    return float(np.max(sample_cpus)), float(np.median(sample_cpus))


def collect_run_signatures(runs_dir: Path) -> list[dict[str, Any]]:
    """Build one signature record per run directory."""
    records: list[dict[str, Any]] = []
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        index_file = run_dir / "index.json"
        if not index_file.exists():
            continue
        try:
            meta = json.loads(index_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        peak, median = read_cpu_stats(run_dir)
        flow_count = read_hubble_flow_count(run_dir)
        falco_rules = read_falco_rules(run_dir)
        audit_verbs = read_audit_verbs(run_dir)

        records.append(
            {
                "run_id": run_dir.name,
                "threat_class": str(meta.get("threat_class", "unknown")),
                "class_status": meta.get("class_status"),
                "expected_cpu_profile": meta.get("expected_cpu_profile"),
                "falco_rules": falco_rules,
                "audit_verbs": audit_verbs,
                "hubble_flow_count": flow_count,
                "hubble_band": hubble_band(flow_count),
                "cpu_peak_mcores": round(peak, 2),
                "cpu_median_mcores": round(median, 2),
                "cpu_band": cpu_band(peak, median),
            }
        )
    return records


def build_table(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Group run signatures by class and compute the largest single-signature share.

    Runs carrying a `class_status` (for example "pilot only, class dropped")
    are reported in the per-run detail but are EXCLUDED from the per-class
    statistics, because their class is not part of the evaluated corpus.
    """
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get("class_status"):
            continue
        by_class[record["threat_class"]].append(record)

    table: dict[str, Any] = {}
    for threat_class, class_records in sorted(by_class.items()):
        signature_counts: Counter[tuple[str, ...]] = Counter()
        signature_runs: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for record in class_records:
            key = (
                ",".join(record["falco_rules"]) or "(none)",
                ",".join(record["audit_verbs"]) or "(none)",
                record["hubble_band"],
                record["cpu_band"],
            )
            signature_counts[key] += 1
            signature_runs[key].append(record["run_id"])

        total = len(class_records)
        largest_key, largest_count = (
            max(signature_counts.items(), key=lambda kv: kv[1]) if signature_counts else ((), 0)
        )
        largest_pct = (largest_count / total * 100.0) if total else 0.0

        table[threat_class] = {
            "total_runs": total,
            "distinct_signatures": len(signature_counts),
            "largest_signature_runs": largest_count,
            "largest_signature_pct": round(largest_pct, 1),
            "largest_signature": {
                "falco_rules": largest_key[0] if largest_key else "",
                "audit_verbs": largest_key[1] if largest_key else "",
                "hubble_band": largest_key[2] if largest_key else "",
                "cpu_band": largest_key[3] if largest_key else "",
            },
            "flagged": largest_pct >= FLAGGED_SHARE_PCT,
            "signatures": [
                {
                    "falco_rules": key[0],
                    "audit_verbs": key[1],
                    "hubble_band": key[2],
                    "cpu_band": key[3],
                    "runs": count,
                    "pct": round(count / total * 100.0, 1),
                    "run_ids": signature_runs[key],
                }
                for key, count in sorted(signature_counts.items(), key=lambda kv: -kv[1])
            ],
        }
    return table


def print_table(records: list[dict[str, Any]], table: dict[str, Any]) -> None:
    """Print the human-readable Table F."""
    print("=" * 100)
    print("  RuntimeLens Table F — Distinct Telemetry Signature per Threat Class (REAL telemetry)")
    print("  signature = (Falco rule set | audit verbs | Hubble flow band | CPU band)")
    print("  read-only: no telemetry is modified, moved or deleted")
    print("=" * 100)

    excluded = [r for r in records if r.get("class_status")]
    if excluded:
        print(
            f"\nNOTE: {len(excluded)} run(s) carry a class_status and are reported but excluded "
            "from class-level statistics:"
        )
        for record in excluded:
            print(f"  - {record['run_id']} ({record['threat_class']}): {record['class_status']}")
        print()

    print("\n[Per-run signature detail]")
    print(
        f"{'run_id':<18}{'class':<18}{'falco rules':<52}"
        f"{'verbs':<22}{'flows':>6}{'band':>6}{'peak':>8}{'med':>8}{'cpu':>6}"
    )
    for record in records:
        print(
            f"{record['run_id']:<18}"
            f"{record['threat_class']:<18}"
            f"{(', '.join(record['falco_rules']) or '(none)'):<52}"
            f"{(', '.join(record['audit_verbs']) or '(none)'):<22}"
            f"{record['hubble_flow_count']:>6}"
            f"{record['hubble_band']:>6}"
            f"{record['cpu_peak_mcores']:>8.2f}"
            f"{record['cpu_median_mcores']:>8.2f}"
            f"{record['cpu_band']:>6}"
        )

    print("\n[Table F — per class]")
    if excluded:
        print(
            f"({len(excluded)} run(s) with a class_status are EXCLUDED from the per-class "
            "statistics below.)"
        )
    for threat_class, info in table.items():
        flag = "  <-- FLAGGED (>= 60% of runs in one signature)" if info["flagged"] else ""
        print(
            f"\nClass {threat_class}: runs={info['total_runs']} "
            f"distinct_signatures={info['distinct_signatures']} "
            f"largest={info['largest_signature_pct']:.1f}%{flag}"
        )
        for signature in info["signatures"]:
            print(
                f"    {signature['runs']:>3} runs ({signature['pct']:>5.1f}%)  "
                f"falco=[{signature['falco_rules']}] verbs=[{signature['audit_verbs']}] "
                f"hubble={signature['hubble_band']} cpu={signature['cpu_band']}"
            )
            print(f"          run_ids: {', '.join(signature['run_ids'])}")

    print("\n" + "=" * 100)
    flagged = [c for c, info in table.items() if info["flagged"]]
    if flagged:
        print("CLASSES WHERE >= 60% OF RUNS SHARE ONE SIGNATURE:")
        for threat_class in flagged:
            info = table[threat_class]
            print(
                f"  {threat_class}: {info['largest_signature_runs']}/{info['total_runs']} runs "
                f"= {info['largest_signature_pct']:.1f}%"
            )
    else:
        print("CLASSES WHERE >= 60% OF RUNS SHARE ONE SIGNATURE: (none)")
    print("=" * 100)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Table F signature computation")
    parser.add_argument("--runs-dir", default="data/raw/runs", help="Per-run directories root")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = parser.parse_args()

    runs_dir = Path(args.runs_dir)
    if not runs_dir.is_dir():
        print(f"ERROR: runs directory not found: {runs_dir}")
        return 1

    records = collect_run_signatures(runs_dir)
    if not records:
        print(f"ERROR: no run directories with index.json found under {runs_dir}")
        return 1

    table = build_table(records)

    if args.json:
        print(json.dumps({"runs": records, "table": table}, indent=2, default=str))
    else:
        print_table(records, table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
