"""Analyze distinct Falco rules and Kubernetes audit verbs across completed runs."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def analyze_signals(runs_dir: Path) -> None:
    falco_by_class: dict[str, set[str]] = defaultdict(set)
    audit_by_class: dict[str, set[str]] = defaultdict(set)
    run_counts_by_class: dict[str, int] = defaultdict(int)

    for r_dir in sorted(runs_dir.iterdir()):
        if not r_dir.is_dir():
            continue
        idx_f = r_dir / "index.json"
        if not idx_f.exists():
            continue
        try:
            meta = json.loads(idx_f.read_text(encoding="utf-8"))
        except Exception:
            continue
        t_class = meta.get("threat_class", "unknown")
        run_counts_by_class[t_class] += 1

        falco_f = r_dir / "falco" / "events.jsonl"
        if falco_f.exists():
            with open(falco_f, encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("{"):
                        try:
                            rule = json.loads(line).get("rule")
                            if rule:
                                falco_by_class[t_class].add(rule)
                        except Exception:
                            pass

        audit_f = r_dir / "audit" / "events.jsonl"
        if audit_f.exists():
            with open(audit_f, encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("{"):
                        try:
                            verb = json.loads(line).get("verb")
                            if verb:
                                audit_by_class[t_class].add(verb)
                        except Exception:
                            pass

    print("================================================================================")
    print("  Distinct Falco Rules and Audit Verbs by Threat Class")
    print(f"  Target Runs Directory: {runs_dir}")
    print("================================================================================")
    for t_class in sorted(run_counts_by_class.keys()):
        f_rules = sorted(falco_by_class[t_class])
        a_verbs = sorted(audit_by_class[t_class])
        print(f"\nClass: {t_class.upper()} ({run_counts_by_class[t_class]} runs)")
        print(f"  Distinct Falco Rules ({len(f_rules)}):")
        for r in f_rules:
            print(f"    - {r}")
        if not f_rules:
            print("    (none)")
        print(f"  Distinct Audit Verbs ({len(a_verbs)}):")
        for v in a_verbs:
            print(f"    - {v}")
        if not a_verbs:
            print("    (none)")
    print("\n================================================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze pilot telemetry signals")
    parser.add_argument("--runs-dir", default="data/raw/runs", help="Runs directory")
    args = parser.parse_args()
    analyze_signals(Path(args.runs_dir))
