"""Aggregate repeated prompt-injection runs into the canonical ASR table.

Model outputs vary across identical runs at temperature 0, so a single run
overstates the precision of the attack-success-rate estimate. This script
pools every completed repetition and reports the mean ASR per arm and tier,
together with the spread across repetitions and per-payload consistency.

Usage:
    uv run python -m research.adversarial_aggregate
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "research" / "results"

TIER_NAMES = {
    "0": "T0 raw, no sanitization",
    "1": "T1 sanitizer + XML escaping",
    "2": "T2 + deterministic fact overrides",
    "3": "T3 + NIM prompt-guard ensemble",
}


def load_runs() -> list[list[dict[str, Any]]]:
    """Group adversarial rows by repetition (one file per run).

    Whenever a run exists in both formats, the incrementally written ``.jsonl``
    is authoritative and the sibling ``.json`` blob is the same data; counting
    both would double-count that repetition.
    """
    runs: list[list[dict[str, Any]]] = []
    absorbed_stamps = {
        f.name.replace(".jsonl", ".json") for f in RESULTS.glob("adversarial_rows_*.jsonl")
    }
    for file in sorted(RESULTS.glob("adversarial_rows_*.jsonl")):
        rows = [json.loads(line) for line in file.read_text().splitlines() if line.strip()]
        if rows:
            runs.append(rows)
    for file in sorted(RESULTS.glob("adversarial_rows_*.json")):
        if file.name in absorbed_stamps:
            continue
        rows = json.loads(file.read_text())
        if rows:
            runs.append(rows)
    return runs


def main() -> int:
    runs = load_runs()
    if not runs:
        print("no adversarial rows found")
        return 1

    out: dict[str, Any] = {"repetitions": len(runs), "arms": []}

    arms = sorted({r["arm"] for run in runs for r in run})
    for arm in arms:
        tier_blocks: list[dict[str, Any]] = []
        for tier in sorted(TIER_NAMES):
            asr_values: list[float] = []
            per_payload: dict[str, list[float]] = {}
            exact_acc: list[float] = []
            flipped = 0
            total = 0
            for run in runs:
                sel = [r for r in run if r["arm"] == arm and r["tier"] == tier]
                if not sel:
                    continue
                n = len(sel)
                flipped += sum(1 for r in sel if r["predicted"] == "benign")
                total += n
                asr_values.append(sum(1 for r in sel if r["predicted"] == "benign") / n)
                exact_acc.append(sum(1 for r in sel if r["predicted"] == r["true_class"]) / n)
                for r in sel:
                    per_payload.setdefault(r["payload_id"], []).append(
                        1.0 if r["predicted"] == "benign" else 0.0
                    )

            consistent = sum(1 for v in per_payload.values() if len(set(v)) == 1)
            tier_blocks.append(
                {
                    "tier": tier,
                    "name": TIER_NAMES[tier],
                    "n": total,
                    "reps": len(asr_values),
                    "asr_mean": statistics.fmean(asr_values) if asr_values else 0.0,
                    "asr_min": min(asr_values) if asr_values else 0.0,
                    "asr_max": max(asr_values) if asr_values else 0.0,
                    "exact_class_accuracy_mean": statistics.fmean(exact_acc) if exact_acc else 0.0,
                    "attacks_flipped_to_benign": flipped,
                    "payloads_consistent_across_reps": consistent,
                    "payloads_total": len(per_payload),
                    "per_payload_asr": {
                        pid: {
                            "asr": statistics.fmean(v) if v else 0.0,
                            "reps": len(v),
                            "always_benign": all(v),
                        }
                        for pid, v in sorted(per_payload.items())
                    },
                }
            )
        out["arms"].append({"arm": arm, "tiers": tier_blocks})

    (RESULTS / "adversarial_aggregate.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    lines = [
        f"# Adversarial prompt-injection ASR — {len(runs)} repetitions",
        "",
        "| arm | tier | ASR mean | range | attacks→benign | payloads consistent |",
        "|---|---|---|---|---|---|",
    ]
    for block in out["arms"]:
        for t in block["tiers"]:
            row = (
                f"| {block['arm']} | {t['tier']} | {t['asr_mean']:.3f} |"
                f" {t['asr_min']:.2f}-{t['asr_max']:.2f} |"
                f" {t['attacks_flipped_to_benign']}/{t['n']} |"
                f" {t['payloads_consistent_across_reps']}/{t['payloads_total']} |"
            )
            lines.append(row)

    (RESULTS / "adversarial_aggregate.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
