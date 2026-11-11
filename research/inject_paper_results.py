"""Inject the measured live-experiment numbers into the IEEE paper source.

Reads ``research/results/live_analysis.json`` and ``research/results/adversarial_asr_*.json``
and rewrites the corresponding tables in ``docs/paper/runtimelens_paper.tex`` so the
paper and the deck can never disagree.

The tables are delimited by the marker comments ``%% BEGIN <name>`` and
``%% END <name>``, which are inserted on first run.

Usage:
    uv run python -m research.inject_paper_results
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "research" / "results"
PAPER = ROOT / "docs" / "paper" / "runtimelens_paper.tex"


def _load_analysis() -> dict[str, Any]:
    path = RESULTS / "live_analysis.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _load_asr() -> dict[str, Any]:
    path = RESULTS / "adversarial_aggregate.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"repetitions": 0, "arms": []}


def _fmt_ci(lo: float, hi: float) -> str:
    return f"[{lo:+.4f}, {hi:+.4f}]"


def build_live_rows(analysis: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for arm in analysis.get("arms", []):
        boot = arm["paired_bootstrap"]["delta_macro_f1"]
        mc = arm["mcnemar_midp"]
        model = arm["model"].replace("openai/", "").replace("qwen/", "")
        rows.append(
            "{} & {:.4f} & {:+.4f} & {} & {:.3f} & {} \\\\".format(
                model,
                arm["with_baseline"]["macro_f1"],
                arm["delta_macro_f1"],
                _fmt_ci(boot["lo"], boot["hi"]),
                mc["p_value"],
                arm["n_incidents"],
            )
        )
    return rows


def build_asr_rows(aggregate: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for block in aggregate.get("arms", []):
        arm = {
            "groq-20b": "gpt-oss-20b",
            "groq-qwen27b": "qwen3.8-27b",
            "groq-120b": "gpt-oss-120b",
        }.get(block["arm"], block["arm"])
        cells = []
        for tier in ("0", "1", "2", "3"):
            entry = next((t for t in block["tiers"] if t["tier"] == tier), None)
            if not entry:
                cells.append("--")
                continue
            cells.append(
                f"{entry['asr_mean'] * 100:.0f}\\% "
                f"[{entry['asr_min'] * 100:.0f}-{entry['asr_max'] * 100:.0f}]"
            )
        rows.append(f"{arm} & " + " & ".join(cells) + " \\\\")
    return rows


def replace_block(text: str, name: str, body: str) -> str:
    pattern = re.compile(
        rf"(%% BEGIN {re.escape(name)}\n).*?(\n?%% END {re.escape(name)})",
        re.DOTALL,
    )
    if not pattern.search(text):
        raise SystemExit(f"marker block {name} not found in {PAPER}")
    return pattern.sub(lambda m: m.group(1) + body.rstrip("\n") + "\n" + m.group(2), text)


def main() -> int:
    analysis = _load_analysis()
    asr = _load_asr()
    if not analysis and not asr:
        print("no live results found; nothing to inject")
        return 1

    text = PAPER.read_text()

    live_rows = build_live_rows(analysis)
    if live_rows:
        text = replace_block(text, "LIVE_TABLE", "\n".join(live_rows))

    asr_rows = build_asr_rows(asr)
    if asr_rows:
        text = replace_block(text, "ASR_TABLE", "\n".join(asr_rows))

    PAPER.write_text(text)
    print(f"injected into {PAPER}")
    print(f"  live rows: {len(live_rows)}, asr rows: {len(asr_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
