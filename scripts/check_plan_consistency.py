"""Plan-vs-runner consistency check over all 55 registered templates.

For every template in `docs/SCENARIO_PLAN_v2.md` §3.1-§3.5 the script compares
the registry row against the runner's template definition and reports every
mismatch in: class, length bin, CPU profile, expected Falco rules, the
feature triple, the audit verbs and the Hubble band.

Exit code 0 = consistent, 1 = at least one mismatch.

Run from the repository root:

    PYTHONPATH=src:. python3 scripts/check_plan_consistency.py
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

sys.path.insert(0, ".")

import scripts.stage4a_runner as runner  # noqa: E402

PLAN = pathlib.Path("docs/SCENARIO_PLAN_v2.md")

RULE_SHORT = {
    "Interactive Shell Spawned in Non-Debug Container": "Shell Spawn",
    "Launch Sensitive Mount Container": "Sensitive Mount",
    "Read Sensitive Host Information Untrusted": "Sensitive File Read",
    "Suspicious High Port Egress": "High Port Egress",
}

ID_PREFIX_TO_CLASS = {
    "BEN": "benign",
    "ESC": "container_escape",
    "PRV": "privilege_abuse",
    "MNR": "cryptomining",
    "UNK": "unknown",
}

BINS = (("30–80", 80), ("81–150", 150), ("151–250+", 10_000))


def bin_of(length: int) -> str:
    for label, ceiling in BINS:
        if length <= ceiling:
            return label
    return BINS[-1][0]


def clean(cell: str) -> str:
    return cell.replace("**", "").strip()


def parse_plan() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in PLAN.read_text().splitlines():
        if not line.startswith("| `TMPL-"):
            continue
        parts = [p.strip() for p in line.split("|")[1:-1]]
        if len(parts) < 13:
            continue
        rows[parts[0].strip("`")] = parts
    return rows


def all_runner_templates() -> list[dict[str, Any]]:
    return (
        list(runner.TEMPLATES)
        + list(runner.ROUND2_TEMPLATES)
        + list(runner.ROUND3_TEMPLATES)
        + list(runner.ROUND4_TEMPLATES)
        + list(runner.ROUND5_TEMPLATES)
    )


def main() -> int:
    plan = parse_plan()
    templates = all_runner_templates()
    by_id = {t["template_id"]: t for t in templates}

    problems: list[str] = []
    checked = 0

    if len(plan) != 55:
        problems.append(f"plan registry holds {len(plan)} rows, expected 55")
    if len(by_id) != 55:
        problems.append(f"runner holds {len(by_id)} templates, expected 55")
    if set(plan) != set(by_id):
        for missing in sorted(set(plan) ^ set(by_id)):
            problems.append(f"template {missing} is in exactly one of plan/runner")

    for tid, parts in sorted(plan.items()):
        template = by_id.get(tid)
        if template is None:
            continue
        checked += 1
        plan_bin = clean(parts[2])
        plan_profile = clean(parts[6])
        plan_rules = [r.strip() for r in clean(parts[7]).split(",") if r.strip()]
        plan_features = [f.strip() for f in clean(parts[8]).split("/")]
        plan_verbs = sorted(v.strip() for v in clean(parts[9]).split(",") if v.strip())
        plan_band = clean(parts[10])

        prefix = tid.split("-")[1]
        expected_class = ID_PREFIX_TO_CLASS.get(prefix)
        if expected_class != template["threat_class"]:
            problems.append(
                f"{tid}: class {template['threat_class']!r} != id-implied {expected_class!r}"
            )

        length = len(template["command"]) + 6
        if bin_of(length) != plan_bin:
            problems.append(
                f"{tid}: length bin {plan_bin!r} != measured {bin_of(length)!r} ({length} chars)"
            )

        if plan_profile != template["expected_cpu_profile"]:
            problems.append(
                f"{tid}: cpu profile {plan_profile!r} != runner "
                f"{template['expected_cpu_profile']!r}"
            )

        runner_rules = [RULE_SHORT[r] for r in template["expect_falco"]]
        if sorted(plan_rules) != sorted(runner_rules):
            problems.append(
                f"{tid}: expected falco rules {sorted(plan_rules)} != runner {sorted(runner_rules)}"
            )

        if plan_features != template["expect_features"]:
            problems.append(
                f"{tid}: features {plan_features} != runner {template['expect_features']}"
            )

        if plan_verbs != sorted(template["expect_verbs"]):
            problems.append(
                f"{tid}: audit verbs {plan_verbs} != runner {sorted(template['expect_verbs'])}"
            )

        if plan_band != template["expect_hubble_band"]:
            problems.append(
                f"{tid}: hubble band {plan_band!r} != runner {template['expect_hubble_band']!r}"
            )

    print(f"templates checked: {checked}")
    if problems:
        print(f"mismatches: {len(problems)}")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("mismatches: 0  (class, length bin, cpu profile, falco rules, features, verbs, band)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
