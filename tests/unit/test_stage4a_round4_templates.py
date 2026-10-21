"""Unit tests for the Stage 4a Round 4 template registry (32 never-run templates).

The Round 4 command-writing round is offline: these tests assert the structural
invariants that the round established, without touching the cluster.
"""

from __future__ import annotations

import pathlib
import re
from collections import Counter

from scripts.scenario_safety_lint import lint_manifest
from scripts.stage4a_round4 import OBS_A, OBS_B, OBS_C, OBS_D, ROUND4_TEMPLATE_DEFS
from scripts.stage4a_runner import (
    ROUND2_TEMPLATES,
    ROUND5_BATCHES,
    ROUND5_TEMPLATES,
    TEMPLATES,
    select_templates,
)

OBSERVATIONS = {"A": OBS_A, "B": OBS_B, "C": OBS_C, "D": OBS_D}

# Strings that must never appear inside a command (anti-leakage).
FORBIDDEN = [
    "benign",
    "container_escape",
    "privilege_abuse",
    "cryptomining",
    "unknown",
    "TMPL",
    "SC-",
    "run-s4a",
    "s4a-",
]


def _bin(length: int) -> str:
    if length <= 80:
        return "30-80"
    if length <= 150:
        return "81-150"
    return "151-250+"


def test_round4_has_32_templates_in_four_batches() -> None:
    assert len(ROUND5_TEMPLATES) == 32
    assert set(ROUND5_BATCHES) == {"a", "b", "c", "d"}
    assert [len(ROUND5_BATCHES[b]) for b in "abcd"] == [10, 10, 10, 2]
    for batch in "abcd":
        assert select_templates(f"5{batch}") == ROUND5_BATCHES[batch]


def test_round4_templates_do_not_overlap_the_executed_ones() -> None:
    executed = {t["template_id"] for t in list(TEMPLATES) + list(ROUND2_TEMPLATES)}
    new = {t["template_id"] for t in ROUND5_TEMPLATES}
    assert not (executed & new)
    assert len(executed) == 23
    assert len(new) == 32


def test_every_local_only_template_carries_exactly_one_observation() -> None:
    """A scenario with no network activity of its own needs one observation."""
    for definition in ROUND4_TEMPLATE_DEFS:
        if definition["own"]:
            continue
        assert definition["obs"] in OBSERVATIONS, definition["template_id"]
        assert definition["command"].endswith(OBSERVATIONS[definition["obs"]])


def test_no_observation_is_duplicated_in_a_command() -> None:
    """A declared observation must appear exactly once, never twice."""
    for definition in ROUND4_TEMPLATE_DEFS:
        command = definition["command"]
        for kind, snippet in OBSERVATIONS.items():
            count = command.count(snippet)
            assert count <= 1, f"{definition['template_id']} repeats observation {kind}"


def test_observations_are_audit_neutral_and_credential_free() -> None:
    for kind, snippet in OBSERVATIONS.items():
        assert "Authorization" not in snippet, f"type {kind} must not carry a credential"
        assert "serviceaccount/token" not in snippet, f"type {kind} must not read a token"


def test_no_command_leaks_a_class_name_or_an_identifier() -> None:
    for template in ROUND5_TEMPLATES:
        command = template["command"]
        for token in FORBIDDEN:
            assert token not in command, f"{template['template_id']} leaks {token!r}"


def test_no_command_uses_the_unsupported_busybox_wget_option() -> None:
    for template in ROUND5_TEMPLATES:
        if "Authorization" in template["command"]:
            assert "-H " not in template["command"], template["template_id"]
            assert "--header=" in template["command"], template["template_id"]


def test_mining_templates_use_the_verified_inner_loop_shape() -> None:
    """D-22 / D-27: the 3000-iteration inner loop of the measured MNR-03."""
    mining = [t for t in ROUND5_TEMPLATES if t["threat_class"] == "cryptomining"]
    assert len(mining) == 7
    for template in mining:
        assert "while [ $j -lt 3000 ]" in template["command"], template["template_id"]
        assert "nc -u -w 1 198.51.100.22" in template["command"], template["template_id"]


def test_sandbox_manifests_pass_the_safety_linter() -> None:
    for template in ROUND5_TEMPLATES:
        spec = template.get("pod_spec")
        if spec is None:
            continue
        assert spec["metadata"]["namespace"] == "sandbox-workloads"
        assert lint_manifest(spec) == [], template["template_id"]


def test_escape_templates_have_no_host_path_and_no_privilege() -> None:
    for template in ROUND5_TEMPLATES:
        spec = template.get("pod_spec")
        if spec is None:
            continue
        assert spec["spec"]["volumes"] == [], template["template_id"]
        assert not spec["spec"]["containers"][0].get("securityContext"), template["template_id"]


def test_expected_falco_rules_are_only_rules_that_can_fire() -> None:
    """No `Launch Sensitive Mount Container` without a hostPath, and no
    `Read Sensitive Host Information Untrusted` without an identity-file read."""
    for template in ROUND5_TEMPLATES:
        rules = template["expect_falco"]
        command = template["command"]
        spec = template.get("pod_spec")
        has_host_path = bool(spec and spec["spec"]["volumes"])
        reads_identity = (
            "/etc/shadow" in command
            or "/etc/passwd" in command
            or "/opt/runtimelens-dummy/etc/shadow" in command
            or "/opt/runtimelens-dummy/etc/passwd" in command
        )
        if "Launch Sensitive Mount Container" in rules:
            assert has_host_path, template["template_id"]
        if "Read Sensitive Host Information Untrusted" in rules:
            assert reads_identity, template["template_id"]


def test_observation_mix_is_present_in_every_named_class() -> None:
    """Each of benign/escape/privilege/unknown carries every observation type."""
    effective: dict[str, set[str]] = {}
    for definition in ROUND4_TEMPLATE_DEFS:
        effective.setdefault(definition["threat_class"], set()).add(
            definition["obs"] or definition["own"]
        )
    for template in list(TEMPLATES) + list(ROUND2_TEMPLATES):
        command = template["command"]
        if "nslookup" in command:
            kind = "A"
        elif "nc -z" in command:
            kind = "B"
        elif "wget" in command:
            kind = "C"
        else:
            kind = "D"
        effective.setdefault(template["threat_class"], set()).add(kind)
    for cls in ("benign", "container_escape", "privilege_abuse", "unknown"):
        assert effective[cls] == {"A", "B", "C", "D"}, (cls, effective[cls])


def test_length_bin_distribution_is_reasonably_balanced() -> None:
    """No class may be confined to a single length bin."""
    bands: dict[str, set[str]] = {}
    for template in ROUND5_TEMPLATES:
        length = len(template["command"]) + 6
        bands.setdefault(template["threat_class"], set()).add(_bin(length))
    for template in list(TEMPLATES) + list(ROUND2_TEMPLATES):
        length = len(template["command"]) + 6
        bands.setdefault(template["threat_class"], set()).add(_bin(length))
    for cls, observed in bands.items():
        assert len(observed) >= 2, (cls, observed)


def test_feature_triples_and_verbs_are_well_formed() -> None:
    for template in ROUND5_TEMPLATES:
        assert len(template["expect_features"]) == 3
        assert set(template["expect_features"]) <= {"T", "F"}
        assert set(template["expect_verbs"]) <= {"get", "create", "list"}
        assert template["expect_hubble_band"] in {"LOW", "MID", "HIGH"}
        assert template["expected_cpu_profile"] in {"low", "burst", "throttled", "high"}


def test_run_ids_are_unique_and_do_not_leak_into_the_command() -> None:
    ids = [t["run_id"] for t in ROUND5_TEMPLATES]
    assert len(set(ids)) == len(ids)
    for template in ROUND5_TEMPLATES:
        assert template["run_id"] not in template["command"]


def test_no_command_contains_a_scenario_or_template_identifier() -> None:
    pattern = re.compile(r"(TMPL-|SC-|run-s4a|s4a-r)")
    for template in ROUND5_TEMPLATES:
        assert not pattern.search(template["command"]), template["template_id"]


def test_observation_type_counts_are_recorded() -> None:
    counts = Counter(definition["obs"] or definition["own"] for definition in ROUND4_TEMPLATE_DEFS)
    assert set(counts) == {"A", "B", "C", "D"}


MIX_HEADER = (
    "| Class | A (DNS) | B (TCP to cluster DNS) | C (API discovery) "
    "| D (UDP to inert IP) | Templates |"
)


def _plan_mix_row(text: str, cls: str) -> list[str]:
    """Return the class row of the plan's observation-mix table."""
    start = text.index(MIX_HEADER)
    marker = f"| `{cls}` |"
    for line in text[start:].splitlines():
        if line.startswith(marker) and line.count("|") == 7:
            return [cell.strip() for cell in line.strip("|").split("|")]
    raise AssertionError(f"no mix row for {cls}")


def test_plan_observation_mix_table_matches_the_runner() -> None:
    """The published per-class observation table must not drift from the runner."""
    from collections import Counter

    from scripts.stage4a_runner import ROUND2_TEMPLATES, TEMPLATES

    effective: dict[str, Counter[str]] = {}
    for definition in ROUND4_TEMPLATE_DEFS:
        effective.setdefault(definition["threat_class"], Counter())[
            definition["obs"] or definition["own"]
        ] += 1
    for template in list(TEMPLATES) + list(ROUND2_TEMPLATES):
        command = template["command"]
        if "nslookup" in command:
            kind = "A"
        elif "nc -z" in command:
            kind = "B"
        elif "wget" in command:
            kind = "C"
        else:
            kind = "D"
        effective.setdefault(template["threat_class"], Counter())[kind] += 1

    plan = pathlib.Path("docs/SCENARIO_PLAN_v2.md").read_text()
    for cls, counts in effective.items():
        row = _plan_mix_row(plan, cls)
        assert row[1] == str(counts["A"]), (cls, row)
        assert row[2] == str(counts["B"]), (cls, row)
        assert row[3] == str(counts["C"]), (cls, row)
        assert row[4] == str(counts["D"]), (cls, row)
        assert row[5] == str(sum(counts.values())), (cls, row)
