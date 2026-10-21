"""Unit tests for the Stage 4a runner template registry (Round 1 and Round 2).

These tests are static and offline: they never touch the cluster. They assert
the structural invariants that the Stage 4a review depends on, in particular
the command-length bins recorded in `docs/SCENARIO_PLAN_v2.md` and the
corrected `Expected Falco Rules` column.
"""

from __future__ import annotations

from typing import Any

import pytest

from scripts.scenario_safety_lint import lint_manifest
from scripts.stage4a_runner import (
    ROUND1_TEMPLATE_IDS,
    ROUND2_TEMPLATE_IDS,
    ROUND2_TEMPLATES,
    SANDBOX_NS,
    TEMPLATES,
    select_templates,
)


def _bin(length: int) -> str:
    if 30 <= length <= 80:
        return "30-80"
    if 81 <= length <= 150:
        return "81-150"
    return "151-250+"


def _all_templates() -> list[dict[str, Any]]:
    return list(TEMPLATES) + list(ROUND2_TEMPLATES)


def test_round_sizes() -> None:
    assert len(TEMPLATES) == 10
    assert len(ROUND2_TEMPLATES) == 13


def test_round2_template_ids_are_exactly_the_reviewed_set() -> None:
    assert (
        frozenset(
            {
                "TMPL-ESC-05",
                "TMPL-ESC-08",
                "TMPL-ESC-09",
                "TMPL-ESC-10",
                "TMPL-PRV-02",
                "TMPL-PRV-04",
                "TMPL-PRV-05",
                "TMPL-BEN-06",
                "TMPL-BEN-14",
                "TMPL-BEN-16",
                "TMPL-BEN-17",
                "TMPL-PRV-07",
                "TMPL-UNK-R2",
            }
        )
        == ROUND2_TEMPLATE_IDS
    )


def test_rounds_do_not_overlap() -> None:
    assert not (ROUND1_TEMPLATE_IDS & ROUND2_TEMPLATE_IDS)


def test_select_templates_returns_the_requested_round() -> None:
    assert len(select_templates("1")) == 10
    assert len(select_templates("2")) == 13
    with pytest.raises(ValueError):
        select_templates("3")


def test_expected_command_lengths_match_the_plan_bins() -> None:
    """Each runner command must land in the bin recorded in the plan registry."""
    expected_bins = {
        "TMPL-ESC-05": "151-250+",
        "TMPL-ESC-08": "30-80",
        "TMPL-ESC-09": "151-250+",
        "TMPL-ESC-10": "81-150",
        "TMPL-PRV-02": "81-150",
        "TMPL-PRV-04": "151-250+",
        "TMPL-PRV-05": "81-150",
        "TMPL-BEN-06": "151-250+",
        "TMPL-BEN-14": "151-250+",
        "TMPL-BEN-16": "151-250+",
        "TMPL-BEN-17": "151-250+",
        "TMPL-PRV-07": "151-250+",
        "TMPL-UNK-R2": "81-150",
    }
    for tpl in ROUND2_TEMPLATES:
        length = len(tpl["command"]) + 6  # `sh -c ` prefix
        assert _bin(length) == expected_bins[tpl["template_id"]], (
            f"{tpl['template_id']}: {length} chars -> {_bin(length)} "
            f"(expected {expected_bins[tpl['template_id']]})"
        )


def test_privileged_only_templates_do_not_expect_sensitive_mount() -> None:
    """A pod with no hostPath volume can never trigger the mount rule."""
    for tpl in _all_templates():
        spec = tpl.get("pod_spec")
        if spec is None:
            continue
        has_host_path = bool(spec["spec"].get("volumes"))
        expects_mount = "Launch Sensitive Mount Container" in tpl["expect_falco"]
        assert expects_mount == has_host_path, (
            f"{tpl['template_id']}: hostPath={has_host_path} "
            f"but expects Sensitive Mount={expects_mount}"
        )


def test_escape_templates_with_expected_sensitive_file_read_exist() -> None:
    """`TMPL-ESC-09` reads the dummy shadow file, so the rule must be expected."""
    esc09 = next(t for t in ROUND2_TEMPLATES if t["template_id"] == "TMPL-ESC-09")
    assert "Read Sensitive Host Information Untrusted" in esc09["expect_falco"]
    assert "Launch Sensitive Mount Container" in esc09["expect_falco"]


def test_sandbox_manifests_pass_the_safety_linter() -> None:
    for tpl in _all_templates():
        spec = tpl.get("pod_spec")
        if spec is None:
            continue
        assert spec["metadata"]["namespace"] == SANDBOX_NS
        assert lint_manifest(spec) == [], f"{tpl['template_id']} failed the safety linter"


def test_feature_expectations_are_binary_triples() -> None:
    for tpl in _all_templates():
        assert len(tpl["expect_features"]) == 3
        assert set(tpl["expect_features"]) <= {"T", "F"}


def test_burst_profile_templates_exist_for_round2() -> None:
    burst = [t["template_id"] for t in ROUND2_TEMPLATES if t["expected_cpu_profile"] == "burst"]
    assert set(burst) == {
        "TMPL-BEN-14",
        "TMPL-BEN-16",
        "TMPL-BEN-17",
        "TMPL-PRV-07",
        "TMPL-UNK-R2",
    }
