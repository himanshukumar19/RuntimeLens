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
    NET_OBSERVATIONS,
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
    assert len(select_templates("3")) == 7
    with pytest.raises(ValueError):
        select_templates("4")


def test_expected_command_lengths_match_the_plan_bins() -> None:
    """Each runner command must land in the bin recorded in the plan registry."""
    expected_bins = {
        "TMPL-ESC-05": "151-250+",
        "TMPL-ESC-08": "81-150",
        "TMPL-ESC-09": "151-250+",
        "TMPL-ESC-10": "81-150",
        "TMPL-PRV-02": "81-150",
        "TMPL-PRV-04": "151-250+",
        "TMPL-PRV-05": "151-250+",
        "TMPL-BEN-06": "151-250+",
        "TMPL-BEN-14": "151-250+",
        "TMPL-BEN-16": "151-250+",
        "TMPL-BEN-17": "151-250+",
        "TMPL-PRV-07": "151-250+",
        "TMPL-UNK-R2": "151-250+",
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
        "TMPL-UNK-R2",
    }


def test_net_observation_vocabulary_is_declared() -> None:
    assert set(NET_OBSERVATIONS) == {"A", "B", "C", "D"}
    for snippet in NET_OBSERVATIONS.values():
        assert snippet.strip().endswith("|| true")


def test_every_local_only_round2_template_carries_a_network_observation() -> None:
    """Decision D-29: a purely local scenario must still produce Hubble flows.

    The per-run gate requires all five sources to be non-empty, so each Round 2
    template that performs no network activity of its own must end with
    exactly one declared benign observation.
    """
    for tpl in ROUND2_TEMPLATES:
        command = tpl["command"]
        has_own_network = any(
            marker in command for marker in ("nslookup", "nc ", "wget", "nc -z", "nc -u")
        )
        carries_observation = any(
            command.endswith(NET_OBSERVATIONS[kind]) for kind in NET_OBSERVATIONS
        )
        assert has_own_network or carries_observation, (
            f"{tpl['template_id']} performs no network activity at all"
        )


def test_observation_mix_is_present_in_every_named_class() -> None:
    """The observation type must not be a class marker (Decision D-29).

    The claim is corpus-level: over the full 55-template registry every one of
    the four named classes carries at least one template of each added
    observation type A, B and C.  The mapping below is the registry recorded in
    `docs/SCENARIO_PLAN_v2.md` section 3.6.3.
    """
    # Template -> observation type, for the templates that receive a declared
    # D-29 observation (marked "+" in the plan registry).
    plan_added_observation = {
        # benign
        "TMPL-BEN-02": "B",
        "TMPL-BEN-03": "A",
        "TMPL-BEN-08": "C",
        "TMPL-BEN-10": "A",
        "TMPL-BEN-14": "B",
        "TMPL-BEN-15": "C",
        "TMPL-BEN-16": "C",
        "TMPL-BEN-17": "A",
        # container_escape
        "TMPL-ESC-01": "B",
        "TMPL-ESC-02": "A",
        "TMPL-ESC-05": "A",
        "TMPL-ESC-07": "C",
        "TMPL-ESC-08": "B",
        "TMPL-ESC-09": "C",
        # privilege_abuse
        "TMPL-PRV-06": "B",
        "TMPL-PRV-08": "A",
        # unknown
        "TMPL-UNK-04": "B",
        "TMPL-UNK-07": "A",
        "TMPL-UNK-R1": "C",
        "TMPL-UNK-R2": "A",
        "TMPL-UNK-R4": "B",
    }
    # Threat class of every template referenced above, from the plan registry.
    class_of = {tpl["template_id"]: tpl["threat_class"] for tpl in ROUND2_TEMPLATES}
    class_of.update(
        {
            "TMPL-BEN-01": "benign",
            "TMPL-BEN-02": "benign",
            "TMPL-BEN-03": "benign",
            "TMPL-BEN-04": "benign",
            "TMPL-BEN-05": "benign",
            "TMPL-BEN-07": "benign",
            "TMPL-BEN-08": "benign",
            "TMPL-BEN-09": "benign",
            "TMPL-BEN-10": "benign",
            "TMPL-BEN-11": "benign",
            "TMPL-BEN-12": "benign",
            "TMPL-BEN-13": "benign",
            "TMPL-BEN-15": "benign",
            "TMPL-BEN-18": "benign",
            "TMPL-BEN-19": "benign",
            "TMPL-BEN-20": "benign",
            "TMPL-BEN-21": "benign",
            "TMPL-ESC-01": "container_escape",
            "TMPL-ESC-02": "container_escape",
            "TMPL-ESC-03": "container_escape",
            "TMPL-ESC-04": "container_escape",
            "TMPL-ESC-06": "container_escape",
            "TMPL-ESC-07": "container_escape",
            "TMPL-PRV-01": "privilege_abuse",
            "TMPL-PRV-03": "privilege_abuse",
            "TMPL-PRV-06": "privilege_abuse",
            "TMPL-PRV-08": "privilege_abuse",
            "TMPL-UNK-03": "unknown",
            "TMPL-UNK-04": "unknown",
            "TMPL-UNK-05": "unknown",
            "TMPL-UNK-07": "unknown",
            "TMPL-UNK-R1": "unknown",
            "TMPL-UNK-R3": "unknown",
            "TMPL-UNK-R4": "unknown",
        }
    )
    # Templates whose own scenario already provides the observation.
    plan_own_observation = {
        "TMPL-BEN-01": "B",
        "TMPL-BEN-04": "D",
        "TMPL-BEN-05": "B",
        "TMPL-BEN-06": "C",
        "TMPL-BEN-07": "B",
        "TMPL-BEN-09": "B",
        "TMPL-BEN-11": "C",
        "TMPL-BEN-12": "A",
        "TMPL-BEN-13": "B",
        "TMPL-BEN-18": "C",
        "TMPL-BEN-19": "B",
        "TMPL-BEN-20": "B",
        "TMPL-BEN-21": "B",
        "TMPL-ESC-03": "B",
        "TMPL-ESC-04": "D",
        "TMPL-ESC-06": "B",
        "TMPL-ESC-10": "B",
        "TMPL-PRV-01": "C",
        "TMPL-PRV-02": "C",
        "TMPL-PRV-03": "C",
        "TMPL-PRV-04": "C",
        "TMPL-PRV-05": "C",
        "TMPL-PRV-07": "C",
        "TMPL-UNK-03": "D",
        "TMPL-UNK-05": "B",
        "TMPL-UNK-R3": "B",
    }
    per_class: dict[str, set[str]] = {}
    for tid, kind in {**plan_own_observation, **plan_added_observation}.items():
        cls = class_of.get(tid)
        if cls is None:
            continue
        per_class.setdefault(cls, set()).add(kind)
    for cls in ("benign", "container_escape", "privilege_abuse", "unknown"):
        assert {"A", "B", "C"} <= per_class.get(cls, set()), (
            f"{cls} cannot carry {sorted({'A', 'B', 'C'} - per_class.get(cls, set()))}"
        )


def test_observations_are_audit_neutral_and_credential_free() -> None:
    """Type C must not present a credential (it would add an audit event)."""
    for kind, snippet in NET_OBSERVATIONS.items():
        assert "Authorization" not in snippet, f"type {kind} must not carry a credential"
        assert "serviceaccount/token" not in snippet, f"type {kind} must not read a token"


def test_no_busybox_incompatible_wget_options() -> None:
    """BusyBox wget supports only `--header`, never the short `-H` option.

    Round 2 attempt 2 failed on `TMPL-PRV-04` with zero Hubble flows and no
    audit event: the command used `-H "Authorization: Bearer $T"`, and BusyBox
    aborted with "wget: unrecognized option: H" *before* any network request
    was made.  This regression test pins the option form for every template.
    """
    for tpl in _all_templates():
        command = tpl["command"]
        if "wget" not in command:
            continue
        assert "-H " not in command, (
            f"{tpl['template_id']}: BusyBox wget does not support the -H option"
        )
        assert "wget" in command


def test_service_account_templates_use_the_verified_header_form() -> None:
    """Every ServiceAccount-authenticated request must use `--header=`."""
    sa_templates = [
        t
        for t in _all_templates()
        if "serviceaccount/token" in t["command"] and "wget" in t["command"]
    ]
    assert len(sa_templates) >= 4
    for tpl in sa_templates:
        assert '--header="Authorization: Bearer $T"' in tpl["command"], (
            f"{tpl['template_id']}: must use the BusyBox-compatible --header= form"
        )
