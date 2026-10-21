"""Unit tests for the Decision D-28 classifier feature-set exclusion.

`command_length` is EXCLUDED from the classifier feature set because the
master template registry proves it is a near-perfect class marker for this
dataset (every `privilege_abuse` template is necessarily in the longest
command-length bin). It is retained only as a diagnostic.
"""

from __future__ import annotations

import json
from pathlib import Path

from runtimelens.features.extractor import (
    EXCLUDED_DIAGNOSTIC_FEATURES,
    FEATURE_NAMES,
    extract_command_length,
    extract_features_from_run_dir,
)


def _write_run(tmp_path: Path, run_id: str, cmdline: str) -> Path:
    run_dir = tmp_path / run_id
    for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
        (run_dir / src).mkdir(parents=True, exist_ok=True)
    with open(run_dir / "falco" / "events.jsonl", "w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "rule": "Interactive Shell Spawned in Non-Debug Container",
                    "output_fields": {
                        "proc.cmdline": cmdline,
                        "proc.name": "sh",
                        "k8s.pod.name": "web-01",
                        "user.name": "root",
                    },
                }
            )
            + "\n"
        )
    with open(run_dir / "audit" / "events.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps({"verb": "get", "objectRef": {"resource": "pods"}}) + "\n")
    with open(run_dir / "hubble" / "flows.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps({"flow": {"verdict": "FORWARDED"}}) + "\n")
    with open(run_dir / "prometheus" / "metrics.json", "w", encoding="utf-8") as f:
        json.dump({"pod_stats": []}, f)
    with open(run_dir / "trivy" / "report.json", "w", encoding="utf-8") as f:
        json.dump({"SchemaVersion": 2, "Results": []}, f)
    return run_dir


def test_classifier_feature_set_has_18_features() -> None:
    assert len(FEATURE_NAMES) == 18


def test_command_length_is_not_in_classifier_feature_set() -> None:
    assert "command_length" not in FEATURE_NAMES


def test_excluded_diagnostic_features_declares_command_length() -> None:
    assert "command_length" in EXCLUDED_DIAGNOSTIC_FEATURES
    for name in EXCLUDED_DIAGNOSTIC_FEATURES:
        assert name not in FEATURE_NAMES


def test_extracted_vector_length_matches_feature_set(tmp_path: Path) -> None:
    run_dir = _write_run(tmp_path, "run-001", "sh -c " + "x" * 200)
    vec = extract_features_from_run_dir(run_dir)
    assert len(vec) == len(FEATURE_NAMES) == 18


def test_command_length_remains_available_as_diagnostic(tmp_path: Path) -> None:
    """The diagnostic helper must still report the raw command length."""
    cmd = "sh -c " + "x" * 200
    run_dir = _write_run(tmp_path, "run-002", cmd)
    assert extract_command_length(run_dir) == float(len(cmd))


def test_feature_indices_after_removal_are_stable(tmp_path: Path) -> None:
    """The features that used to follow `command_length` shift down by one.

    `is_cpu_abnormal` was index 07 and is now index 06; `orch_verb_get_secret`
    was index 18 and is now index 17.
    """
    assert FEATURE_NAMES[6] == "is_cpu_abnormal"
    assert FEATURE_NAMES[7] == "cpu_usage_mcores"
    assert FEATURE_NAMES[16] == "orch_verb_exec"
    assert FEATURE_NAMES[17] == "orch_verb_get_secret"


def test_scaldown_state_carries_no_command_length_field() -> None:
    """The ScaleDown state must not expose a command-length number.

    The state serializer never emitted a length field, but the exclusion must
    be enforced by a regression test rather than left to chance.
    """
    from runtimelens.classifiers.scaledown import serialize_canonical_state
    from runtimelens.models.event import (
        BaselineContext,
        CanonicalEvent,
        DeterministicFacts,
        RuntimeContext,
        TelemetryHealth,
        TelemetrySourceRef,
        WorkloadIdentity,
    )

    event = CanonicalEvent(
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name="web-01",
            pod_uid="uid-1",
            owner_workload="web",
            container_name="web",
            image_digest="sha256:deadbeef",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="e-1",
            raw_event_ref="falco/events.jsonl#1",
            source_rule_name="Interactive Shell Spawned in Non-Debug Container",
        ),
        facts=DeterministicFacts(),
        runtime=RuntimeContext(
            process_name="sh",
            command_args_sanitized="sh -c " + "x" * 120,
            syscall="execve",
        ),
        baseline=BaselineContext(),
        health=TelemetryHealth(),
    )
    state = serialize_canonical_state(event)
    lowered = state.lower()
    assert "command_length" not in lowered
    assert "raw_length" not in lowered
    assert "cmd_len" not in lowered
    assert "length=" not in lowered
