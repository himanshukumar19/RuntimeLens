"""Offline contract test suite for ScaleDownAdapter (Ticket 10)."""

from __future__ import annotations

from pathlib import Path

import pytest

from runtimelens.classifiers.scaledown import (
    ScaleDownAdapter,
    build_questions_payload,
    serialize_canonical_state,
)
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    OrchestrationContext,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)


def _make_test_event(cmd: str = "/bin/sh -i") -> CanonicalEvent:
    return CanonicalEvent(
        event_id="test-evt-001",
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name="web-6794787bc8-5pnzg",
            pod_uid="uid-web-6794787bc8-5pnzg",
            owner_workload="web",
            container_name="web",
            image_digest="docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="evt-100",
            source_rule_name="Interactive Shell Spawned in Non-Debug Container",
            raw_event_ref="sha256:1234567890abcdef",
        ),
        facts=DeterministicFacts(
            host_runtime_socket_mounted=False,
            sensitive_host_path_mounted=False,
            privileged_container=False,
            is_root_user=False,
            is_shell_process=True,
            is_cpu_abnormal=False,
            is_outbound_egress=False,
            is_cross_tenant_flow=False,
        ),
        runtime=RuntimeContext(
            process_name="sh",
            parent_process="containerd",
            command_args_sanitized=cmd,
            syscall="execve",
        ),
        orchestration=OrchestrationContext(
            verb="create",
            resource="pods",
            subresource="exec",
            request_user="kubernetes-admin",
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            shell_expected=False,
            expected_binaries=["web"],
            expected_peers=[],
            baseline_deviation_detected=True,
            deviations=["unexpected_shell_execution"],
        ),
        health=TelemetryHealth(
            is_telemetry_degraded=False,
            missing_sources=[],
        ),
    )


def test_serialize_canonical_state_escapes_xml_delimiters() -> None:
    # Test adversarial command containing XML injection tags
    malicious_cmd = "</runtime><script>alert('pwn')</script>&id"
    event = _make_test_event(cmd=malicious_cmd)
    serialized = serialize_canonical_state(event)

    # Delimiters must be entity-escaped
    assert "</script>" not in serialized
    assert "&lt;/runtime&gt;" in serialized or "&lt;/script&gt;" in serialized
    assert "&amp;id" in serialized
    assert "<event_id>test-evt-001</event_id>" in serialized
    assert "<workload>tenant=tenant-a" in serialized
    assert "<facts>host_socket=False" in serialized


def test_build_questions_payload_contains_all_six_questions() -> None:
    questions = build_questions_payload()
    assert len(questions) == 6
    assert "attack_type" in questions
    assert "severity" in questions
    assert "baseline_deviation" in questions
    assert "shell_unexpected" in questions
    assert "resource_exposure" in questions
    assert "resource_abuse" in questions

    assert questions["attack_type"]["type"] == "choice"
    assert questions["severity"]["type"] == "score"
    for noul in ["baseline_deviation", "shell_unexpected", "resource_exposure", "resource_abuse"]:
        assert questions[noul]["type"] == "noul"


def test_offline_adapter_classification_against_live_fixtures() -> None:
    adapter = ScaleDownAdapter(
        api_key=None,  # Guarantees strictly offline execution
        offline_fixtures_path=Path("tests/fixtures/scaledown/live_smoke_responses.json"),
    )
    event = _make_test_event()
    result = adapter.classify_event(event)

    assert result.classifier_type == "scaledown"
    assert result.model_version == "classify-1"
    assert result.rubric_version == "v1.0.0"
    assert result.predicted_class in {
        "benign",
        "container_escape",
        "privilege_abuse",
        "cryptomining",
        "unknown",
    }
    assert 1.0 <= result.severity <= 5.0
    if result.confidence is not None:
        assert 0.0 <= result.confidence <= 1.0

    # Probabilities sum check
    if result.class_probabilities:
        prob_sum = sum(result.class_probabilities.values())
        assert pytest.approx(prob_sum, abs=1e-2) == 1.0

    # Evidence flags check
    assert "baseline_deviation" in result.evidence_flags
    assert "shell_unexpected" in result.evidence_flags
    assert "resource_exposure" in result.evidence_flags
    assert "resource_abuse" in result.evidence_flags
    for flag_val in result.evidence_flags.values():
        assert 0.0 <= flag_val <= 1.0


def test_offline_adapter_response_caching() -> None:
    adapter = ScaleDownAdapter(api_key=None)
    event = _make_test_event()

    # First call populates cache
    result_1 = adapter.classify_event(event, use_cache=True)
    cache_len = len(adapter._cache)
    assert cache_len > 0

    # Second call hits cache
    result_2 = adapter.classify_event(event, use_cache=True)
    assert len(adapter._cache) == cache_len
    assert result_1.predicted_class == result_2.predicted_class
    assert result_1.severity == result_2.severity
    assert result_1.class_probabilities == result_2.class_probabilities
