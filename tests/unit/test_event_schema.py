"""Tests for CanonicalEvent schema conformance and strict validation."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)


def _make_valid_event() -> CanonicalEvent:
    return CanonicalEvent(
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name="web-12345-abcde",
            pod_uid="uid-web-12345",
            owner_workload="web",
            container_name="web",
            container_id="1234567890ab",
            image_digest="alpine:3.19",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="evt-101",
            raw_event_ref="sha256:abcdef",
        ),
        facts=DeterministicFacts(
            host_runtime_socket_mounted=False,
            sensitive_host_path_mounted=False,
            privileged_container=False,
            is_root_user=False,
            is_shell_process=False,
            has_critical_vulnerability=False,
            cpu_usage_mcores=10.0,
            is_cpu_abnormal=False,
            is_outbound_egress=False,
            is_cross_tenant_flow=False,
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            is_baseline_stale=False,
            shell_expected=False,
            expected_binaries=["web"],
            expected_peers=[],
            baseline_deviation_detected=False,
            deviations=[],
        ),
        health=TelemetryHealth(
            is_telemetry_degraded=False,
            missing_sources=[],
        ),
    )


def test_valid_event_creation() -> None:
    event = _make_valid_event()
    assert event.schema_version == "1.0.0"
    assert event.workload.tenant == "tenant-a"
    assert not event.facts.is_root_user


def test_schema_forbids_unknown_fields() -> None:
    event_dict = _make_valid_event().model_dump()
    event_dict["unexpected_rogue_field"] = "malicious_payload"

    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(event_dict)


def test_workload_forbids_unknown_fields() -> None:
    event_dict = _make_valid_event().model_dump()
    event_dict["workload"]["rogue_field"] = "bad"

    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(event_dict)


def test_matches_json_schema_definition() -> None:
    schema_path = Path("schemas/event.schema.json")
    if not schema_path.exists():
        pytest.skip("schemas/event.schema.json not present")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert "event_id" in schema["required"]
    assert "schema_version" in schema["required"]
