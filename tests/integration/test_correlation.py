"""Integration tests for multi-source temporal correlation engine (Ticket 04)."""

from runtimelens.collector.correlation import CorrelationBuffer, redact_secrets_in_text
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)


def _make_sample_falco_event(pod_uid: str, timestamp_iso: str) -> CanonicalEvent:
    return CanonicalEvent(
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name="web-12345",
            pod_uid=pod_uid,
            owner_workload="web",
            container_name="web",
            image_digest="docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="evt-1",
            raw_event_ref="sha256:abc",
        ),
        facts=DeterministicFacts(),
        baseline=BaselineContext(),
        health=TelemetryHealth(),
        event_timestamp=timestamp_iso,
    )


def test_correlation_joins_falco_and_audit_within_30s_window() -> None:
    buffer = CorrelationBuffer(window_seconds=30.0)

    # 1. Ingest Falco event at t=10s
    falco_evt = _make_sample_falco_event(
        pod_uid="uid-web-99", timestamp_iso="2026-10-18T10:00:10.000000Z"
    )
    buffer.ingest_falco_event(falco_evt)
    assert falco_evt.orchestration is None  # Not yet correlated

    # 2. Ingest K8s Audit event at t=15s (within 30s window for same pod UID)
    raw_audit = {
        "verb": "create",
        "stageTimestamp": "2026-10-18T10:00:15.000000Z",
        "objectRef": {
            "resource": "pods",
            "subresource": "exec",
            "namespace": "tenant-a",
            "uid": "uid-web-99",
            "name": "web-12345",
        },
        "user": {"username": "admin-user"},
    }
    buffer.ingest_audit_event(raw_audit)

    # Assert that the Falco event was joined with the orchestration context!
    assert falco_evt.orchestration is not None
    assert falco_evt.orchestration.resource == "pods"
    assert falco_evt.orchestration.subresource == "exec"
    assert falco_evt.orchestration.request_user == "admin-user"


def test_correlation_ignores_events_outside_window() -> None:
    buffer = CorrelationBuffer(window_seconds=30.0)

    falco_evt = _make_sample_falco_event(
        pod_uid="uid-web-99", timestamp_iso="2026-10-18T10:00:00.000000Z"
    )
    buffer.ingest_falco_event(falco_evt)

    # Audit event at t=100s (exceeds 30s window: 100 - 0 = 100 > 30)
    raw_audit = {
        "verb": "get",
        "stageTimestamp": "2026-10-18T10:01:40.000000Z",
        "objectRef": {
            "resource": "pods",
            "namespace": "tenant-a",
            "uid": "uid-web-99",
        },
        "user": {"username": "admin"},
    }
    buffer.ingest_audit_event(raw_audit)

    # Orchestration context remains unjoined
    assert falco_evt.orchestration is None


def test_correlation_secret_redaction() -> None:
    text_with_token = (
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-o7N_qP password=secret12345"
    )
    redacted = redact_secrets_in_text(text_with_token)
    assert "secret12345" not in redacted
    assert "eyJhbGciOi" not in redacted
    assert "[REDACTED]" in redacted


def test_correlation_bounded_buffer_drops_oldest() -> None:
    buffer = CorrelationBuffer(window_seconds=30.0)
    pod_uid = "uid-overflow"

    # Ingest 550 events exceeding MAX_BUFFER_PER_KEY (500)
    for i in range(550):
        evt = _make_sample_falco_event(
            pod_uid=pod_uid, timestamp_iso=f"2026-10-18T10:00:{i % 60:02d}.000Z"
        )
        buffer.ingest_falco_event(evt)

    assert buffer.drop_counter == 50
    assert len(buffer._falco_events["tenant-a:uid-overflow"]) == 500
