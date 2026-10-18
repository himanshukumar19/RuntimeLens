"""Unit tests for declarative YAML baseline loader and drift comparator (Ticket 05)."""

from pathlib import Path

from runtimelens.baseline.comparator import compare_against_baseline
from runtimelens.baseline.loader import BaselineStore
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)


def _make_event(workload: str, process_name: str, is_shell: bool = False) -> CanonicalEvent:
    return CanonicalEvent(
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name=f"{workload}-12345",
            pod_uid="uid-101",
            owner_workload=workload,
            container_name=workload,
            image_digest="alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="evt-01",
            raw_event_ref="sha256:abc",
        ),
        facts=DeterministicFacts(
            is_shell_process=is_shell,
        ),
        runtime=RuntimeContext(
            process_name=process_name,
            command_args_sanitized=process_name,
            syscall="execve",
        ),
        baseline=BaselineContext(),
        health=TelemetryHealth(),
    )


def test_baseline_store_loads_four_lab_profiles() -> None:
    store = BaselineStore(baselines_dir=Path("baselines"))
    for workload in ["web", "api", "database", "payment-style"]:
        profile = store.get_baseline(workload)
        assert profile is not None, f"Missing baseline for {workload}"
        assert profile.metadata.workload == workload
        assert profile.runtime.shell_allowed is False
        assert len(profile.runtime.allowed_binaries) > 0


def test_unauthorized_binary_triggers_drift_detection() -> None:
    store = BaselineStore(baselines_dir=Path("baselines"))
    payment_baseline = store.get_baseline("payment-style")
    assert payment_baseline is not None

    # payment-style only allows /usr/local/bin/payment-worker
    # An event with unauthorized binary 'curl' or 'nc' MUST trigger deviation
    event = _make_event("payment-style", "curl")
    result = compare_against_baseline(event, payment_baseline)

    assert result.baseline_deviation_detected is True
    assert any("unauthorized_binary:curl" in dev for dev in result.deviations)


def test_authorized_binary_produces_no_drift() -> None:
    store = BaselineStore(baselines_dir=Path("baselines"))
    web_baseline = store.get_baseline("web")
    assert web_baseline is not None

    # web allows /usr/sbin/nginx and /bin/nc
    event = _make_event("web", "nginx")
    result = compare_against_baseline(event, web_baseline)

    assert result.baseline_deviation_detected is False
    assert len(result.deviations) == 0


def test_unexpected_shell_triggers_drift() -> None:
    store = BaselineStore(baselines_dir=Path("baselines"))
    web_baseline = store.get_baseline("web")
    assert web_baseline is not None

    # /bin/sh in web (shell_allowed=False)
    event = _make_event("web", "sh", is_shell=True)
    result = compare_against_baseline(event, web_baseline)

    assert result.baseline_deviation_detected is True
    assert "unexpected_shell_execution" in result.deviations


def test_missing_baseline_flags_deviation() -> None:
    event = _make_event("unregistered-workload", "app")
    result = compare_against_baseline(event, None)

    assert result.baseline_deviation_detected is True
    assert "workload_baseline_missing" in result.deviations
