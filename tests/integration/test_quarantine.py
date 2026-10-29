"""Integration test suite for SRE response controller and quarantine mechanics (Ticket 13b)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from runtimelens.controller.quarantine import (
    MockKubernetesClient,
    QuarantineController,
)
from runtimelens.models.decision import PolicyDecision
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)


def _make_sample_event(
    namespace: str = "tenant-a",
    pod_name: str = "payment-service-8f4b",
    pod_uid: str = "uid-payment-1234",
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-quarantine-001",
        workload=WorkloadIdentity(
            tenant=namespace,
            namespace=namespace,
            pod_name=pod_name,
            pod_uid=pod_uid,
            owner_workload="payment-service",
            container_name="payment",
            image_digest="docker.io/library/payment@sha256:1111222233334444555566667777888899990000111122223333444455556666",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="src-evt-001",
            source_rule_name="Suspicious High Port Egress",
            raw_event_ref="sha256:abcd",
        ),
        facts=DeterministicFacts(
            host_runtime_socket_mounted=False,
            sensitive_host_path_mounted=False,
        ),
        runtime=RuntimeContext(
            process_name="miner",
            parent_process="sh",
            command_args_sanitized="./miner --pool 10.0.0.1",
            syscall="connect",
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            is_baseline_stale=False,
            shell_expected=False,
            expected_binaries=["payment-bin"],
            expected_peers=["database.tenant-a.svc.cluster.local"],
            baseline_deviation_detected=True,
            deviations=["unexpected_binary", "unexpected_outbound_egress"],
        ),
        health=TelemetryHealth(is_telemetry_degraded=False),
    )


def test_dry_run_quarantine(tmp_path: Path) -> None:
    audit_file = tmp_path / "quarantine_audit.jsonl"
    mock_client = MockKubernetesClient(
        initial_pods={"tenant-a/payment-service-8f4b": {"app": "payment"}}
    )
    controller = QuarantineController(k8s_client=mock_client, audit_file=audit_file)

    event = _make_sample_event()
    decision = PolicyDecision(
        action="quarantine",
        reason_codes=["HIGH_SEVERITY_CONTAINMENT"],
        policy_version="v1.0.0",
        dry_run=True,
        quarantine_labels={"quarantine": "true"},
        auto_rollback_ttl_seconds=900,
    )

    record = controller.apply_decision(decision, event, incident_id="inc-999")
    assert record is not None
    assert record.status == "active"
    assert record.dry_run is True
    assert record.diff == {"metadata": {"labels": {"quarantine": "true"}}}
    assert record.namespace == "tenant-a"
    assert record.pod_name == "payment-service-8f4b"

    # In dry-run mode, client patch must NOT be invoked
    assert len(mock_client.patch_log) == 0
    assert mock_client.get_pod_labels("tenant-a", "payment-service-8f4b") == {"app": "payment"}

    # Audit record must be persisted
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["action_id"] == record.action_id
    assert data["dry_run"] is True


def test_live_quarantine(tmp_path: Path) -> None:
    mock_client = MockKubernetesClient(
        initial_pods={"tenant-a/payment-service-8f4b": {"app": "payment"}}
    )
    controller = QuarantineController(k8s_client=mock_client)

    event = _make_sample_event()
    decision = PolicyDecision(
        action="quarantine",
        reason_codes=["HIGH_SEVERITY_CONTAINMENT"],
        policy_version="v1.0.0",
        dry_run=False,  # Live execution
        quarantine_labels={"quarantine": "true"},
        auto_rollback_ttl_seconds=900,
    )

    record = controller.apply_decision(decision, event, incident_id="inc-live-1")
    assert record is not None
    assert record.status == "active"
    assert record.dry_run is False

    # In live mode, client patch MUST be called and label applied
    assert len(mock_client.patch_log) == 1
    labels = mock_client.get_pod_labels("tenant-a", "payment-service-8f4b")
    assert labels.get("quarantine") == "true"
    assert labels.get("app") == "payment"


def test_ttl_auto_rollback(tmp_path: Path) -> None:
    mock_client = MockKubernetesClient(
        initial_pods={"tenant-a/payment-service-8f4b": {"app": "payment"}}
    )
    controller = QuarantineController(k8s_client=mock_client)

    event = _make_sample_event()
    decision = PolicyDecision(
        action="quarantine",
        dry_run=False,
        auto_rollback_ttl_seconds=900,  # 15 minutes
    )

    record = controller.apply_decision(decision, event)
    assert record is not None
    pod_labels = mock_client.get_pod_labels("tenant-a", "payment-service-8f4b")
    assert pod_labels.get("quarantine") == "true"

    # Before TTL expires (e.g. +10 minutes): reconcile does nothing
    t_10m = datetime.now(UTC) + timedelta(minutes=10)
    reconciled_early = controller.reconcile_expired(current_time=t_10m)
    assert len(reconciled_early) == 0
    pod_labels_early = mock_client.get_pod_labels("tenant-a", "payment-service-8f4b")
    assert pod_labels_early.get("quarantine") == "true"

    # After TTL expires (e.g. +16 minutes): reconcile triggers rollback
    t_16m = datetime.now(UTC) + timedelta(minutes=16)
    reconciled = controller.reconcile_expired(current_time=t_16m)
    assert len(reconciled) == 1
    assert reconciled[0].action_id == record.action_id
    assert reconciled[0].status == "rolled_back"
    assert reconciled[0].rollback_at is not None

    # Verify quarantine label has been stripped from pod
    current_labels = mock_client.get_pod_labels("tenant-a", "payment-service-8f4b")
    assert "quarantine" not in current_labels
    assert current_labels.get("app") == "payment"


def test_analyst_promotion_prevents_rollback() -> None:
    mock_client = MockKubernetesClient(initial_pods={"tenant-b/api-gateway": {"app": "api"}})
    controller = QuarantineController(k8s_client=mock_client)

    record = controller.quarantine_pod(
        namespace="tenant-b",
        pod_name="api-gateway",
        pod_uid="uid-api",
        incident_id="inc-api",
        event_id="evt-api",
        ttl_seconds=600,
        dry_run=False,
    )
    assert record.status == "active"

    # Analyst confirms incident and promotes quarantine
    promoted = controller.promote_quarantine(record.action_id, reason="Confirmed CVE exploit")
    assert promoted.status == "promoted"

    # Past TTL expiration, reconcile should NOT roll back promoted action
    t_past = datetime.now(UTC) + timedelta(minutes=20)
    reconciled = controller.reconcile_expired(current_time=t_past)
    assert len(reconciled) == 0

    # Pod must stay quarantined
    assert mock_client.get_pod_labels("tenant-b", "api-gateway").get("quarantine") == "true"


def test_forbidden_system_namespace_refusal() -> None:
    mock_client = MockKubernetesClient()
    controller = QuarantineController(k8s_client=mock_client)

    # Attempt to quarantine core system component
    record = controller.quarantine_pod(
        namespace="kube-system",
        pod_name="coredns-5e3a",
        pod_uid="uid-coredns",
        incident_id="inc-sec",
        event_id="evt-sec",
        dry_run=False,
    )
    assert record.status == "failed"
    assert "ALLOWED_QUARANTINE_NAMESPACES" in (record.error_message or "")
    assert len(mock_client.patch_log) == 0


def test_zero_delete_rbac_manifest_invariant() -> None:
    """SRE Security Audit: Assert RBAC manifest contains zero pod deletion verbs."""
    rbac_file = Path("lab/rbac/response-controller-rbac.yaml")
    assert rbac_file.exists(), f"Missing required RBAC manifest at {rbac_file}"

    manifests = list(yaml.safe_load_all(rbac_file.read_text(encoding="utf-8")))
    assert len(manifests) >= 4, "Expected ServiceAccount and at least 3 Role/RoleBinding manifests"

    for doc in manifests:
        if not doc or not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        if kind in ("Role", "ClusterRole"):
            rules: list[dict[str, Any]] = doc.get("rules", [])
            for rule in rules:
                verbs: list[str] = rule.get("verbs", [])
                assert "delete" not in verbs, (
                    f"FORBIDDEN 'delete' verb found in {doc.get('metadata')}"
                )
                assert "deletecollection" not in verbs, (
                    f"FORBIDDEN 'deletecollection' verb found in {doc.get('metadata')}"
                )
                assert "*" not in verbs, (
                    f"FORBIDDEN wildcard '*' verb found in {doc.get('metadata')}"
                )
                # Assert exactly permitted verbs
                for verb in verbs:
                    assert verb in {"get", "list", "watch", "patch"}


def test_controller_rejects_delete_capable_client() -> None:
    """Safety guardrail: Controller must refuse to initialize if client allows delete."""

    class InsecureClient(MockKubernetesClient):
        def can_delete_pods(self) -> bool:
            return True

    with pytest.raises(PermissionError, match="CRITICAL SRE SAFETY VIOLATION"):
        QuarantineController(k8s_client=InsecureClient())


def test_idempotent_reconciliation() -> None:
    """Principle-make-operations-idempotent: Repeated reconcile calls converge stably."""
    mock_client = MockKubernetesClient(initial_pods={"tenant-c/db-cluster-0": {"app": "db"}})
    controller = QuarantineController(k8s_client=mock_client)

    controller.quarantine_pod(
        namespace="tenant-c",
        pod_name="db-cluster-0",
        pod_uid="uid-db",
        incident_id="inc-db",
        event_id="evt-db",
        ttl_seconds=300,
        dry_run=False,
    )

    t_expired = datetime.now(UTC) + timedelta(minutes=10)
    first_run = controller.reconcile_expired(current_time=t_expired)
    assert len(first_run) == 1
    assert first_run[0].status == "rolled_back"

    # Second call at same time produces zero new rollbacks and doesn't re-patch
    second_run = controller.reconcile_expired(current_time=t_expired)
    assert len(second_run) == 0
    assert "quarantine" not in mock_client.get_pod_labels("tenant-c", "db-cluster-0")
