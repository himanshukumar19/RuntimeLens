"""Exhaustive unit test suite for pure policy engine (Decision D-13, D-19, Ticket 13a)."""

from __future__ import annotations

from runtimelens.models.decision import ClassificationResult
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)
from runtimelens.policy.engine import evaluate_policy


def _make_base_event(
    namespace: str = "tenant-a",
    is_degraded: bool = False,
    is_stale: bool = False,
    host_sock: bool = False,
    sensitive_path: bool = False,
    deviations: list[str] | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-policy-001",
        workload=WorkloadIdentity(
            tenant="tenant-a" if namespace.startswith("tenant-") else "system",
            namespace=namespace,
            pod_name="test-pod-01",
            pod_uid="uid-test-01",
            owner_workload="test-workload",
            container_name="app",
            image_digest="docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="src-001",
            source_rule_name="Test Rule",
            raw_event_ref="sha256:dummy",
        ),
        facts=DeterministicFacts(
            host_runtime_socket_mounted=host_sock,
            sensitive_host_path_mounted=sensitive_path,
        ),
        runtime=RuntimeContext(
            process_name="app",
            parent_process="init",
            command_args_sanitized="app run",
            syscall="execve",
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            is_baseline_stale=is_stale,
            shell_expected=False,
            expected_binaries=["app"],
            expected_peers=[],
            baseline_deviation_detected=bool(deviations),
            deviations=deviations or [],
        ),
        health=TelemetryHealth(
            is_telemetry_degraded=is_degraded,
            missing_sources=["k8s_audit"] if is_degraded else [],
        ),
    )


# ---------------------------------------------------------------------------
# 1. Critical Safety Overrides Tests
# ---------------------------------------------------------------------------


def test_override_telemetry_degraded_forces_human_review() -> None:
    event = _make_base_event(is_degraded=True)
    classification = ClassificationResult(
        predicted_class="container_escape",
        severity=5.0,
        confidence=0.95,
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "ERR_TELEMETRY_DEGRADED" in decision.reason_codes
    assert decision.dry_run is True


def test_override_model_degraded_forces_human_review() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="privilege_abuse",
        severity=4.0,
        confidence=0.85,
        degraded_mode=True,
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "ERR_MODEL_DEGRADED" in decision.reason_codes


def test_override_stale_baseline_forces_human_review() -> None:
    event = _make_base_event(is_stale=True)
    classification = ClassificationResult(
        predicted_class="cryptomining",
        severity=4.0,
        confidence=0.90,
        evidence_flags={"resource_abuse": 0.8},
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "ERR_BASELINE_STALE" in decision.reason_codes


def test_override_critical_fact_mismatch_benign_with_host_socket() -> None:
    event = _make_base_event(host_sock=True)
    classification = ClassificationResult(
        predicted_class="benign",
        severity=1.0,
        confidence=0.95,
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "OVERRIDE_CRITICAL_FACT_MISMATCH" in decision.reason_codes
    assert "OVERRIDE_HOST_PATH_MOUNTED" in decision.reason_codes


# ---------------------------------------------------------------------------
# 2. Choice-Noul Conflict Matrix Tests
# ---------------------------------------------------------------------------


def test_conflict_unknown_class_forces_human_review() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="unknown",
        severity=3.0,
        confidence=0.50,
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "CLASS_UNKNOWN" in decision.reason_codes


def test_conflict_benign_with_high_baseline_deviation() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="benign",
        severity=1.5,
        confidence=0.90,
        evidence_flags={"baseline_deviation": 0.85},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "CONFLICT_BENIGN_WITH_EVIDENCE" in decision.reason_codes


def test_conflict_escape_without_corroborating_evidence() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="container_escape",
        severity=4.5,
        confidence=0.85,
        evidence_flags={"resource_exposure": 0.1, "shell_unexpected": 0.1},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "CONFLICT_ESCAPE_WITHOUT_EVIDENCE" in decision.reason_codes


def test_conflict_privilege_abuse_without_deviation() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="privilege_abuse",
        severity=3.5,
        confidence=0.85,
        evidence_flags={"baseline_deviation": 0.1},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "CONFLICT_PRIVILEGE_WITHOUT_DEVIATION" in decision.reason_codes


def test_conflict_cryptomining_without_resource_abuse() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="cryptomining",
        severity=4.0,
        confidence=0.85,
        evidence_flags={"resource_abuse": 0.15},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "CONFLICT_MINING_WITHOUT_RESOURCE_ABUSE" in decision.reason_codes


# ---------------------------------------------------------------------------
# 3. Confidence Gates & Action Tier Tests
# ---------------------------------------------------------------------------


def test_confidence_gate_below_threshold_routes_to_human_review() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="privilege_abuse",
        severity=3.8,
        confidence=0.65,  # Below 0.70 default threshold
        evidence_flags={"baseline_deviation": 0.9},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "human_review"
    assert "LOW_CONFIDENCE_GATE" in decision.reason_codes


def test_uncalibrated_heuristic_confidence_none_bypasses_gate() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="privilege_abuse",
        severity=3.8,
        confidence=None,  # Rule-based uncalibrated heuristic
        evidence_flags={"baseline_deviation": 1.0},
        classifier_type="rules",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "alert"
    assert "LOW_CONFIDENCE_GATE" not in decision.reason_codes


def test_routine_benign_without_conflicts_logs() -> None:
    event = _make_base_event()
    classification = ClassificationResult(
        predicted_class="benign",
        severity=1.0,
        confidence=0.92,
        evidence_flags={"baseline_deviation": 0.05, "resource_exposure": 0.0},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "log"
    assert "BENIGN_VERIFIED" in decision.reason_codes


def test_high_severity_tenant_workload_triggers_quarantine() -> None:
    event = _make_base_event(namespace="tenant-a")
    classification = ClassificationResult(
        predicted_class="container_escape",
        severity=4.8,
        confidence=0.88,
        evidence_flags={"resource_exposure": 0.95, "shell_unexpected": 0.9},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "quarantine"
    assert decision.dry_run is True
    assert decision.quarantine_labels == {"quarantine": "true"}
    assert decision.auto_rollback_ttl_seconds == 900
    assert "HIGH_SEVERITY_CONTAINMENT" in decision.reason_codes


def test_high_severity_system_namespace_blocks_quarantine_and_alerts() -> None:
    event = _make_base_event(namespace="kube-system")
    classification = ClassificationResult(
        predicted_class="container_escape",
        severity=4.8,
        confidence=0.88,
        evidence_flags={"resource_exposure": 0.95, "shell_unexpected": 0.9},
        classifier_type="scaledown",
    )
    decision = evaluate_policy(classification, event)
    assert decision.action == "alert"  # Downgraded from quarantine
    assert "QUARANTINE_BLOCKED_SYSTEM_NAMESPACE" in decision.reason_codes
    assert decision.quarantine_labels is None
