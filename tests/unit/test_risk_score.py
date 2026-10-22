"""Comprehensive unit tests for exposure-based continuous risk scoring (Ticket 15)."""

from __future__ import annotations

import pytest

from runtimelens.models.decision import ClassificationResult
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    NetworkContext,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)
from runtimelens.policy.risk_score import (
    ExposureMetadata,
    compute_risk_score,
    determine_risk_tier,
    evaluate_event_risk_score,
    resolve_cve_factor,
    resolve_exposure_factor,
    resolve_namespace_weight,
)


def _make_dummy_event(
    namespace: str = "tenant-a",
    owner_workload: str = "web",
    has_crit_vuln: bool = False,
    is_egress: bool = False,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-risk-001",
        workload=WorkloadIdentity(
            tenant="tenant-a" if namespace.startswith("tenant-") else "sandbox",
            namespace=namespace,
            pod_name="test-pod",
            pod_uid="uid-test",
            owner_workload=owner_workload,
            container_name="test-container",
            image_digest="docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="src-risk-1",
            source_rule_name="Test Rule",
            raw_event_ref="sha256:dummy",
        ),
        facts=DeterministicFacts(
            has_critical_vulnerability=has_crit_vuln,
            is_outbound_egress=is_egress,
        ),
        runtime=RuntimeContext(
            process_name="nginx",
            parent_process="init",
            command_args_sanitized="nginx -g 'daemon off;'",
            syscall="execve",
        ),
        network=NetworkContext(
            destination_ip="198.51.100.1" if is_egress else None,
            destination_port=443 if is_egress else None,
            verdict="FORWARDED" if is_egress else None,
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            expected_binaries=["nginx"],
            expected_peers=[],
        ),
        health=TelemetryHealth(
            is_telemetry_degraded=False,
            missing_sources=[],
        ),
    )


def _make_dummy_classification(
    severity: float = 1.0,
    predicted_class: str = "benign",
) -> ClassificationResult:
    return ClassificationResult(
        predicted_class="benign" if predicted_class == "benign" else "container_escape",
        severity=severity,
        confidence=0.95,
        evidence_flags={},
        classifier_type="rules",
        model_version="v1.0.0",
    )


class TestExposureFactorResolution:
    def test_internet_facing_factor(self) -> None:
        factor = resolve_exposure_factor(is_internet_facing=True, is_outbound_egress=False)
        assert factor == 1.25

    def test_outbound_egress_factor(self) -> None:
        factor = resolve_exposure_factor(is_internet_facing=False, is_outbound_egress=True)
        assert factor == 1.10

    def test_internal_only_factor(self) -> None:
        factor = resolve_exposure_factor(is_internet_facing=False, is_outbound_egress=False)
        assert factor == 0.90

    def test_custom_exposure_override(self) -> None:
        factor = resolve_exposure_factor(
            is_internet_facing=False,
            is_outbound_egress=False,
            custom_factor=1.85,
        )
        assert factor == 1.85


class TestCveFactorResolution:
    def test_zero_cve_factor(self) -> None:
        factor = resolve_cve_factor(has_critical_vulnerability=False, critical_cve_count=0)
        assert factor == 1.00

    def test_boolean_flag_only(self) -> None:
        factor = resolve_cve_factor(has_critical_vulnerability=True, critical_cve_count=0)
        assert factor == 1.15

    def test_cve_count_scaling(self) -> None:
        # 1 CVE: 1.00 + 0.05 = 1.05
        assert resolve_cve_factor(True, 1) == 1.05
        # 3 CVEs: 1.00 + 0.15 = 1.15
        assert resolve_cve_factor(True, 3) == 1.15
        # 5 CVEs: 1.00 + 0.25 = 1.25
        assert resolve_cve_factor(True, 5) == 1.25
        # 10 CVEs: capped at 1.25
        assert resolve_cve_factor(True, 10) == 1.25


class TestNamespaceWeightResolution:
    def test_tenant_namespaces(self) -> None:
        assert resolve_namespace_weight("tenant-a") == 1.00
        assert resolve_namespace_weight("tenant-b") == 1.00
        assert resolve_namespace_weight("tenant-c") == 1.00
        assert resolve_namespace_weight("production") == 1.00
        assert resolve_namespace_weight("payment") == 1.00

    def test_sandbox_namespaces(self) -> None:
        assert resolve_namespace_weight("sandbox") == 0.50
        assert resolve_namespace_weight("sandbox-test") == 0.50
        assert resolve_namespace_weight("dev") == 0.50
        assert resolve_namespace_weight("test") == 0.50

    def test_default_namespace(self) -> None:
        assert resolve_namespace_weight("default") == 0.80

    def test_custom_namespace_weight_override(self) -> None:
        assert resolve_namespace_weight("tenant-a", custom_weight=0.35) == 0.35


class TestRiskTierClassification:
    def test_tier_boundaries(self) -> None:
        assert determine_risk_tier(0.0) == "LOW"
        assert determine_risk_tier(3.99) == "LOW"
        assert determine_risk_tier(4.0) == "MEDIUM"
        assert determine_risk_tier(6.99) == "MEDIUM"
        assert determine_risk_tier(7.0) == "HIGH"
        assert determine_risk_tier(8.99) == "HIGH"
        assert determine_risk_tier(9.0) == "CRITICAL"
        assert determine_risk_tier(10.0) == "CRITICAL"


class TestComputeRiskScore:
    def test_severity_validation_bounds(self) -> None:
        with pytest.raises(ValueError, match=r"Severity must be in range \[1.0, 5.0\]"):
            compute_risk_score(severity=0.5)
        with pytest.raises(ValueError, match=r"Severity must be in range \[1.0, 5.0\]"):
            compute_risk_score(severity=5.5)

    def test_benign_internal_workload_low_risk(self) -> None:
        # Severity 1.0, internal only, tenant-a, no CVEs
        # Base: 2.0 * 1.0 = 2.0. Exposure: 0.90, CVE: 1.00, NS: 1.00
        # Score: 2.0 * 0.90 * 1.00 * 1.00 = 1.80 -> LOW
        res = compute_risk_score(
            severity=1.0,
            is_internet_facing=False,
            is_outbound_egress=False,
            has_critical_vulnerability=False,
            namespace="tenant-a",
        )
        assert res.score == 1.80
        assert res.tier == "LOW"
        assert res.severity_score == 1.0
        assert res.exposure_factor == 0.90
        assert res.cve_factor == 1.00
        assert res.namespace_weight == 1.00

    def test_benign_internet_facing_remains_low_risk(self) -> None:
        # Severity 1.0, internet-facing, tenant-a, 2 CVEs
        # Base: 2.0. Exposure: 1.25, CVE: 1.10, NS: 1.00
        # Score: 2.0 * 1.25 * 1.10 * 1.00 = 2.75 -> LOW
        res = compute_risk_score(
            severity=1.0,
            is_internet_facing=True,
            is_outbound_egress=False,
            has_critical_vulnerability=True,
            critical_cve_count=2,
            namespace="tenant-a",
        )
        assert res.score == 2.75
        assert res.tier == "LOW"

    def test_high_threat_in_sandbox_downgraded_to_medium(self) -> None:
        # Severity 5.0, internal only, sandbox, no CVEs
        # Base: 10.0. Exposure: 0.90, CVE: 1.00, NS: 0.50
        # Score: 10.0 * 0.90 * 1.00 * 0.50 = 4.50 -> MEDIUM
        res = compute_risk_score(
            severity=5.0,
            is_internet_facing=False,
            is_outbound_egress=False,
            has_critical_vulnerability=False,
            namespace="sandbox",
        )
        assert res.score == 4.50
        assert res.tier == "MEDIUM"

    def test_high_threat_in_tenant_escalates_to_critical(self) -> None:
        # Severity 4.5, internet-facing, 3 CVEs, tenant-c
        # Base: 2.0 * 4.5 = 9.0. Exposure: 1.25, CVE: 1.15, NS: 1.00
        # Score: 9.0 * 1.25 * 1.15 * 1.00 = 12.9375 -> clamped to 10.00 -> CRITICAL
        res = compute_risk_score(
            severity=4.5,
            is_internet_facing=True,
            is_outbound_egress=True,
            has_critical_vulnerability=True,
            critical_cve_count=3,
            namespace="tenant-c",
        )
        assert res.score == 10.00
        assert res.tier == "CRITICAL"

    def test_score_strictly_clamped_at_ten(self) -> None:
        res = compute_risk_score(
            severity=5.0,
            custom_exposure_factor=2.5,
            has_critical_vulnerability=True,
            critical_cve_count=10,
            namespace="tenant-a",
        )
        assert res.score == 10.00
        assert res.tier == "CRITICAL"

    def test_using_structured_exposure_metadata(self) -> None:
        meta = ExposureMetadata(
            is_internet_facing=True,
            is_outbound_egress=True,
            has_critical_vulnerability=True,
            critical_cve_count=1,
            namespace="tenant-b",
        )
        res = compute_risk_score(severity=3.0, exposure=meta)
        # Base: 6.0. Exposure: 1.25, CVE: 1.05, NS: 1.00
        # 6.0 * 1.25 * 1.05 = 7.875 -> 7.88 -> HIGH
        assert res.score == 7.88
        assert res.tier == "HIGH"
        assert res.details["namespace"] == "tenant-b"


class TestEvaluateEventRiskScore:
    def test_evaluate_from_canonical_event(self) -> None:
        event = _make_dummy_event(
            namespace="tenant-a",
            owner_workload="web",  # automatically infers is_internet_facing = True
            has_crit_vuln=True,
            is_egress=True,
        )
        cls_result = _make_dummy_classification(severity=3.5)

        res = evaluate_event_risk_score(classification=cls_result, event=event)
        # Base: 7.0. Exposure: 1.25 (web), CVE: 1.15 (bool vuln), NS: 1.00
        # Score: 7.0 * 1.25 * 1.15 = 10.06 -> clamped to 10.00
        assert res.score == 10.00
        assert res.tier == "CRITICAL"
        assert res.details["is_internet_facing"] is True
        assert res.details["has_critical_vulnerability"] is True

    def test_evaluate_event_with_explicit_overrides(self) -> None:
        event = _make_dummy_event(
            namespace="tenant-a",
            owner_workload="web",
            has_crit_vuln=False,
            is_egress=False,
        )
        cls_result = _make_dummy_classification(severity=2.0)

        res = evaluate_event_risk_score(
            classification=cls_result,
            event=event,
            is_internet_facing=False,
            custom_namespace_weight=0.50,
        )
        # Base: 4.0. Exposure: 0.90, CVE: 1.00, NS: 0.50
        # Score: 4.0 * 0.90 * 1.00 * 0.50 = 1.80
        assert res.score == 1.80
        assert res.tier == "LOW"
