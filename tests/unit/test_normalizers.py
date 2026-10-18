"""Unit tests for Hubble, Prometheus, and Trivy telemetry normalizers (Ticket 09b)."""

from __future__ import annotations

from runtimelens.normalizer.hubble import normalize_hubble_flow
from runtimelens.normalizer.prometheus import normalize_prometheus_metric
from runtimelens.normalizer.trivy import normalize_trivy_report


def test_hubble_flow_normalizer_cross_tenant_detection() -> None:
    raw_flow = {
        "flow": {
            "time": "2026-10-18T14:29:43Z",
            "verdict": "FORWARDED",
            "IP": {"source": "10.244.0.5", "destination": "10.244.0.9"},
            "l4": {"TCP": {"destination_port": 3333}},
            "source": {"namespace": "tenant-a", "pod_name": "web-01"},
            "destination": {"namespace": "tenant-b", "pod_name": "api-01"},
        }
    }
    net_ctx, facts = normalize_hubble_flow(raw_flow)
    assert net_ctx.destination_port == 3333
    assert net_ctx.protocol == "TCP"
    assert net_ctx.verdict == "FORWARDED"
    assert facts["is_cross_tenant_flow"] is True
    assert facts["is_outbound_egress"] is False


def test_hubble_flow_normalizer_external_egress() -> None:
    raw_flow = {
        "flow": {
            "verdict": "DROPPED",
            "IP": {"source": "10.244.0.5", "destination": "198.51.100.22"},
            "l4": {"UDP": {"destination_port": 53}},
            "source": {"namespace": "tenant-a"},
            "destination": {"namespace": ""},
        }
    }
    net_ctx, facts = normalize_hubble_flow(raw_flow)
    assert net_ctx.destination_port == 53
    assert net_ctx.protocol == "UDP"
    assert net_ctx.verdict == "DROPPED"
    assert facts["is_cross_tenant_flow"] is False
    assert facts["is_outbound_egress"] is True


def test_prometheus_normalizer_relative_anomaly() -> None:
    # Baseline envelope is 25 mcores; 85 mcores is >= 3x (75 mcores)
    metric_high = {"value": 0.085}
    mcores, is_abnormal = normalize_prometheus_metric(
        metric_high, baseline_cpu_envelope_mcores=25.0
    )
    assert mcores == 85.0
    assert is_abnormal is True

    # Normal usage: 15 mcores (< 75 mcores)
    metric_low = {"value": 0.015}
    mcores_low, is_abnormal_low = normalize_prometheus_metric(
        metric_low, baseline_cpu_envelope_mcores=25.0
    )
    assert mcores_low == 15.0
    assert is_abnormal_low is False


def test_trivy_normalizer_critical_vulnerability_extraction() -> None:
    sample_report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "alpine:3.19",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-1111", "Severity": "LOW"},
                    {"VulnerabilityID": "CVE-2024-9999", "Severity": "CRITICAL"},
                ],
            }
        ],
    }
    has_crit, cve_list = normalize_trivy_report(sample_report)
    assert has_crit is True
    assert "CVE-2024-9999" in cve_list
    assert "CVE-2024-1111" not in cve_list
