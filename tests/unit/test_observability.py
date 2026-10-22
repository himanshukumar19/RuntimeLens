"""Unit tests for Prometheus metrics exporter and Grafana dashboard specification."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from prometheus_client import CollectorRegistry

from runtimelens.models.decision import ClassificationResult, PolicyDecision
from runtimelens.observability.exporter import (
    MetricsExporter,
    get_default_exporter,
    start_metrics_server,
    stop_metrics_server,
)


@pytest.fixture
def isolated_exporter() -> MetricsExporter:
    """Fixture providing an exporter bound to an isolated CollectorRegistry."""
    registry = CollectorRegistry()
    return MetricsExporter(registry=registry)


def test_exporter_metric_registration(isolated_exporter: MetricsExporter) -> None:
    """Verify that all required Prometheus metrics are registered on the isolated registry."""
    exporter = isolated_exporter
    raw_metrics_text = exporter.generate_metrics().decode("utf-8")
    assert "# TYPE runtimelens_telemetry_events_total counter" in raw_metrics_text
    assert "# TYPE runtimelens_telemetry_drops_total counter" in raw_metrics_text
    assert "# TYPE runtimelens_telemetry_source_up gauge" in raw_metrics_text
    assert "# TYPE runtimelens_decisions_total counter" in raw_metrics_text
    assert "# TYPE runtimelens_classification_duration_seconds histogram" in raw_metrics_text
    assert "# TYPE runtimelens_degraded_events_total counter" in raw_metrics_text
    assert "# TYPE runtimelens_quarantines_active gauge" in raw_metrics_text
    assert "# TYPE runtimelens_quarantine_rollbacks_total counter" in raw_metrics_text
    assert "# TYPE runtimelens_review_queue_depth gauge" in raw_metrics_text
    assert "# TYPE runtimelens_recovery_time_seconds histogram" in raw_metrics_text


def test_record_telemetry_events_and_drops(isolated_exporter: MetricsExporter) -> None:
    """Test telemetry ingestion event and drop counter updates."""
    exporter = isolated_exporter
    exporter.record_event("falco", 12.0)
    exporter.record_event("k8s_audit", 8.0)
    exporter.record_drop("falco", 3.0)

    reg = exporter.registry
    assert reg.get_sample_value("runtimelens_telemetry_events_total", {"source": "falco"}) == 12.0
    assert (
        reg.get_sample_value("runtimelens_telemetry_events_total", {"source": "k8s_audit"}) == 8.0
    )
    assert reg.get_sample_value("runtimelens_telemetry_drops_total", {"source": "falco"}) == 3.0
    drops_k8s = reg.get_sample_value("runtimelens_telemetry_drops_total", {"source": "k8s_audit"})
    assert drops_k8s is None


def test_telemetry_source_up(isolated_exporter: MetricsExporter) -> None:
    """Test telemetry source heartbeat gauge toggling."""
    exporter = isolated_exporter
    exporter.set_source_up("falco", True)
    exporter.set_source_up("hubble", False)
    exporter.set_source_up("trivy", 1)

    reg = exporter.registry
    assert reg.get_sample_value("runtimelens_telemetry_source_up", {"source": "falco"}) == 1.0
    assert reg.get_sample_value("runtimelens_telemetry_source_up", {"source": "hubble"}) == 0.0
    assert reg.get_sample_value("runtimelens_telemetry_source_up", {"source": "trivy"}) == 1.0


def test_record_decisions_and_labels(isolated_exporter: MetricsExporter) -> None:
    """Test decision recording and label normalization."""
    exporter = isolated_exporter
    exporter.record_decision(
        threat_class="container_escape",
        model="scaledown",
        action="quarantine",
        count=2.0,
    )
    exporter.record_decision(
        threat_class="benign",
        model="rules",
        action="log",
        count=5.0,
    )
    # Action 'human_review' should be normalized to 'review' per OBSERVABILITY.md
    exporter.record_decision(
        threat_class="privilege_abuse",
        model="rf",
        action="human_review",
        count=1.0,
    )

    reg = exporter.registry
    assert (
        reg.get_sample_value(
            "runtimelens_decisions_total",
            {"class": "container_escape", "model": "scaledown", "action": "quarantine"},
        )
        == 2.0
    )
    assert (
        reg.get_sample_value(
            "runtimelens_decisions_total",
            {"class": "benign", "model": "rules", "action": "log"},
        )
        == 5.0
    )
    assert (
        reg.get_sample_value(
            "runtimelens_decisions_total",
            {"class": "privilege_abuse", "model": "rf", "action": "review"},
        )
        == 1.0
    )


def test_record_decision_result_helper(isolated_exporter: MetricsExporter) -> None:
    """Test recording decisions via ClassificationResult and PolicyDecision models."""
    exporter = isolated_exporter
    classification = ClassificationResult(
        predicted_class="cryptomining",
        class_probabilities={"cryptomining": 0.95},
        severity=4.0,
        confidence=0.95,
        classifier_type="scaledown",
    )
    decision = PolicyDecision(
        action="quarantine",
        reason_codes=["CRYPTO_DETECTED"],
        dry_run=True,
    )
    exporter.record_decision_result(classification, decision)

    reg = exporter.registry
    val = reg.get_sample_value(
        "runtimelens_decisions_total",
        {"class": "cryptomining", "model": "scaledown", "action": "quarantine"},
    )
    assert val == 1.0


def test_classification_duration_histogram(isolated_exporter: MetricsExporter) -> None:
    """Test classification duration latency histogram observations."""
    exporter = isolated_exporter
    exporter.record_classification_duration("scaledown", 0.045, cache_hit=False)
    exporter.record_classification_duration("scaledown", 0.012, cache_hit=True)

    reg = exporter.registry
    sum_val = reg.get_sample_value(
        "runtimelens_classification_duration_seconds_sum",
        {"model": "scaledown", "cache_hit": "false"},
    )
    count_val = reg.get_sample_value(
        "runtimelens_classification_duration_seconds_count",
        {"model": "scaledown", "cache_hit": "false"},
    )
    assert count_val == 1.0
    assert sum_val is not None and abs(sum_val - 0.045) < 1e-4

    hit_count = reg.get_sample_value(
        "runtimelens_classification_duration_seconds_count",
        {"model": "scaledown", "cache_hit": "true"},
    )
    assert hit_count == 1.0


def test_degraded_events_counter(isolated_exporter: MetricsExporter) -> None:
    """Test fallback degraded events counter."""
    exporter = isolated_exporter
    exporter.record_degraded("model_timeout", 2.0)
    exporter.record_degraded("telemetry_drop", 1.0)

    reg = exporter.registry
    assert (
        reg.get_sample_value("runtimelens_degraded_events_total", {"reason": "model_timeout"})
        == 2.0
    )
    assert (
        reg.get_sample_value("runtimelens_degraded_events_total", {"reason": "telemetry_drop"})
        == 1.0
    )


def test_quarantines_and_rollbacks(isolated_exporter: MetricsExporter) -> None:
    """Test active quarantine gauge, rollbacks, and recovery time."""
    exporter = isolated_exporter
    exporter.set_quarantines_active("tenant-a", 3)
    exporter.inc_quarantines_active("tenant-a", 1)
    exporter.dec_quarantines_active("tenant-a", 2)
    exporter.record_rollback("ttl_expired", 2.0)
    exporter.record_recovery_time(34.2)

    reg = exporter.registry
    assert reg.get_sample_value("runtimelens_quarantines_active", {"namespace": "tenant-a"}) == 2.0
    assert (
        reg.get_sample_value(
            "runtimelens_quarantine_rollbacks_total",
            {"reason": "ttl_expired"},
        )
        == 2.0
    )
    assert reg.get_sample_value("runtimelens_recovery_time_seconds_count") == 1.0


def test_review_queue_depth(isolated_exporter: MetricsExporter) -> None:
    """Test human review queue depth gauge updates."""
    exporter = isolated_exporter
    exporter.set_review_queue_depth(10)
    exporter.inc_review_queue_depth(4)
    exporter.dec_review_queue_depth(1)

    reg = exporter.registry
    assert reg.get_sample_value("runtimelens_review_queue_depth") == 13.0


def test_generate_metrics(isolated_exporter: MetricsExporter) -> None:
    """Test raw Prometheus text representation generation."""
    exporter = isolated_exporter
    exporter.record_event("falco", 1.0)
    text_data = exporter.generate_metrics()
    assert isinstance(text_data, bytes)
    assert b"runtimelens_telemetry_events_total" in text_data


def test_http_server_lifecycle_and_scrape(isolated_exporter: MetricsExporter) -> None:
    """Test dynamic port HTTP scrape server binding strictly to 127.0.0.1 and handling requests."""
    exporter = isolated_exporter
    exporter.record_event("falco", 7.0)
    exporter.record_decision("container_escape", "scaledown", "quarantine")

    # Start server on dynamic port (0)
    server = exporter.start_server(port=0, host="127.0.0.1")
    try:
        assert server.is_running
        assert server.host == "127.0.0.1"
        assert server.port > 0

        # Query metrics via httpx
        url = f"http://127.0.0.1:{server.port}/metrics"
        resp = httpx.get(url, timeout=3.0)
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")
        content = resp.text
        assert "runtimelens_telemetry_events_total" in content
        assert "container_escape" in content
        assert "quarantine" in content
    finally:
        server.stop()
        assert not server.is_running


def test_server_security_bind_guard(isolated_exporter: MetricsExporter) -> None:
    """Verify that binding to non-localhost addresses raises a security violation."""
    exporter = isolated_exporter
    with pytest.raises(ValueError, match="Security violation: Metrics server must bind strictly"):
        exporter.start_server(port=9090, host="0.0.0.0")

    with pytest.raises(ValueError, match="Security violation: Metrics server must bind strictly"):
        exporter.start_server(port=9090, host="192.168.1.100")


def test_standalone_server_helpers(isolated_exporter: MetricsExporter) -> None:
    """Test module-level start_metrics_server and stop_metrics_server functions."""
    exporter = isolated_exporter
    server = start_metrics_server(port=0, host="127.0.0.1", exporter=exporter)
    try:
        assert server.is_running
    finally:
        stop_metrics_server(server)
        assert not server.is_running


def test_default_exporter_singleton() -> None:
    """Verify get_default_exporter returns a valid MetricsExporter instance."""
    exp1 = get_default_exporter()
    exp2 = get_default_exporter()
    assert exp1 is exp2
    assert isinstance(exp1, MetricsExporter)


def test_grafana_dashboard_json() -> None:
    """Validate Grafana SecOps dashboard JSON structure, schema, and panel queries."""
    dashboard_path = Path("lab/monitoring/grafana/dashboard.json")
    assert dashboard_path.exists(), f"Dashboard JSON missing at {dashboard_path}"

    with dashboard_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Basic dashboard structure
    assert data.get("title") == "RuntimeLens SecOps Dashboard"
    assert data.get("uid") == "runtimelens-secops"
    assert data.get("schemaVersion", 0) >= 36
    assert "runtimelens" in data.get("tags", [])

    panels = data.get("panels", [])
    assert len(panels) >= 4, "Dashboard must have at least 4 main panels"

    # Verify key panels by title and query expressions
    panel_titles = {p.get("title", ""): p for p in panels if p.get("type") != "row"}

    # 1. Telemetry sensor health panel
    assert "Telemetry Sensor Health" in panel_titles
    sensor_panel = panel_titles["Telemetry Sensor Health"]
    sensor_exprs = [t.get("expr", "") for t in sensor_panel.get("targets", [])]
    assert any("runtimelens_telemetry_source_up" in expr for expr in sensor_exprs)

    # 2. Decision distribution panel
    assert "Decision Distribution by Threat Class" in panel_titles
    dec_panel = panel_titles["Decision Distribution by Threat Class"]
    dec_exprs = [t.get("expr", "") for t in dec_panel.get("targets", [])]
    assert any("runtimelens_decisions_total" in expr and "class" in expr for expr in dec_exprs)

    # 3. Containment action breakdown panel
    assert "Containment Action Breakdown" in panel_titles
    action_panel = panel_titles["Containment Action Breakdown"]
    action_exprs = [t.get("expr", "") for t in action_panel.get("targets", [])]
    assert any("runtimelens_decisions_total" in expr and "action" in expr for expr in action_exprs)

    # 4. Pipeline latency p50/p95 panel
    assert "Pipeline Latency p50 / p95 / p99" in panel_titles
    lat_panel = panel_titles["Pipeline Latency p50 / p95 / p99"]
    lat_exprs = [t.get("expr", "") for t in lat_panel.get("targets", [])]
    assert any("runtimelens_classification_duration_seconds" in expr for expr in lat_exprs)
    assert any("0.50" in expr or "0.5" in expr for expr in lat_exprs)
    assert any("0.95" in expr for expr in lat_exprs)
