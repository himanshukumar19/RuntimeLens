"""Prometheus metrics exporter and health monitoring for RuntimeLens."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING
from wsgiref.simple_server import WSGIServer

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

if TYPE_CHECKING:
    from runtimelens.models.decision import ClassificationResult, PolicyDecision

DEFAULT_CLASSIFICATION_LATENCY_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

DEFAULT_RECOVERY_TIME_BUCKETS = (
    1.0,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    900.0,
    1800.0,
)

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})


class MetricsServer:
    """Wrapper managing a Prometheus WSGI scrape server and daemon thread."""

    def __init__(
        self,
        httpd: WSGIServer,
        thread: threading.Thread,
        host: str,
        port: int,
    ) -> None:
        self.httpd = httpd
        self.thread = thread
        self.host = host
        self.port = port
        self._stopped = False

    @property
    def is_running(self) -> bool:
        """Check whether the metrics server thread is alive and not stopped."""
        return not self._stopped and self.thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """Shut down the server and wait for thread termination."""
        if not self._stopped:
            self._stopped = True
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=timeout)


class MetricsExporter:
    """Prometheus metrics exporter for RuntimeLens runtime and orchestration observability."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self._server: MetricsServer | None = None

        # 1. Telemetry Ingestion & Health Metrics
        self.telemetry_events_total = Counter(
            "runtimelens_telemetry_events_total",
            "Total raw telemetry events ingested by source",
            ["source"],
            registry=self.registry,
        )
        self.telemetry_drops_total = Counter(
            "runtimelens_telemetry_drops_total",
            "Total raw telemetry buffer drops by source",
            ["source"],
            registry=self.registry,
        )
        self.telemetry_source_up = Gauge(
            "runtimelens_telemetry_source_up",
            "Telemetry source heartbeat status (1=healthy, 0=degraded/disconnected)",
            ["source"],
            registry=self.registry,
        )

        # 2. Classification & Pipeline Metrics
        self.decisions_total = Counter(
            "runtimelens_decisions_total",
            "Total decisions rendered across threat class, model, and containment action",
            ["class", "model", "action"],
            registry=self.registry,
        )
        self.classification_duration_seconds = Histogram(
            "runtimelens_classification_duration_seconds",
            "Classification inference latency duration in seconds",
            ["model", "cache_hit"],
            buckets=DEFAULT_CLASSIFICATION_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.degraded_events_total = Counter(
            "runtimelens_degraded_events_total",
            "Total degraded fallback executions by reason",
            ["reason"],
            registry=self.registry,
        )

        # 3. Containment & Operational SRE Metrics
        self.quarantines_active = Gauge(
            "runtimelens_quarantines_active",
            "Number of active quarantined workloads by namespace",
            ["namespace"],
            registry=self.registry,
        )
        self.quarantine_rollbacks_total = Counter(
            "runtimelens_quarantine_rollbacks_total",
            "Total quarantine rollbacks executed by reason",
            ["reason"],
            registry=self.registry,
        )
        self.recovery_time_seconds = Histogram(
            "runtimelens_recovery_time_seconds",
            "Elapsed time in seconds from quarantine isolation to clean rollback",
            buckets=DEFAULT_RECOVERY_TIME_BUCKETS,
            registry=self.registry,
        )
        self.review_queue_depth = Gauge(
            "runtimelens_review_queue_depth",
            "Current depth of the human review queue",
            registry=self.registry,
        )

    # Telemetry helper methods
    def record_event(self, source: str, count: float = 1.0) -> None:
        """Record ingested raw telemetry events."""
        self.telemetry_events_total.labels(source=source).inc(count)

    def record_drop(self, source: str, count: float = 1.0) -> None:
        """Record dropped raw telemetry events."""
        self.telemetry_drops_total.labels(source=source).inc(count)

    def set_source_up(self, source: str, is_up: bool | int) -> None:
        """Update source heartbeat status (1 for healthy, 0 for degraded)."""
        self.telemetry_source_up.labels(source=source).set(1.0 if is_up else 0.0)

    # Decision & pipeline helper methods
    def record_decision(
        self,
        threat_class: str,
        model: str,
        action: str,
        count: float = 1.0,
    ) -> None:
        """Record a pipeline decision. Normalizes 'human_review' to 'review'."""
        norm_action = "review" if action == "human_review" else action
        self.decisions_total.labels(
            **{"class": threat_class, "model": model, "action": norm_action}
        ).inc(count)

    def record_decision_result(
        self,
        classification: ClassificationResult,
        decision: PolicyDecision,
    ) -> None:
        """Record decision directly from domain model objects."""
        self.record_decision(
            threat_class=classification.predicted_class,
            model=classification.classifier_type,
            action=decision.action,
        )

    def record_classification_duration(
        self,
        model: str,
        duration_seconds: float,
        cache_hit: bool = False,
    ) -> None:
        """Record classification inference latency."""
        cache_hit_str = "true" if cache_hit else "false"
        self.classification_duration_seconds.labels(
            model=model,
            cache_hit=cache_hit_str,
        ).observe(duration_seconds)

    def record_degraded(self, reason: str, count: float = 1.0) -> None:
        """Record a degraded fallback event execution."""
        self.degraded_events_total.labels(reason=reason).inc(count)

    # SRE containment & operational helper methods
    def set_quarantines_active(self, namespace: str, count: int | float) -> None:
        """Set the active quarantine count for a specific namespace."""
        self.quarantines_active.labels(namespace=namespace).set(float(count))

    def inc_quarantines_active(self, namespace: str, amount: float = 1.0) -> None:
        """Increment active quarantine gauge for a namespace."""
        self.quarantines_active.labels(namespace=namespace).inc(amount)

    def dec_quarantines_active(self, namespace: str, amount: float = 1.0) -> None:
        """Decrement active quarantine gauge for a namespace."""
        self.quarantines_active.labels(namespace=namespace).dec(amount)

    def record_rollback(self, reason: str, count: float = 1.0) -> None:
        """Record quarantine rollback event."""
        self.quarantine_rollbacks_total.labels(reason=reason).inc(count)

    def record_recovery_time(self, duration_seconds: float) -> None:
        """Record elapsed time for quarantine recovery/rollback."""
        self.recovery_time_seconds.observe(duration_seconds)

    def set_review_queue_depth(self, depth: int | float) -> None:
        """Set current depth of human review queue."""
        self.review_queue_depth.set(float(depth))

    def inc_review_queue_depth(self, amount: float = 1.0) -> None:
        """Increment current depth of human review queue."""
        self.review_queue_depth.inc(amount)

    def dec_review_queue_depth(self, amount: float = 1.0) -> None:
        """Decrement current depth of human review queue."""
        self.review_queue_depth.dec(amount)

    def generate_metrics(self) -> bytes:
        """Generate latest Prometheus metrics text representation."""
        return generate_latest(self.registry)

    # HTTP server helper methods
    def start_server(self, port: int = 9090, host: str = "127.0.0.1") -> MetricsServer:
        """Start Prometheus scrape HTTP server bound strictly to localhost/127.0.0.1."""
        if host not in ALLOWED_HOSTS:
            raise ValueError(
                f"Security violation: Metrics server must bind strictly to 127.0.0.1 (got {host!r})"
            )
        if self._server is not None and self._server.is_running:
            return self._server

        httpd, thread = start_http_server(port, addr=host, registry=self.registry)
        actual_port = int(getattr(httpd, "server_port", port))
        server = MetricsServer(httpd=httpd, thread=thread, host=host, port=actual_port)
        self._server = server
        return server

    def stop_server(self, timeout: float = 5.0) -> None:
        """Stop running HTTP server if active."""
        if self._server is not None:
            self._server.stop(timeout=timeout)
            self._server = None


_default_exporter: MetricsExporter | None = None
_exporter_lock = threading.Lock()


def get_default_exporter() -> MetricsExporter:
    """Return thread-safe module-level default MetricsExporter instance."""
    global _default_exporter
    if _default_exporter is None:
        with _exporter_lock:
            if _default_exporter is None:
                _default_exporter = MetricsExporter()
    return _default_exporter


def start_metrics_server(
    port: int = 9090,
    host: str = "127.0.0.1",
    exporter: MetricsExporter | None = None,
) -> MetricsServer:
    """Start Prometheus scrape HTTP server using specified or default exporter."""
    active_exporter = exporter if exporter is not None else get_default_exporter()
    return active_exporter.start_server(port=port, host=host)


def stop_metrics_server(server: MetricsServer, timeout: float = 5.0) -> None:
    """Stop an active MetricsServer."""
    server.stop(timeout=timeout)
