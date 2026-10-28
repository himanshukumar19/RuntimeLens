"""Live multi-source correlation daemon wiring Falco and K8s audit streams (Ticket 04-live).

Wires live Falco HTTP webhook and Kubernetes API Audit webhook streams simultaneously
into a shared temporal CorrelationBuffer (+-30s window), yielding unified CanonicalEvents
with full orchestration context and writing tamper-evident AuditRecords.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from runtimelens.audit.writer import AuditWriter
from runtimelens.classifiers.rules import classify_rules
from runtimelens.collector.correlation import CorrelationBuffer
from runtimelens.controller.quarantine import QuarantineController
from runtimelens.models.decision import AuditRecord
from runtimelens.normalizer.falco import normalize_falco_event
from runtimelens.policy.engine import evaluate_policy

logger = logging.getLogger("runtimelens.collector.live_wiring")

DEFAULT_CORRELATION_AUDIT_PATH = Path("data/audit/live_decisions.jsonl")


class LiveCorrelationDaemon:
    """Coordinates Falco and K8s Audit ingestion, temporal correlation, and decision emission."""

    def __init__(
        self,
        audit_writer: AuditWriter,
        quarantine_controller: QuarantineController | None = None,
        correlation_window_seconds: float = 30.0,
        dry_run: bool = True,
    ) -> None:
        self.audit_writer = audit_writer
        self.quarantine_controller = quarantine_controller
        self.dry_run = dry_run
        self.buffer = CorrelationBuffer(window_seconds=correlation_window_seconds)
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def ingest_raw_audit_payload(self, payload: dict[str, Any]) -> int:
        """Ingest raw Kubernetes EventList audit batch into correlation buffer."""
        items: list[dict[str, Any]] = payload.get("items", [])
        with self._lock:
            for raw_audit in items:
                self.buffer.ingest_audit_event(raw_audit)
        return len(items)

    def ingest_raw_falco_payload(self, payload: dict[str, Any]) -> AuditRecord:
        """Process a raw Falco event, join orchestration context, classify, and write audit."""
        # 1. Normalize raw Falco alert to CanonicalEvent
        canonical = normalize_falco_event(payload)

        # 2. Correlate with temporal buffer
        with self._lock:
            correlated_event = self.buffer.ingest_falco_event(canonical)

        # 3. Classify threat
        classification = classify_rules(correlated_event)

        # 4. Evaluate deterministic safety policy
        decision = evaluate_policy(classification, correlated_event, dry_run=self.dry_run)

        # 5. Apply quarantine containment if indicated
        if self.quarantine_controller is not None and decision.action == "quarantine":
            self.quarantine_controller.apply_decision(
                decision=decision,
                event=correlated_event,
                incident_id=f"inc-{correlated_event.event_id}",
            )

        # 6. Write tamper-evident audit record
        with self._lock:
            record = self.audit_writer.write_record(
                event=correlated_event,
                classification=classification,
                decision=decision,
            )
            self.records.append(record)

        return record


class FalcoStreamHandler(BaseHTTPRequestHandler):
    """HTTP handler receiving Falco webhook events and forwarding to daemon."""

    daemon_instance: LiveCorrelationDaemon
    expected_token: str

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 65536:
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length)

        # Check authentication if expected_token is set
        if self.expected_token:
            auth_header = self.headers.get("Authorization", "")
            token = auth_header.removeprefix("Bearer ").strip()
            if not token:
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                token = params.get("token", [""])[0]

            if not hmac.compare_digest(token, self.expected_token):
                self.send_response(401)
                self.end_headers()
                return

        try:
            payload = json.loads(body.decode("utf-8"))
            record = self.daemon_instance.ingest_raw_falco_payload(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"status": "ok", "record_id": record.record_id}).encode("utf-8")
            )
        except Exception as e:
            logger.exception("Error processing Falco webhook")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))


class AuditStreamHandler(BaseHTTPRequestHandler):
    """HTTP handler receiving K8s Audit batch events and forwarding to daemon."""

    daemon_instance: LiveCorrelationDaemon
    expected_token: str

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 10485760:  # 10 MB limit
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length)

        if self.expected_token:
            auth_header = self.headers.get("Authorization", "")
            token = auth_header.removeprefix("Bearer ").strip()
            if not hmac.compare_digest(token, self.expected_token):
                self.send_response(401)
                self.end_headers()
                return

        try:
            payload = json.loads(body.decode("utf-8"))
            count = self.daemon_instance.ingest_raw_audit_payload(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "items_ingested": count}).encode("utf-8"))
        except Exception as e:
            logger.exception("Error processing K8s Audit webhook")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))


class MultiSourceWebhookServer:
    """Manages simultaneous HTTP listeners for Falco and Audit events."""

    def __init__(
        self,
        daemon: LiveCorrelationDaemon,
        host: str = "127.0.0.1",
        falco_port: int = 0,
        audit_port: int = 0,
        falco_token: str = "",
        audit_token: str = "",
    ) -> None:
        self.daemon = daemon
        self.host = host

        # Configure Falco server
        falco_handler = type(
            "BoundFalcoHandler",
            (FalcoStreamHandler,),
            {"daemon_instance": self.daemon, "expected_token": falco_token},
        )
        self.falco_server = ThreadingHTTPServer((host, falco_port), falco_handler)
        self.falco_port = self.falco_server.server_address[1]

        # Configure Audit server
        audit_handler = type(
            "BoundAuditHandler",
            (AuditStreamHandler,),
            {"daemon_instance": self.daemon, "expected_token": audit_token},
        )
        self.audit_server = ThreadingHTTPServer((host, audit_port), audit_handler)
        self.audit_port = self.audit_server.server_address[1]

        self._falco_thread: threading.Thread | None = None
        self._audit_thread: threading.Thread | None = None

    def start(self) -> None:
        """Start both webhook listeners in background daemon threads."""
        self._falco_thread = threading.Thread(
            target=self.falco_server.serve_forever, daemon=True, name="falco-webhook"
        )
        self._audit_thread = threading.Thread(
            target=self.audit_server.serve_forever, daemon=True, name="audit-webhook"
        )
        self._falco_thread.start()
        self._audit_thread.start()
        logger.info(
            "MultiSourceWebhookServer listening on %s: Falco=%d, Audit=%d",
            self.host,
            self.falco_port,
            self.audit_port,
        )

    def shutdown(self) -> None:
        """Gracefully shut down both HTTP servers."""
        self.falco_server.shutdown()
        self.falco_server.server_close()
        self.audit_server.shutdown()
        self.audit_server.server_close()
        if self._falco_thread:
            self._falco_thread.join(timeout=2.0)
        if self._audit_thread:
            self._audit_thread.join(timeout=2.0)
