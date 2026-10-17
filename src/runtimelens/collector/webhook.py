"""Falco HTTP JSON Webhook Receiver and Minimal Vertical Slice Processor."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from runtimelens.audit.writer import AuditWriter
from runtimelens.classifiers.rules import classify_rules
from runtimelens.models.decision import AuditRecord
from runtimelens.normalizer.falco import normalize_falco_event
from runtimelens.policy.engine import evaluate_policy

logger = logging.getLogger("runtimelens.webhook")

DEFAULT_AUDIT_PATH = Path("data/audit/decisions.jsonl")


def process_falco_payload(
    raw_payload: dict[str, Any],
    audit_writer: AuditWriter,
    dry_run: bool = True,
) -> AuditRecord:
    """Process a single raw Falco event end-to-end through the vertical slice."""
    # 1. Normalize
    canonical_event = normalize_falco_event(raw_payload)

    # 2. Classify (Rule-based minimal engine)
    classification = classify_rules(canonical_event)

    # 3. Policy Evaluation
    decision = evaluate_policy(classification, canonical_event, dry_run=dry_run)

    # 4. Tamper-evident Audit Logging
    audit_record = audit_writer.write_record(
        event=canonical_event,
        classification=classification,
        decision=decision,
    )

    return audit_record


class FalcoWebhookHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Falco JSON webhook alerts."""

    audit_writer: AuditWriter

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Empty body"}')
            return

        body = self.rfile.read(content_length)
        try:
            raw_event = json.loads(body.decode("utf-8"))
            record = process_falco_payload(
                raw_payload=raw_event,
                audit_writer=self.audit_writer,
                dry_run=True,
            )
            response = {
                "status": "ok",
                "event_id": record.event_id,
                "action": record.decision.action,
                "record_hash": record.record_hash,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception as e:
            logger.exception("Failed to process webhook payload")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stdout access logging to prevent noisy terminal logs."""
        pass


def run_webhook_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    audit_path: Path = DEFAULT_AUDIT_PATH,
) -> ThreadingHTTPServer:
    """Instantiate and start the webhook receiver bound strictly to 127.0.0.1."""
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError(f"Safety violation: Webhook must bind to 127.0.0.1, got {host}")

    writer = AuditWriter(audit_path)
    FalcoWebhookHandler.audit_writer = writer

    server = ThreadingHTTPServer((host, port), FalcoWebhookHandler)
    logger.info("Falco webhook receiver running on http://%s:%d", host, port)
    return server
