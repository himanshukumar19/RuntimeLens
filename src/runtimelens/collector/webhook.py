"""Falco HTTP JSON Webhook Receiver and Minimal Vertical Slice Processor."""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
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
MAX_PAYLOAD_BYTES = 65536  # 64 KB limit
DEFAULT_WEBHOOK_TOKEN = "runtimelens-lab-pre-shared-webhook-token-v1"

# In-memory sliding window rate limiter
RATE_LIMIT_WINDOW_SECONDS = 1.0
RATE_LIMIT_MAX_REQUESTS = 100
_request_timestamps: list[float] = []


def is_rate_limited() -> bool:
    """Check if the current request exceeds the rate limit window."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    global _request_timestamps
    _request_timestamps = [ts for ts in _request_timestamps if ts > cutoff]
    if len(_request_timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    _request_timestamps.append(now)
    return False


def get_expected_webhook_token() -> str:
    """Retrieve the expected shared webhook token from environment."""
    return os.environ.get("FALCO_WEBHOOK_SECRET") or DEFAULT_WEBHOOK_TOKEN


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
    """HTTP Request Handler for Falco JSON webhook alerts with security guardrails."""

    audit_writer: AuditWriter

    def _is_authenticated(self) -> bool:
        """Verify pre-shared webhook token using constant-time comparison."""
        import hmac

        expected = get_expected_webhook_token().encode("utf-8")

        # Check headers (X-Webhook-Token or Authorization: Bearer)
        header_token = self.headers.get("X-Webhook-Token")
        if header_token and hmac.compare_digest(header_token.strip().encode("utf-8"), expected):
            return True

        auth_header = self.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip().encode("utf-8")
            if hmac.compare_digest(bearer_token, expected):
                return True

        # Fallback query parameter specifically required by Falco native C++ http_output
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        token_list = query_params.get("token")
        if not token_list:
            return False
        return hmac.compare_digest(token_list[0].strip().encode("utf-8"), expected)

    def _send_json_error(self, status: int, message: str) -> None:
        """Send an RFC-compliant JSON error response."""
        data = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", 0))

        # 1. Rate Limiting Check
        if is_rate_limited():
            if content_length > 0:
                self.rfile.read(content_length)
            self._send_json_error(429, "Too Many Requests: Rate limit exceeded")
            return

        # 2. Authentication Check
        if not self._is_authenticated():
            if content_length > 0:
                self.rfile.read(min(content_length, MAX_PAYLOAD_BYTES))
            self._send_json_error(401, "Unauthorized: Invalid or missing webhook token")
            return

        # 3. Payload Size Limit Check
        if content_length == 0:
            self._send_json_error(400, "Empty body")
            return

        if content_length > MAX_PAYLOAD_BYTES:
            # Drain up to 4KB then reject
            self.rfile.read(min(content_length, 4096))
            self._send_json_error(413, "Payload Too Large: Maximum allowed size is 64 KB")
            return

        body = self.rfile.read(content_length)

        # 4. JSON Schema / Syntax Validation
        try:
            raw_event = json.loads(body.decode("utf-8"))
            if not isinstance(raw_event, dict):
                raise ValueError("Payload must be a JSON object")

            record = process_falco_payload(
                raw_payload=raw_event,
                audit_writer=self.audit_writer,
                dry_run=True,
            )
            response = json.dumps(
                {
                    "status": "ok",
                    "event_id": record.event_id,
                    "action": record.decision.action,
                    "record_hash": record.record_hash,
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except Exception as e:
            logger.exception("Failed to process webhook payload")
            self._send_json_error(400, f"Invalid JSON payload: {e}")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stdout access logging to prevent noisy terminal logs."""
        pass


def run_webhook_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    audit_path: Path = DEFAULT_AUDIT_PATH,
) -> ThreadingHTTPServer:
    """Start webhook receiver bound to 127.0.0.1 or internal kind bridge 172.18.0.1."""
    if host not in {"127.0.0.1", "localhost", "172.18.0.1"}:
        raise ValueError(
            f"Safety violation: Webhook must bind to 127.0.0.1 or 172.18.0.1, got {host}"
        )

    writer = AuditWriter(audit_path)
    FalcoWebhookHandler.audit_writer = writer

    server = ThreadingHTTPServer((host, port), FalcoWebhookHandler)
    logger.info("Falco webhook receiver running on http://%s:%d", host, port)
    return server
