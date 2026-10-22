"""Kubernetes API Audit Webhook Receiver (Decision D-07, Ticket 04)."""

from __future__ import annotations

import hmac
import json
import logging
import os
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

logger = logging.getLogger("runtimelens.audit_webhook")

DEFAULT_RAW_AUDIT_PATH = Path("data/raw/audit/audit_raw_events.jsonl")
MAX_AUDIT_PAYLOAD_BYTES = 10485760  # 10 MB batch limit
DEFAULT_AUDIT_TIMEOUT_SECONDS = 30.0

# In-memory sliding window rate limiter
RATE_LIMIT_WINDOW_SECONDS = 1.0
RATE_LIMIT_MAX_REQUESTS = 200
_request_timestamps: list[float] = []

# Global watermark state
_last_batch_timestamp: float = time.time()
_seen_audit_ids: set[str] = set()


def is_rate_limited() -> bool:
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    global _request_timestamps
    _request_timestamps = [ts for ts in _request_timestamps if ts > cutoff]
    if len(_request_timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    _request_timestamps.append(now)
    return False


def get_expected_audit_token() -> str:
    """Retrieve the expected K8s audit webhook bearer token strictly from environment."""
    token = os.environ.get("K8S_AUDIT_WEBHOOK_SECRET")
    if not token or not token.strip():
        raise RuntimeError(
            "Security violation: K8S_AUDIT_WEBHOOK_SECRET is not configured. "
            "Audit webhook receiver refuses to operate without authentication."
        )
    return token.strip()


def is_audit_telemetry_degraded(timeout_seconds: float = DEFAULT_AUDIT_TIMEOUT_SECONDS) -> bool:
    """Check if the audit webhook has experienced an ingestion gap exceeding threshold."""
    return (time.time() - _last_batch_timestamp) > timeout_seconds


class AuditWebhookHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Kubernetes API Audit batch events."""

    raw_log_path: Path

    def log_request_event(self, status: int, request_id: str) -> None:
        """Log request metadata without ever leaking query strings, tokens, or credentials."""
        parsed_url = urllib.parse.urlparse(self.path)
        sanitized_path = parsed_url.path  # Path only! Zero token or query string
        logger.info(
            "Audit webhook processed: method=%s path=%s status=%d request_id=%s",
            self.command,
            sanitized_path,
            status,
            request_id,
        )

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default BaseHTTPRequestHandler access log."""
        pass

    def _is_authenticated(self) -> bool:
        """Verify pre-shared bearer token using constant-time comparison."""
        expected = get_expected_audit_token().encode("utf-8")
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return False

        bearer_token = auth_header[7:].strip().encode("utf-8")
        return hmac.compare_digest(bearer_token, expected)

    def _send_json_error(self, status: int, message: str, request_id: str = "") -> None:
        data = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
        self.log_request_event(status, request_id)

    def do_POST(self) -> None:  # noqa: N802
        request_id = str(uuid.uuid4())[:8]
        content_length = int(self.headers.get("Content-Length", 0))

        # 1. Rate Limiting Check
        if is_rate_limited():
            if content_length > 0:
                self.rfile.read(content_length)
            self._send_json_error(429, "Too Many Requests: Rate limit exceeded", request_id)
            return

        # 2. Authentication Check (Bearer token required)
        if not self._is_authenticated():
            if content_length > 0:
                self.rfile.read(min(content_length, 4096))
            self._send_json_error(401, "Unauthorized: Invalid or missing audit token", request_id)
            return

        # 3. Payload Size Limit Check (10 MB max)
        if content_length == 0:
            self._send_json_error(400, "Empty body", request_id)
            return

        if content_length > MAX_AUDIT_PAYLOAD_BYTES:
            self.rfile.read(min(content_length, 4096))
            self._send_json_error(
                413, "Payload Too Large: Maximum allowed audit batch is 10 MB", request_id
            )
            return

        body = self.rfile.read(content_length)

        # 4. Write Raw Batch to Append-Only JSONL BEFORE parsing (Audit Integrity Invariant)
        self.raw_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.raw_log_path, "ab") as f:
            f.write(body + b"\n")

        # 5. Parse and Deduplicate by auditID
        try:
            batch_data = json.loads(body.decode("utf-8"))
            items = batch_data.get("items", []) if isinstance(batch_data, dict) else []

            global _last_batch_timestamp, _seen_audit_ids
            _last_batch_timestamp = time.time()
            new_events_count = 0

            for event in items:
                if isinstance(event, dict):
                    audit_id = str(event.get("auditID") or "")
                    if audit_id and audit_id not in _seen_audit_ids:
                        _seen_audit_ids.add(audit_id)
                        new_events_count += 1

            # Bounded deduplication cache
            if len(_seen_audit_ids) > 50000:
                _seen_audit_ids.clear()

            response = json.dumps(
                {
                    "status": "ok",
                    "batch_events_received": len(items),
                    "new_events_deduped": new_events_count,
                }
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.log_request_event(200, request_id)
        except Exception as e:
            logger.exception("Failed to process audit batch JSON")
            self._send_json_error(400, f"Malformed audit batch JSON: {e}", request_id)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def run_audit_webhook_server(
    host: str = "172.18.0.1",
    port: int = 8766,
    raw_path: Path = DEFAULT_RAW_AUDIT_PATH,
    cert_file: Path | None = None,
    key_file: Path | None = None,
) -> ThreadingHTTPServer:
    """Start the Kubernetes Audit Webhook Receiver bound strictly to internal IP."""
    if host not in {"127.0.0.1", "localhost", "172.18.0.1"}:
        raise ValueError(
            f"Safety violation: Audit webhook must bind to 127.0.0.1 or 172.18.0.1, got {host}"
        )

    AuditWebhookHandler.raw_log_path = raw_path
    server = ReusableThreadingHTTPServer((host, port), AuditWebhookHandler)
    if cert_file and key_file and cert_file.exists() and key_file.exists():
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_file), str(key_file))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        logger.info("Kubernetes Audit webhook receiver running on https://%s:%d (TLS)", host, port)
    else:
        logger.info("Kubernetes Audit webhook receiver running on http://%s:%d", host, port)
    return server
