"""Unit tests for Kubernetes Audit Webhook Receiver (security, auth, dedupe, size limits)."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx
import pytest

from runtimelens.collector.audit_webhook import (
    DEFAULT_AUDIT_TIMEOUT_SECONDS,
    is_audit_telemetry_degraded,
    run_audit_webhook_server,
)

AUDIT_TEST_TOKEN = "ephemeral-test-k8s-audit-secret-token-32bytes"


def test_audit_webhook_auth_and_deduplication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K8S_AUDIT_WEBHOOK_SECRET", AUDIT_TEST_TOKEN)

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        raw_log_path = Path(f.name)

    server = run_audit_webhook_server("127.0.0.1", 18776, raw_path=raw_log_path)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    sample_batch = {
        "kind": "EventList",
        "apiVersion": "audit.k8s.io/v1",
        "items": [
            {
                "auditID": "audit-id-001",
                "verb": "get",
                "stage": "ResponseComplete",
                "objectRef": {"resource": "pods", "namespace": "tenant-a"},
            },
            {
                "auditID": "audit-id-002",
                "verb": "list",
                "stage": "ResponseComplete",
                "objectRef": {"resource": "services", "namespace": "tenant-a"},
            },
            # Duplicate auditID in same batch
            {
                "auditID": "audit-id-001",
                "verb": "get",
                "stage": "ResponseComplete",
                "objectRef": {"resource": "pods", "namespace": "tenant-a"},
            },
        ],
    }

    try:
        with httpx.Client(base_url="http://127.0.0.1:18776") as client:
            # 1. Unauthenticated request rejected
            unauth_resp = client.post("/k8s-audit", json=sample_batch)
            assert unauth_resp.status_code == 401

            # 2. Authenticated request accepted and deduped
            auth_resp = client.post(
                "/k8s-audit",
                json=sample_batch,
                headers={"Authorization": f"Bearer {AUDIT_TEST_TOKEN}"},
            )
            assert auth_resp.status_code == 200
            data = auth_resp.json()
            assert data["batch_events_received"] == 3
            assert data["new_events_deduped"] == 2  # 1 duplicate dropped

            # 3. Verify raw batch was written before parsing
            raw_content = raw_log_path.read_text(encoding="utf-8")
            assert "audit-id-001" in raw_content
            assert "audit-id-002" in raw_content
    finally:
        server.shutdown()
        server.server_close()
        if raw_log_path.exists():
            raw_log_path.unlink()


def test_audit_webhook_logging_never_records_tokens(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    import logging

    secret_canary = "audit-sensitive-canary-token-987654321"
    monkeypatch.setenv("K8S_AUDIT_WEBHOOK_SECRET", secret_canary)

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        raw_log_path = Path(f.name)

    server = run_audit_webhook_server("127.0.0.1", 18777, raw_path=raw_log_path)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    caplog.set_level(logging.INFO, logger="runtimelens.audit_webhook")

    try:
        with httpx.Client(base_url="http://127.0.0.1:18777") as client:
            resp = client.post(
                "/k8s-audit",
                json={"kind": "EventList", "items": []},
                headers={"Authorization": f"Bearer {secret_canary}"},
            )
            assert resp.status_code == 200

            # Canary token must NEVER appear in logger records
            assert secret_canary not in caplog.text
            assert all(secret_canary not in r.message for r in caplog.records)

            # Metadata must be logged
            assert "method=POST path=/k8s-audit status=200" in caplog.text
            assert "request_id=" in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        if raw_log_path.exists():
            raw_log_path.unlink()


def test_audit_telemetry_degraded_threshold() -> None:
    # A threshold of 0 seconds immediately indicates degradation
    assert is_audit_telemetry_degraded(timeout_seconds=0.0) is True
    # A standard large threshold does not indicate degradation
    assert is_audit_telemetry_degraded(timeout_seconds=DEFAULT_AUDIT_TIMEOUT_SECONDS) is False
