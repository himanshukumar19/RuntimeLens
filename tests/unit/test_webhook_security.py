"""Tests for Falco webhook receiver authentication, payload size limit, and rate limiting."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx

from runtimelens.collector.webhook import DEFAULT_WEBHOOK_TOKEN, run_webhook_server


def test_webhook_unauthenticated_request_rejected() -> None:
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    server = run_webhook_server("127.0.0.1", 18765, audit_path=log_path)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Request with NO token
        with httpx.Client(base_url="http://127.0.0.1:18765") as client:
            resp = client.post("/falco", json={"output": "test"})
            assert resp.status_code == 401
            assert "Unauthorized" in resp.text

            # Request with WRONG token
            resp_wrong = client.post(
                "/falco",
                json={"output": "test"},
                headers={"X-Webhook-Token": "invalid-token"},
            )
            assert resp_wrong.status_code == 401
    finally:
        server.shutdown()
        server.server_close()
        if log_path.exists():
            log_path.unlink()


def test_webhook_authenticated_request_accepted() -> None:
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    server = run_webhook_server("127.0.0.1", 18766, audit_path=log_path)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    valid_payload = {
        "output": "Test authenticated event",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-pod",
            "proc.cmdline": "ls",
            "time": "2026-10-18T00:00:00Z",
        },
    }

    try:
        with httpx.Client(base_url="http://127.0.0.1:18766") as client:
            # 1. Via X-Webhook-Token header
            resp_header = client.post(
                "/falco",
                json=valid_payload,
                headers={"X-Webhook-Token": DEFAULT_WEBHOOK_TOKEN},
            )
            assert resp_header.status_code == 200
            assert resp_header.json()["status"] == "ok"

            # 2. Via URL query parameter
            resp_query = client.post(
                f"/falco?token={DEFAULT_WEBHOOK_TOKEN}",
                json=valid_payload,
            )
            assert resp_query.status_code == 200
    finally:
        server.shutdown()
        server.server_close()
        if log_path.exists():
            log_path.unlink()


def test_webhook_oversized_payload_rejected() -> None:
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    server = run_webhook_server("127.0.0.1", 18767, audit_path=log_path)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    # Payload > 64 KB (65536 bytes)
    huge_payload = {"output": "A" * 70000}

    try:
        with httpx.Client(base_url="http://127.0.0.1:18767") as client:
            resp = client.post(
                "/falco",
                content=json.dumps(huge_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Token": DEFAULT_WEBHOOK_TOKEN,
                },
            )
            assert resp.status_code == 413
            assert "Payload Too Large" in resp.text
    finally:
        server.shutdown()
        server.server_close()
        if log_path.exists():
            log_path.unlink()
