"""Integration tests for live multi-source correlation wiring (Ticket 04-live)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from runtimelens.audit.writer import AuditWriter
from runtimelens.collector.live_wiring import LiveCorrelationDaemon, MultiSourceWebhookServer
from runtimelens.controller.quarantine import MockKubernetesClient, QuarantineController


def _make_sample_falco_payload(
    namespace: str = "tenant-a",
    pod_name: str = "web-frontend-9999",
    timestamp: str | None = None,
) -> dict[str, Any]:
    ts = timestamp or datetime.now(UTC).isoformat()
    return {
        "output": "12:00:00.000000000: Warning Shell spawned in container (user=root ...)",
        "priority": "Warning",
        "rule": "Terminal shell in container",
        "time": ts,
        "output_fields": {
            "container.id": "c1234567890a",
            "container.name": "web",
            "container.image.repository": "docker.io/library/nginx",
            "k8s.ns.name": namespace,
            "k8s.pod.name": pod_name,
            "proc.name": "sh",
            "proc.pname": "containerd-shim",
            "proc.cmdline": "/bin/sh",
            "user.name": "root",
            "user.uid": 0,
            "evt.type": "execve",
        },
    }


def _make_sample_audit_payload(
    namespace: str = "tenant-a",
    pod_name: str = "web-frontend-9999",
    timestamp: str | None = None,
    username: str = "kubernetes-admin",
) -> dict[str, Any]:
    ts = timestamp or datetime.now(UTC).isoformat()
    return {
        "kind": "EventList",
        "apiVersion": "audit.k8s.io/v1",
        "items": [
            {
                "level": "Metadata",
                "auditID": "audit-id-1234",
                "stage": "ResponseComplete",
                "requestURI": f"/api/v1/namespaces/{namespace}/pods/{pod_name}/exec",
                "verb": "create",
                "user": {"username": username},
                "objectRef": {
                    "resource": "pods",
                    "namespace": namespace,
                    "name": pod_name,
                    "subresource": "exec",
                },
                "stageTimestamp": ts,
            }
        ],
    }


def test_daemon_direct_correlation(tmp_path: Path) -> None:
    audit_file = tmp_path / "live_audit.jsonl"
    writer = AuditWriter(audit_file)
    daemon = LiveCorrelationDaemon(audit_writer=writer, correlation_window_seconds=30.0)

    now = datetime.now(UTC).isoformat()
    audit_payload = _make_sample_audit_payload(timestamp=now)
    falco_payload = _make_sample_falco_payload(timestamp=now)

    # Ingest Audit first, then Falco
    count = daemon.ingest_raw_audit_payload(audit_payload)
    assert count == 1

    record = daemon.ingest_raw_falco_payload(falco_payload)
    assert record is not None
    assert record.event.orchestration is not None
    assert record.event.orchestration.verb == "create"
    assert record.event.orchestration.resource == "pods"
    assert record.event.orchestration.subresource == "exec"
    assert record.event.orchestration.request_user == "kubernetes-admin"

    # Verify audit record written to disk
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    disk_record = json.loads(lines[0])
    assert disk_record["event"]["orchestration"]["verb"] == "create"


def test_concurrent_webhook_streaming(tmp_path: Path) -> None:
    audit_file = tmp_path / "stream_audit.jsonl"
    writer = AuditWriter(audit_file)
    mock_client = MockKubernetesClient(initial_pods={"tenant-a/web-frontend-9999": {"app": "web"}})
    controller = QuarantineController(k8s_client=mock_client)
    daemon = LiveCorrelationDaemon(
        audit_writer=writer,
        quarantine_controller=controller,
        dry_run=True,
    )

    server = MultiSourceWebhookServer(
        daemon=daemon,
        host="127.0.0.1",
        falco_port=0,
        audit_port=0,
        falco_token="secret-falco-token",
        audit_token="secret-audit-token",
    )
    server.start()

    try:
        falco_url = f"http://127.0.0.1:{server.falco_port}/"
        audit_url = f"http://127.0.0.1:{server.audit_port}/"

        now = datetime.now(UTC).isoformat()
        audit_payload = _make_sample_audit_payload(
            username="analyst_token=eyA12345678.payload.sig",
            timestamp=now,
        )
        falco_payload = _make_sample_falco_payload(timestamp=now)

        # 1. Post audit event to audit webhook
        with httpx.Client() as client:
            audit_resp = client.post(
                audit_url,
                json=audit_payload,
                headers={"Authorization": "Bearer secret-audit-token"},
            )
            assert audit_resp.status_code == 200
            assert audit_resp.json()["items_ingested"] == 1

            # 2. Post Falco event to Falco webhook
            falco_resp = client.post(
                falco_url,
                json=falco_payload,
                headers={"Authorization": "Bearer secret-falco-token"},
            )
            assert falco_resp.status_code == 200
            assert "record_id" in falco_resp.json()

        # 3. Assert correlation joined event and redacted token in user name
        assert len(daemon.records) == 1
        rec = daemon.records[0]
        assert rec.event.orchestration is not None
        req_user = rec.event.orchestration.request_user or ""
        assert "[REDACTED]" in req_user
        assert "ey" not in req_user

    finally:
        server.shutdown()
