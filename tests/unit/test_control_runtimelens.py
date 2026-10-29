"""Unit tests for the control-runtimelens verification harness CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.control_runtimelens import (
    cmd_doctor,
    cmd_post_event,
    cmd_start_webhook,
    cmd_stop_webhook,
    cmd_verify_audit,
)


def test_control_doctor(capsys) -> None:
    """Test doctor diagnostic check returns 0."""
    args = argparse.Namespace()
    ret = cmd_doctor(args)
    captured = capsys.readouterr()
    assert ret == 0
    assert "[PASS] Python version" in captured.out
    assert "[PASS] RuntimeLens core package loaded" in captured.out


def test_control_start_webhook_invalid_host(tmp_path: Path) -> None:
    """Test start-webhook refuses non-loopback hosts."""
    args = argparse.Namespace(
        host="0.0.0.0",
        port=19800,
        audit_file=str(tmp_path / "audit.jsonl"),
        secret="token",
        pid_file=str(tmp_path / "server.pid"),
    )
    ret = cmd_start_webhook(args)
    assert ret == 1
    assert not (tmp_path / "server.pid").exists()


def test_control_webhook_e2e_lifecycle(tmp_path: Path, capsys) -> None:
    """Test full webhook lifecycle: start, post inline, post file, post long json, audit, stop."""
    audit_file = tmp_path / "audit.jsonl"
    pid_file = tmp_path / "server.pid"
    port = 19801
    secret = "e2e-secret-key"

    # 1. Start server
    start_args = argparse.Namespace(
        host="127.0.0.1",
        port=port,
        audit_file=str(audit_file),
        secret=secret,
        pid_file=str(pid_file),
    )
    ret_start = cmd_start_webhook(start_args)
    assert ret_start == 0
    assert pid_file.exists()

    try:
        # 2. Post inline JSON
        post_inline_args = argparse.Namespace(
            host="127.0.0.1",
            port=port,
            endpoint="/falco",
            secret=secret,
            payload=json.dumps(
                {
                    "output": "inline test",
                    "output_fields": {
                        "k8s.ns.name": "tenant-a",
                        "k8s.pod.name": "web-pod",
                        "proc.cmdline": "nginx",
                        "time": "2026-10-23T00:00:00Z",
                    },
                }
            ),
        )
        assert cmd_post_event(post_inline_args) == 0

        # 3. Post payload from file
        payload_file = tmp_path / "payload.json"
        payload_file.write_text(
            json.dumps(
                {
                    "output": "file test",
                    "output_fields": {
                        "k8s.ns.name": "tenant-a",
                        "k8s.pod.name": "web-pod-2",
                        "proc.cmdline": "nginx -s reload",
                        "time": "2026-10-23T00:00:01Z",
                    },
                }
            )
        )
        post_file_args = argparse.Namespace(
            host="127.0.0.1",
            port=port,
            endpoint="/falco",
            secret=secret,
            payload=str(payload_file),
        )
        assert cmd_post_event(post_file_args) == 0

        # 4. Post long JSON string (>255 characters, testing OSError avoidance)
        long_payload = {
            "output": "A" * 300,
            "output_fields": {
                "k8s.ns.name": "tenant-b",
                "k8s.pod.name": "db-pod",
                "proc.cmdline": "B" * 100,
                "time": "2026-10-23T00:00:02Z",
            },
        }
        post_long_args = argparse.Namespace(
            host="127.0.0.1",
            port=port,
            endpoint="/falco",
            secret=secret,
            payload=json.dumps(long_payload),
        )
        assert cmd_post_event(post_long_args) == 0

        # 5. Post unauthorized (should return 401, not fail fatally)
        unauth_args = argparse.Namespace(
            host="127.0.0.1",
            port=port,
            endpoint="/falco",
            secret="wrong-secret",
            payload='{"output": "unauth"}',
        )
        assert cmd_post_event(unauth_args) == 0

        # 6. Verify audit log chain
        audit_args = argparse.Namespace(audit_file=str(audit_file))
        assert cmd_verify_audit(audit_args) == 0
        captured = capsys.readouterr()
        assert '"valid": true' in captured.out
        assert '"record_count": 3' in captured.out

    finally:
        # 7. Stop server
        stop_args = argparse.Namespace(pid_file=str(pid_file))
        assert cmd_stop_webhook(stop_args) == 0
        assert not pid_file.exists()
