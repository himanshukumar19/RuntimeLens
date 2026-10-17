"""Unit tests for minimal vertical slice: normalization -> classification -> policy -> audit log."""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from runtimelens.audit.writer import AuditWriter
from runtimelens.collector.webhook import process_falco_payload


def test_vertical_slice_benign_event() -> None:
    raw_event = {
        "output": "18:00:00: Routine web process started",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-74b88dfd9b-w6tl9",
            "k8s.pod.uid": "uid-web-01",
            "container.name": "web",
            "container.id": "c1234567890a",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "nc -l -p 8080",
            "proc.name": "nc",
            "user.name": "appuser",
            "user.uid": 10001,
        },
        "rule": "Process Execution",
        "time": "2026-10-17T18:00:00.000000Z",
    }

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        record = process_falco_payload(raw_event, writer, dry_run=True)

        assert record.classification.predicted_class == "benign"
        assert record.decision.action == "log"
        assert record.prev_record_hash == "0" * 64
        assert len(record.record_hash) == 64

        # Verify file contents
        is_valid, count, err = AuditWriter.verify_chain(log_path)
        assert is_valid, f"Verification failed: {err}"
        assert count == 1
    finally:
        if log_path.exists():
            log_path.unlink()


def test_vertical_slice_unexpected_shell_privilege_abuse() -> None:
    raw_event = {
        "output": "18:01:00: Interactive shell spawned in tenant container",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-74b88dfd9b-w6tl9",
            "k8s.pod.uid": "uid-web-01",
            "container.name": "web",
            "container.id": "c1234567890a",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "/bin/sh",
            "proc.name": "sh",
            "user.name": "root",
            "user.uid": 0,
        },
        "rule": "Interactive Shell Spawned in Non-Debug Container",
        "time": "2026-10-17T18:01:00.000000Z",
    }

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        record = process_falco_payload(raw_event, writer, dry_run=True)

        assert record.classification.predicted_class == "privilege_abuse"
        assert record.decision.action == "alert"
        assert "unexpected_shell_execution" in record.event.baseline.deviations

        is_valid, count, err = AuditWriter.verify_chain(log_path)
        assert is_valid
        assert count == 1
    finally:
        if log_path.exists():
            log_path.unlink()


def test_vertical_slice_critical_mount_quarantine_dry_run() -> None:
    raw_event = {
        "output": "18:02:00: Sensitive host socket mounted into container",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "payment-style-5cdbff7bff-86ssl",
            "k8s.pod.uid": "uid-payment-01",
            "container.name": "payment-style",
            "container.id": "c9876543210b",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "dockerd --host unix:///var/run/docker.sock",
            "fd.name": "/var/run/docker.sock",
            "user.name": "root",
            "user.uid": 0,
        },
        "rule": "Launch Sensitive Mount Container",
        "time": "2026-10-17T18:02:00.000000Z",
    }

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        record = process_falco_payload(raw_event, writer, dry_run=True)

        assert record.classification.predicted_class == "container_escape"
        assert record.classification.severity >= 4.0
        assert record.decision.action == "quarantine"
        assert record.decision.dry_run is True
        assert record.decision.quarantine_labels == {"quarantine": "true"}

        is_valid, count, err = AuditWriter.verify_chain(log_path)
        assert is_valid
        assert count == 1
    finally:
        if log_path.exists():
            log_path.unlink()


def test_audit_hash_chain_tamper_detection() -> None:
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        # Write two valid records
        for i in range(2):
            raw = {
                "output": f"Event {i}",
                "output_fields": {"k8s.ns.name": "tenant-a", "proc.cmdline": f"echo {i}"},
                "time": f"2026-10-17T18:0{i}:00Z",
            }
            process_falco_payload(raw, writer, dry_run=True)

        is_valid, count, err = AuditWriter.verify_chain(log_path)
        assert is_valid
        assert count == 2

        # Tamper with the first line in the file
        lines = log_path.read_text(encoding="utf-8").splitlines()
        tampered_first = json.loads(lines[0])
        # Forged classification
        tampered_first["classification"]["predicted_class"] = "container_escape"
        lines[0] = json.dumps(tampered_first)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Verify that tamper-evidence detection flags the forgery
        is_valid, count, err = AuditWriter.verify_chain(log_path)
        assert not is_valid
        assert "Hash mismatch at record 0" in str(err)
    finally:
        if log_path.exists():
            log_path.unlink()
