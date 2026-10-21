"""Unit tests for deterministic pod-spec fact extraction (Report Section 5.3, Ticket 06a)."""

from __future__ import annotations

import json
from pathlib import Path

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture
from runtimelens.features.extractor import extract_features_from_run_dir


def _create_minimal_run_dir(run_path: Path) -> None:
    for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
        (run_path / src).mkdir(parents=True, exist_ok=True)
    with open(run_path / "falco" / "events.jsonl", "w", encoding="utf-8") as f:
        f.write("\n")
    with open(run_path / "audit" / "events.jsonl", "w", encoding="utf-8") as f:
        f.write("\n")
    with open(run_path / "hubble" / "flows.jsonl", "w", encoding="utf-8") as f:
        f.write("\n")
    with open(run_path / "prometheus" / "metrics.json", "w", encoding="utf-8") as f:
        json.dump({"pod_stats": []}, f)
    with open(run_path / "trivy" / "report.json", "w", encoding="utf-8") as f:
        json.dump({"SchemaVersion": 2, "Results": []}, f)


def test_pod_spec_feature_extraction_socket(tmp_path: Path) -> None:
    r_dir = tmp_path / "run-test-socket"
    _create_minimal_run_dir(r_dir)

    collector = PerRunTelemetryCapture(tmp_path)
    pod_spec = {
        "spec": {
            "volumes": [
                {
                    "name": "socket-vol",
                    "hostPath": {"path": "/opt/runtimelens-dummy/docker.sock", "type": "File"},
                }
            ],
            "containers": [{"name": "worker", "securityContext": {"privileged": False}}],
        }
    }
    collector.attach_pod_spec(r_dir, pod_spec)

    vec = extract_features_from_run_dir(r_dir)
    assert vec[0] == 1.0  # host_runtime_socket_mounted
    assert vec[1] == 0.0  # sensitive_host_path_mounted
    assert vec[2] == 0.0  # privileged_container


def test_pod_spec_feature_extraction_sensitive_mount(tmp_path: Path) -> None:
    r_dir = tmp_path / "run-test-path"
    _create_minimal_run_dir(r_dir)

    collector = PerRunTelemetryCapture(tmp_path)
    pod_spec = {
        "spec": {
            "volumes": [
                {
                    "name": "etc-vol",
                    "hostPath": {"path": "/opt/runtimelens-dummy/etc", "type": "Directory"},
                }
            ],
            "containers": [{"name": "worker", "securityContext": {"privileged": False}}],
        }
    }
    collector.attach_pod_spec(r_dir, pod_spec)

    vec = extract_features_from_run_dir(r_dir)
    assert vec[0] == 0.0  # host_runtime_socket_mounted
    assert vec[1] == 1.0  # sensitive_host_path_mounted
    assert vec[2] == 0.0  # privileged_container


def test_pod_spec_feature_extraction_privileged(tmp_path: Path) -> None:
    r_dir = tmp_path / "run-test-priv"
    _create_minimal_run_dir(r_dir)

    collector = PerRunTelemetryCapture(tmp_path)
    pod_spec = {
        "spec": {
            "volumes": [],
            "containers": [{"name": "worker", "securityContext": {"privileged": True}}],
        }
    }
    collector.attach_pod_spec(r_dir, pod_spec)

    vec = extract_features_from_run_dir(r_dir)
    assert vec[0] == 0.0  # host_runtime_socket_mounted
    assert vec[1] == 0.0  # sensitive_host_path_mounted
    assert vec[2] == 1.0  # privileged_container


def test_pod_spec_sanitization_zero_leakage(tmp_path: Path) -> None:
    r_dir = tmp_path / "run-test-leak"
    _create_minimal_run_dir(r_dir)

    collector = PerRunTelemetryCapture(tmp_path)
    raw_spec = {
        "metadata": {
            "name": "worker-task-4c17",
            "scenario_id": "TMPL-ESC-03",
            "threat_class": "container_escape",
            "run_id": "run-s4a-04",
        },
        "spec": {
            "volumes": [],
            "containers": [{"name": "worker", "securityContext": {"privileged": False}}],
        },
    }
    collector.attach_pod_spec(r_dir, raw_spec)

    spec_file = r_dir / "pod" / "spec.json"
    assert spec_file.exists()
    content = spec_file.read_text(encoding="utf-8")
    assert "TMPL-ESC-03" not in content
    assert "container_escape" not in content
    assert "run-s4a-04" not in content
