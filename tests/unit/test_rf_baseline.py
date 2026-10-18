"""Unit tests for feature extractor from raw telemetry (Ticket 08/Remediation)."""

from __future__ import annotations

import json
from pathlib import Path

from runtimelens.features.extractor import (
    FEATURE_NAMES,
    extract_dataset_from_run_dirs,
    extract_features_from_run_dir,
)


def _create_mock_run_dir(run_path: Path, is_socket: bool = False, has_shell: bool = False) -> None:
    for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
        (run_path / src).mkdir(parents=True, exist_ok=True)

    # 1. Falco event
    falco_events = []
    if is_socket:
        falco_events.append(
            {
                "rule": "Launch Sensitive Mount Container",
                "output_fields": {
                    "proc.cmdline": "ls -l /var/run/docker.sock",
                    "fd.name": "/var/run/docker.sock",
                    "k8s.pod.name": "web-01",
                    "user.name": "root",
                },
            }
        )
    if has_shell:
        falco_events.append(
            {
                "rule": "Interactive Shell Spawned in Non-Debug Container",
                "output_fields": {
                    "proc.cmdline": "/bin/sh -i",
                    "proc.name": "sh",
                    "k8s.pod.name": "payment-style-01",
                    "user.name": "worker",
                },
            }
        )

    with open(run_path / "falco" / "events.jsonl", "w", encoding="utf-8") as f:
        for evt in falco_events:
            f.write(json.dumps(evt) + "\n")

    # 2. Audit event
    with open(run_path / "audit" / "events.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps({"verb": "get", "objectRef": {"resource": "pods"}}) + "\n")

    # 3. Hubble flow
    flow_payload = {"flow": {"verdict": "FORWARDED", "IP": {"destination": "10.244.0.5"}}}
    with open(run_path / "hubble" / "flows.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(flow_payload) + "\n")

    # 4. Prometheus metrics
    with open(run_path / "prometheus" / "metrics.json", "w", encoding="utf-8") as f:
        json.dump({"pod_stats": [{"containers": [{"cpu": {"usageNanoCores": 15000000}}]}]}, f)

    # 5. Trivy report
    with open(run_path / "trivy" / "report.json", "w", encoding="utf-8") as f:
        json.dump({"SchemaVersion": 2, "Results": []}, f)

    # 6. Index file
    with open(run_path / "index.json", "w", encoding="utf-8") as f:
        json.dump({"threat_class": "container_escape" if is_socket else "benign"}, f)


def test_feature_extractor_from_run_dir(tmp_path: Path) -> None:
    r_dir = tmp_path / "run-001"
    _create_mock_run_dir(r_dir, is_socket=True, has_shell=True)

    vec = extract_features_from_run_dir(r_dir)
    assert len(vec) == len(FEATURE_NAMES)
    assert vec[0] == 1.0  # host_runtime_socket_mounted
    assert vec[1] == 0.0  # sensitive_host_path_mounted
    assert vec[3] == 1.0  # is_root_user
    assert vec[4] == 1.0  # is_shell_process


def test_extract_dataset_from_run_dirs(tmp_path: Path) -> None:
    r1 = tmp_path / "run-001"
    r2 = tmp_path / "run-002"
    _create_mock_run_dir(r1, is_socket=True)
    _create_mock_run_dir(r2, is_socket=False)

    X, y, ids = extract_dataset_from_run_dirs([r1, r2])
    assert X.shape == (2, len(FEATURE_NAMES))
    assert y.shape == (2,)
    assert ids == ["run-001", "run-002"]
    assert y[0] == 1  # container_escape
    assert y[1] == 0  # benign
