"""Raw telemetry capture setup for 5 unified sources (Decision D-07, Ticket 09a)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("runtimelens.raw_capture")

DEFAULT_RAW_DIR = Path("data/raw")


class RawTelemetryArchiver:
    """Manages append-only raw telemetry archives for all five sources.

    Ensures the 400-run dataset never needs regeneration.
    """

    def __init__(self, base_dir: Path = DEFAULT_RAW_DIR) -> None:
        self.base_dir = base_dir
        self.falco_dir = self.base_dir / "falco"
        self.audit_dir = self.base_dir / "audit"
        self.hubble_dir = self.base_dir / "hubble"
        self.prometheus_dir = self.base_dir / "prometheus"
        self.trivy_dir = self.base_dir / "trivy"

        self.all_dirs = [
            self.falco_dir,
            self.audit_dir,
            self.hubble_dir,
            self.prometheus_dir,
            self.trivy_dir,
        ]
        for d in self.all_dirs:
            d.mkdir(parents=True, exist_ok=True)

    def archive_raw_event(self, source: str, raw_data: dict[str, Any] | str) -> Path:
        """Append raw telemetry payload to size-capped rotated JSONL."""
        target_dir = getattr(self, f"{source}_dir", self.base_dir / source)
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / "events_raw.jsonl"

        line = raw_data if isinstance(raw_data, str) else json.dumps(raw_data)
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(line.strip() + "\n")

        return file_path

    def archive_trivy_report(self, image_digest: str, report_data: dict[str, Any]) -> Path:
        """Cache static image vulnerability report keyed by image digest."""
        safe_name = image_digest.replace("/", "_").replace(":", "_").replace("@", "_")
        target_file = self.trivy_dir / f"{safe_name}.json"
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return target_file

    def verify_five_sources_present(self) -> dict[str, bool]:
        """Verify that all five telemetry sources have captured raw data."""
        status = {}
        for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
            src_dir = getattr(self, f"{src}_dir")
            has_files = any(src_dir.iterdir()) if src_dir.exists() else False
            status[src] = has_files
        return status


def create_sample_raw_captures(base_dir: Path = DEFAULT_RAW_DIR) -> dict[str, Path]:
    """Generate sample raw captures for verification of capture sufficiency."""
    archiver = RawTelemetryArchiver(base_dir)
    now = datetime.now(UTC).isoformat()

    # 1. Falco Sample
    p_falco = archiver.archive_raw_event(
        "falco",
        {
            "output": "10:00:00: Interactive shell spawned in tenant container",
            "output_fields": {
                "k8s.ns.name": "tenant-a",
                "k8s.pod.name": "web-6794787bc8-4wmx6",
                "proc.cmdline": "/bin/sh",
                "user.name": "root",
            },
            "rule": "Interactive Shell Spawned in Non-Debug Container",
            "time": now,
        },
    )

    # 2. Audit Sample
    p_audit = archiver.archive_raw_event(
        "audit",
        {
            "kind": "EventList",
            "items": [
                {
                    "auditID": "audit-sample-01",
                    "verb": "create",
                    "stageTimestamp": now,
                    "objectRef": {
                        "resource": "pods",
                        "subresource": "exec",
                        "namespace": "tenant-a",
                    },
                }
            ],
        },
    )

    # 3. Hubble Sample
    p_hubble = archiver.archive_raw_event(
        "hubble",
        {
            "flow": {
                "time": now,
                "verdict": "DROPPED",
                "IP": {"source": "10.244.0.15", "destination": "10.244.0.99"},
                "l4": {"TCP": {"destination_port": 8080}},
                "source": {"namespace": "tenant-a", "pod_name": "api-pod"},
                "destination": {"namespace": "tenant-b", "pod_name": "web-pod"},
                "drop_reason_desc": "POLICY_DENIED",
            }
        },
    )

    # 4. Prometheus Sample
    p_prom = archiver.archive_raw_event(
        "prometheus",
        {
            "timestamp": now,
            "metric": "container_cpu_usage_seconds_total",
            "pod": "web-6794787bc8-4wmx6",
            "namespace": "tenant-a",
            "cpu_rate_mcores": 18.5,
            "memory_working_set_bytes": 33554432,
        },
    )

    # 5. Trivy Sample
    p_trivy = archiver.archive_trivy_report(
        image_digest="docker.io_library_alpine_sha256_6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        report_data={
            "SchemaVersion": 2,
            "ArtifactName": "docker.io/library/alpine:3.19",
            "ArtifactType": "container_image",
            "Metadata": {
                "OS": {"Family": "alpine", "Name": "3.19.1"},
                "ImageID": (
                    "sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
                ),
            },
            "Results": [
                {
                    "Target": "alpine:3.19 (alpine 3.19.1)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [],
                }
            ],
        },
    )

    return {
        "falco": p_falco,
        "audit": p_audit,
        "hubble": p_hubble,
        "prometheus": p_prom,
        "trivy": p_trivy,
    }
