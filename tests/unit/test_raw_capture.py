"""Unit tests for raw telemetry capture architecture across all 5 sources (Ticket 09a)."""

import tempfile
from pathlib import Path

from runtimelens.collector.raw_capture import RawTelemetryArchiver, create_sample_raw_captures


def test_raw_telemetry_archiver_all_five_sources() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        base_path = Path(tmp_dir)
        archiver = RawTelemetryArchiver(base_path)

        # Before captures
        status_before = archiver.verify_five_sources_present()
        assert all(not present for present in status_before.values())

        # Generate sample raw captures across all 5 sources
        paths = create_sample_raw_captures(base_path)
        assert len(paths) == 5

        # After captures: all 5 sources verified present
        status_after = archiver.verify_five_sources_present()
        assert all(present for present in status_after.values()), f"Missing sources: {status_after}"

        # Verify raw JSONL contents
        for src in ["falco", "audit", "hubble", "prometheus"]:
            p = paths[src]
            assert p.exists()
            assert p.stat().st_size > 0

        # Verify static Trivy vulnerability report
        trivy_file = paths["trivy"]
        assert trivy_file.exists()
        assert trivy_file.suffix == ".json"
