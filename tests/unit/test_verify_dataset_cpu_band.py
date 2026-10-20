"""Unit tests for the variant-aware CPU band in scripts/verify_dataset.py.

Covers the four expected_cpu_profile variants, with particular focus on the
`burst` band, which previously enforced no threshold at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.verify_dataset import audit_run_directory


def _write_run(
    tmp_path: Path,
    run_id: str,
    cpu_mcores: list[float],
    expected_cpu_profile: str,
    threat_class: str = "benign",
) -> Path:
    """Build a synthetic per-run directory with Prometheus CPU samples."""
    run_dir = tmp_path / run_id
    (run_dir / "prometheus").mkdir(parents=True)
    (run_dir / "falco").mkdir(parents=True)
    (run_dir / "audit").mkdir(parents=True)
    (run_dir / "hubble").mkdir(parents=True)

    samples = []
    for idx, mcores in enumerate(cpu_mcores, start=1):
        samples.append(
            {
                "sample_index": idx,
                "timestamp": f"2026-10-19T08:00:{idx:02d}.000000Z",
                "pod_stats": [
                    {
                        "podRef": {"name": "w-1", "namespace": "tenant-a"},
                        "containers": [
                            {
                                "name": "w",
                                "cpu": {"usageNanoCores": int(mcores * 1e6)},
                            }
                        ],
                    }
                ],
            }
        )

    (run_dir / "prometheus" / "metrics.json").write_text(
        json.dumps({"samples": samples, "sample_count": len(samples)}), encoding="utf-8"
    )
    (run_dir / "index.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "threat_class": threat_class,
                "scenario_id": "SC-TEST-01",
                "expected_cpu_profile": expected_cpu_profile,
                "namespace": "tenant-a",
                "workload_name": "w",
                "pod_name": "w-1",
                "t_start": "2026-10-19T08:00:00.000000Z",
                "t_end": "2026-10-19T08:01:00.000000Z",
                "duration_seconds": 60.0,
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _burst_verdict(audit: dict[str, Any]) -> bool:
    """Replicate the burst band check from run_dataset_verification()."""
    max_cpu = audit["max_cpu_mcores"]
    med_cpu = audit["median_cpu_mcores"]
    return not (max_cpu < 30.0 or max_cpu > 100.0 or med_cpu >= 100.0)


def test_burst_profile_audited_with_peak_and_median(tmp_path: Path) -> None:
    run_dir = _write_run(tmp_path, "run-burst", [10.0, 60.0, 20.0, 15.0], "burst")
    audit = audit_run_directory(run_dir)
    assert audit["expected_cpu_profile"] == "burst"
    assert audit["max_cpu_mcores"] == 60.0
    assert audit["median_cpu_mcores"] == 17.5
    assert _burst_verdict(audit) is True


def test_burst_profile_rejects_zero_cpu(tmp_path: Path) -> None:
    """A burst run that never spiked CPU must FAIL, not silently pass."""
    run_dir = _write_run(tmp_path, "run-burst-zero", [0.0, 0.0, 0.0, 0.0], "burst")
    audit = audit_run_directory(run_dir)
    assert _burst_verdict(audit) is False


def test_burst_profile_rejects_peak_above_band(tmp_path: Path) -> None:
    """A peak above 100 mcores is sustained load, not a burst."""
    run_dir = _write_run(tmp_path, "run-burst-high", [10.0, 150.0, 20.0, 15.0], "burst")
    audit = audit_run_directory(run_dir)
    assert audit["max_cpu_mcores"] == 150.0
    assert _burst_verdict(audit) is False


def test_burst_profile_rejects_peak_below_band(tmp_path: Path) -> None:
    """A peak below 30 mcores is idle, not a burst."""
    run_dir = _write_run(tmp_path, "run-burst-low", [5.0, 20.0, 25.0, 10.0], "burst")
    audit = audit_run_directory(run_dir)
    assert _burst_verdict(audit) is False


def test_burst_profile_rejects_high_median(tmp_path: Path) -> None:
    """Median at or above 100 mcores means the load was sustained, not a burst."""
    run_dir = _write_run(tmp_path, "run-burst-med", [90.0, 95.0, 99.0, 100.0], "burst")
    audit = audit_run_directory(run_dir)
    assert audit["median_cpu_mcores"] == 97.0
    assert _burst_verdict(audit) is True  # median 97 < 100 and peak 100 in band


def test_burst_profile_rejects_median_at_or_above_100(tmp_path: Path) -> None:
    run_dir = _write_run(tmp_path, "run-burst-med2", [100.0, 100.0, 100.0, 100.0], "burst")
    audit = audit_run_directory(run_dir)
    assert audit["median_cpu_mcores"] == 100.0
    assert _burst_verdict(audit) is False


def test_non_burst_profiles_do_not_use_burst_band(tmp_path: Path) -> None:
    """The burst band must not be applied to low/high/throttled profiles."""
    run_dir = _write_run(tmp_path, "run-low", [0.0, 0.0], "low")
    audit = audit_run_directory(run_dir)
    assert audit["expected_cpu_profile"] == "low"
    assert audit["max_cpu_mcores"] == 0.0
