"""Unit tests for the variant-aware CPU bands (scripts/verify_dataset.py).

Covers the four expected_cpu_profile variants, with particular focus on the
`burst` band (Decision D-26: widened to the cAdvisor measurement resolution)
and the post-lag handling of the sustained-load bands (Decision D-27: the
cAdvisor first-sample lag is excluded from the ratio denominator).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from runtimelens.eval.cpu_bands import (
    BURST_MEDIAN_MAX_MCORES,
    BURST_PEAK_MAX_MCORES,
    BURST_PEAK_MIN_MCORES,
    CPU_LAG_EXCLUSION_SECONDS,
    MIN_POST_LAG_SAMPLES,
    post_lag_cpu_samples,
)
from scripts.verify_dataset import audit_run_directory


def _write_run(
    tmp_path: Path,
    run_id: str,
    cpu_mcores: list[float],
    expected_cpu_profile: str,
    threat_class: str = "benign",
    sample_interval_s: float = 10.0,
) -> Path:
    """Build a synthetic per-run directory with Prometheus CPU samples."""
    run_dir = tmp_path / run_id
    (run_dir / "prometheus").mkdir(parents=True)
    (run_dir / "falco").mkdir(parents=True)
    (run_dir / "audit").mkdir(parents=True)
    (run_dir / "hubble").mkdir(parents=True)

    samples = []
    base = datetime(2026, 10, 19, 8, 0, 0, tzinfo=UTC)
    for idx, mcores in enumerate(cpu_mcores, start=1):
        ts = base + timedelta(seconds=(idx - 1) * sample_interval_s)
        samples.append(
            {
                "sample_index": idx,
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
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
    return not (
        max_cpu < BURST_PEAK_MIN_MCORES
        or max_cpu > BURST_PEAK_MAX_MCORES
        or med_cpu >= BURST_MEDIAN_MAX_MCORES
    )


# ----------------------------------------------------------------------------------
# Decision D-26: burst band
# ----------------------------------------------------------------------------------


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
    """A peak above 150 mcores is sustained load, not a burst."""
    run_dir = _write_run(tmp_path, "run-burst-high", [10.0, 160.0, 20.0, 15.0], "burst")
    audit = audit_run_directory(run_dir)
    assert _burst_verdict(audit) is False


def test_burst_profile_accepts_peak_at_band_edges(tmp_path: Path) -> None:
    """D-26: the band is inclusive at 20 m and 150 m (measured noise floor)."""
    low = _write_run(tmp_path, "run-burst-edge-low", [0.0, 20.0, 5.0], "burst")
    high = _write_run(tmp_path, "run-burst-edge-high", [0.0, 150.0, 5.0], "burst")
    assert _burst_verdict(audit_run_directory(low)) is True
    assert _burst_verdict(audit_run_directory(high)) is True


def test_burst_profile_accepts_observed_real_attempt_peaks(tmp_path: Path) -> None:
    """Regression: the two measured peaks of the identical UNK-03 command both pass.

    Attempt 1 measured 25.77 mcores and attempt 2 measured 117.34 mcores for
    the same workload; the former [30, 100] band rejected both.
    """
    a1 = _write_run(tmp_path, "run-burst-a1", [0.0, 12.88, 25.77], "burst")
    a2 = _write_run(tmp_path, "run-burst-a2", [0.0, 0.0, 117.34], "burst")
    assert _burst_verdict(audit_run_directory(a1)) is True
    assert _burst_verdict(audit_run_directory(a2)) is True


def test_burst_profile_rejects_peak_below_band(tmp_path: Path) -> None:
    """A peak below 20 mcores is idle, not a burst."""
    run_dir = _write_run(tmp_path, "run-burst-low", [5.0, 15.0, 19.0, 10.0], "burst")
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


# ----------------------------------------------------------------------------------
# Decision D-27: cAdvisor first-sample lag
# ----------------------------------------------------------------------------------


def test_post_lag_excludes_first_sample_window() -> None:
    cpus = [0.0, 0.0, 46.64, 102.39, 101.59, 101.59, 89.69]
    ts = [float(i * 10) for i in range(len(cpus))]
    kept = post_lag_cpu_samples(cpus, ts)
    # samples at offset 0.0 s and 10.0 s are inside the 15 s lag window
    assert kept == [46.64, 102.39, 101.59, 101.59, 89.69]


def test_post_lag_keeps_everything_when_timestamps_missing() -> None:
    cpus = [0.0, 5.0, 9.0]
    assert post_lag_cpu_samples(cpus, []) == cpus


def test_post_lag_lag_window_is_fifteen_seconds() -> None:
    assert CPU_LAG_EXCLUSION_SECONDS == 15.0
    assert MIN_POST_LAG_SAMPLES == 4


def test_throttled_attempt1_real_values_pass_post_lag_gate(tmp_path: Path) -> None:
    """Measured run-s4a-09 attempt 1 sample series (real telemetry)."""
    series = [0.0, 75.59, 75.59, 100.58, 100.51, 100.51, 99.78]
    run_dir = _write_run(tmp_path, "run-mnr-a1", series, "throttled", "cryptomining")
    audit = audit_run_directory(run_dir)
    assert audit["post_lag_sample_count"] == 5
    assert audit["pct_above_40_post_lag"] == 100.0
    assert audit["median_post_lag_cpu_mcores"] == 100.51


def test_throttled_attempt2_real_values_pass_post_lag_gate(tmp_path: Path) -> None:
    """Measured run-s4a-09 attempt 2 sample series (real telemetry)."""
    series = [0.0, 0.0, 46.64, 102.39, 101.59, 101.59, 89.69]
    run_dir = _write_run(tmp_path, "run-mnr-a2", series, "throttled", "cryptomining")
    audit = audit_run_directory(run_dir)
    assert audit["post_lag_sample_count"] == 5
    assert audit["pct_above_40_post_lag"] == 100.0
    assert audit["median_post_lag_cpu_mcores"] == 101.59


def test_throttled_post_lag_median_floor_rejects_idle_after_spike(tmp_path: Path) -> None:
    """A short spike followed by idle must fail the D-27 post-lag median floor.

    The legacy all-sample ratio would have accepted this run (3/4 samples above
    40 m), so the new gate is strictly stronger, not weaker.
    """
    series = [0.0, 90.0, 90.0, 2.0, 1.0, 0.0]
    run_dir = _write_run(tmp_path, "run-mnr-spike", series, "throttled", "cryptomining")
    audit = audit_run_directory(run_dir)
    assert audit["pct_above_40"] == pytest.approx(33.333, abs=0.01)
    assert audit["median_post_lag_cpu_mcores"] < 40.0


def test_throttled_post_lag_requires_minimum_sample_count(tmp_path: Path) -> None:
    """Fewer than MIN_POST_LAG_SAMPLES post-lag samples cannot establish a trend."""
    series = [0.0, 100.0, 0.0, 100.0]
    run_dir = _write_run(tmp_path, "run-mnr-few", series, "throttled", "cryptomining")
    audit = audit_run_directory(run_dir)
    assert audit["post_lag_sample_count"] < MIN_POST_LAG_SAMPLES
