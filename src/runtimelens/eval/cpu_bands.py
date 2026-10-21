"""Variant-aware CPU measurement bands shared by the dataset gate and the per-run gate.

This module is intentionally dependency-free (standard library only) so that the
live lab runner inside the air-gapped VM can import it without numpy, scipy or
scikit-learn being installed in the cluster host environment.

Decisions encoded here
----------------------
**Decision D-26 - burst band widened to the cAdvisor measurement resolution.**
The kubelet cAdvisor summary API is polled on an asynchronous ~10 s interval.
A workload whose CPU spike is shorter than one sampling window is not observed
at its true peak; the measured value is the window average. Measured evidence
from the real Stage 4a Part 1 telemetry (no simulation, no synthetic numbers):

    run-s4a-10 attempt 1 : peak  25.77 mcores  (below the former [30, 100] band)
    run-s4a-10 attempt 2 : peak 117.34 mcores  (above the former [30, 100] band)
    run-s4a-09 (MNR-03)  : peak 102.39 mcores  (throttled mining)

The *same* command produced 25.77 m and 117.34 m on two consecutive attempts,
i.e. a ~4.5x spread caused purely by sampling-window alignment. A band of
[30, 100] mcores is therefore narrower than the measurement noise floor and
labels an identical workload as both "no burst" and "sustained mining". D-26
sets the band to peak in [20, 150] mcores with median < 100 mcores. The band
remains disjoint from the `high` (full-throttle mining) band, which requires
>= 80% of post-lag samples >= 100 mcores plus a post-lag median >= 100 mcores.

**Decision D-27 - cAdvisor first-sample lag excluded from the ratio.**
The first one or two cAdvisor samples of a run are taken before the container's
CPU accounting window has accumulated, so they report 0.00 mcores regardless
of the workload. Measured evidence from the real telemetry:

    run-s4a-09 attempt 1 : 0.00, 75.59, 75.59, 100.58, 100.51, 100.51, 99.78
    run-s4a-09 attempt 2 : 0.00,  0.00,  46.64, 102.39, 101.59, 101.59, 89.69

Both are genuine sustained mining with 7 samples, yet the share of samples
above the threshold moves from 85.7% to 71.4% purely because the lag window
covered one sample in one attempt and two in the other. D-27 therefore:

* excludes samples taken within ``CPU_LAG_EXCLUSION_SECONDS`` of the first
  sample of the run from the *ratio denominator*;
* requires at least ``MIN_POST_LAG_SAMPLES`` post-lag samples; and
* adds a strict *post-lag median floor* (>= 100 mcores for `high`, >= 40
  mcores for `throttled`).

The median floor makes the gate strictly **stronger** than the legacy
all-sample ratio it replaces: a workload that spikes briefly and then returns
to idle has a post-lag median far below the floor and still fails, whereas the
legacy ratio could be satisfied by a short spike.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------------------
# Decision D-26: burst measurement band
# --------------------------------------------------------------------------------------
BURST_PEAK_MIN_MCORES: Final[float] = 20.0
BURST_PEAK_MAX_MCORES: Final[float] = 150.0
BURST_MEDIAN_MAX_MCORES: Final[float] = 100.0

# --------------------------------------------------------------------------------------
# Decision D-27: cAdvisor first-sample lag handling
# --------------------------------------------------------------------------------------
CPU_LAG_EXCLUSION_SECONDS: Final[float] = 15.0
MIN_POST_LAG_SAMPLES: Final[int] = 4

# Shared thresholds for the sustained-load profiles
HIGH_CPU_MCORES: Final[float] = 100.0
HIGH_CPU_MIN_PCT: Final[float] = 80.0
HIGH_CPU_MIN_POST_LAG_MEDIAN_MCORES: Final[float] = 100.0
THROTTLED_CPU_MCORES: Final[float] = 40.0
THROTTLED_CPU_MIN_PCT: Final[float] = 60.0
THROTTLED_CPU_MIN_POST_LAG_MEDIAN_MCORES: Final[float] = 40.0


def post_lag_cpu_samples(
    sample_cpus: list[float],
    sample_timestamps: list[float],
) -> list[float]:
    """Return the CPU samples taken at least ``CPU_LAG_EXCLUSION_SECONDS`` after the first.

    Implements the Decision D-27 cAdvisor first-sample lag exclusion. When the
    timestamps are unavailable the full sample list is returned unchanged, so
    the function degrades to the legacy behaviour instead of silently dropping
    data.
    """
    if not sample_cpus or len(sample_cpus) != len(sample_timestamps):
        return list(sample_cpus)
    first_ts = min(sample_timestamps)
    return [
        cpu
        for cpu, ts in zip(sample_cpus, sample_timestamps, strict=True)
        if (ts - first_ts) >= CPU_LAG_EXCLUSION_SECONDS
    ]


def median(values: list[float]) -> float:
    """Return the median of a non-empty list (0.0 for an empty list)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def burst_band_ok(sample_cpus: list[float]) -> bool:
    """Decision D-26 burst band verdict: peak in [20, 150] mcores, median < 100 mcores."""
    if not sample_cpus:
        return False
    peak = max(sample_cpus)
    med = median(sample_cpus)
    return BURST_PEAK_MIN_MCORES <= peak <= BURST_PEAK_MAX_MCORES and med < BURST_MEDIAN_MAX_MCORES


def burst_band_reason(sample_cpus: list[float]) -> str:
    """Human-readable Decision D-26 burst band verdict."""
    if not sample_cpus:
        return "FAIL (no cAdvisor samples)"
    peak = max(sample_cpus)
    med = median(sample_cpus)
    if burst_band_ok(sample_cpus):
        return f"PASS (peak={peak:.2f}m in [20,150], med={med:.2f}m < 100)"
    return (
        f"FAIL (peak={peak:.2f}m not in "
        f"[{BURST_PEAK_MIN_MCORES:.0f},{BURST_PEAK_MAX_MCORES:.0f}] "
        f"or med={med:.2f}m >= {BURST_MEDIAN_MAX_MCORES:.0f})"
    )
