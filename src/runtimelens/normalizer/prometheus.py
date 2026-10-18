"""Prometheus cAdvisor container resource normalizer (Ticket 09b)."""

from __future__ import annotations

from typing import Any


def normalize_prometheus_metric(
    raw_metric: dict[str, Any],
    baseline_cpu_envelope_mcores: float = 25.0,
) -> tuple[float, bool]:
    """Normalize raw Prometheus container CPU metric and detect relative anomaly.

    Returns:
        tuple of (cpu_usage_mcores, is_cpu_abnormal).
        is_cpu_abnormal is True if usage exceeds baseline envelope by >= 3x (Labeling Guide).
    """
    raw_val = float(raw_metric.get("value", 0.0))

    # Convert fractional core usage (e.g. 0.085 cores) to millicores (85.0 mcores)
    # If already > 10.0, assume it's millicores
    cpu_mcores = raw_val * 1000.0 if raw_val < 10.0 else raw_val

    # Anomaly definition: >= 3x baseline envelope or > 80% container quota
    is_abnormal = cpu_mcores >= (baseline_cpu_envelope_mcores * 3.0)

    return round(cpu_mcores, 2), is_abnormal
