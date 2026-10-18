"""Unit tests for pilot power analysis and empirical budgeting (Ticket 06b)."""

from __future__ import annotations

from runtimelens.eval.pilot_power import (
    compute_empirical_resource_budget,
    simulate_bootstrap_power_and_ci_width,
)


def test_compute_empirical_resource_budget() -> None:
    mock_metrics = [
        {"elapsed_seconds": 3.0, "vm_ram_percent": 24.0, "vm_disk_percent": 19.0},
        {"elapsed_seconds": 4.0, "vm_ram_percent": 25.0, "vm_disk_percent": 19.0},
        {"elapsed_seconds": 2.0, "vm_ram_percent": 23.5, "vm_disk_percent": 19.0},
    ]
    budget = compute_empirical_resource_budget(mock_metrics)
    assert budget["total_planned_runs"] == 400
    assert budget["pilot_sample_size"] == 3
    assert budget["per_run_elapsed_time_seconds"]["mean"] == 3.0
    assert budget["peak_observed_vm_ram_percent"] == 25.0
    assert budget["estimated_400_runs_active_wall_time_minutes"] == 20.0


def test_simulate_bootstrap_power_and_ci_width() -> None:
    sim = simulate_bootstrap_power_and_ci_width(n_resamples=500, sample_size=400)
    assert sim["bootstrap_resamples"] == 500
    assert sim["sample_size_evaluated"] == 400
    assert sim["ci_95_percent"]["half_width"] <= 0.08
    assert sim["ci_width_condition_satisfied"] is True
    assert sim["estimated_statistical_power"] >= 0.80
    assert sim["power_threshold_satisfied"] is True
