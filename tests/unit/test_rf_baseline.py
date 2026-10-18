"""Unit tests for Random Forest classical baseline and feature extractor (Ticket 08)."""

from __future__ import annotations

from pathlib import Path

from runtimelens.eval.train_rf import load_dev_split, train_and_evaluate_rf_baseline
from runtimelens.features.extractor import (
    FEATURE_NAMES,
    extract_dataset_matrices,
    extract_features_from_run,
)


def test_feature_extractor_returns_exact_feature_dimensions() -> None:
    sample_run = {
        "run_id": "run-001",
        "scenario_id": "SC-ESC-01",
        "class": "container_escape",
    }
    vec = extract_features_from_run(sample_run)
    assert len(vec) == len(FEATURE_NAMES)
    assert vec[0] == 1.0  # host_runtime_socket_mounted


def test_dataset_matrices_extraction() -> None:
    runs = [
        {"run_id": "r1", "scenario_id": "SC-ESC-01", "class": "container_escape"},
        {"run_id": "r2", "scenario_id": "SC-BEN-01", "class": "benign"},
    ]
    X, y, ids = extract_dataset_matrices(runs)
    assert X.shape == (2, len(FEATURE_NAMES))
    assert y.shape == (2,)
    assert ids == ["r1", "r2"]


def test_rf_training_and_bootstrap_ci_on_dev_split() -> None:
    dev_runs = load_dev_split(Path("datasets/splits/manifest_v1.json"))
    assert len(dev_runs) == 288

    # Fast 3-fold CV with 100 resamples for unit testing
    results = train_and_evaluate_rf_baseline(dev_runs, n_splits=3, n_estimators=25, n_bootstrap=100)

    assert results["cv_macro_f1_mean"] >= 0.75
    assert results["bootstrap_95_ci"]["lower"] >= 0.70
    assert results["bootstrap_95_ci"]["upper"] <= 1.0
    assert results["fitted_model"] is not None
