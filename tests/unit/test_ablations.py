"""Unit tests for pre-registered ablation harness and statistical methods (Ticket 12a)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest

from runtimelens.eval.run_ablations import (
    compute_cluster_bootstrap_ci,
    compute_mcnemar_test,
    holm_bonferroni_correction,
    run_all_ablations,
    synthesize_dev_canonical_event,
)


def test_mcnemar_computation() -> None:
    y_true = [0, 0, 1, 1, 2, 2]
    # Model A: 5 correct, 1 wrong (idx 1)
    y_pred_a = [0, 1, 1, 1, 2, 2]
    # Model B: 3 correct, 3 wrong (idx 1, 3, 5)
    y_pred_b = [0, 1, 1, 0, 2, 0]

    # Discordant:
    # idx 3: A correct (1==1), B wrong (0!=1) -> b += 1
    # idx 5: A correct (2==2), B wrong (0!=2) -> b += 1
    # c = 0
    res = compute_mcnemar_test(y_true, y_pred_a, y_pred_b)
    assert res["contingency_b"] == 2.0
    assert res["contingency_c"] == 0.0
    assert res["both_correct"] == 3.0
    assert res["both_incorrect"] == 1.0
    # Stat = (|2 - 0| - 1)^2 / 2 = 1/2 = 0.5
    assert pytest.approx(res["statistic"], 0.01) == 0.5


def test_cluster_bootstrap_ci() -> None:
    cluster_ids = ["c1", "c1", "c2", "c2", "c3", "c3"]
    y_true = np.array([0, 0, 1, 1, 2, 2])
    y_pred_a = np.array([0, 0, 1, 1, 2, 2])  # Perfect
    y_pred_b = np.array([0, 1, 1, 0, 2, 0])  # Imperfect

    res = compute_cluster_bootstrap_ci(
        cluster_ids=cluster_ids,
        y_true=y_true,
        y_pred_a=y_pred_a,
        y_pred_b=y_pred_b,
        n_bootstrap=100,
        random_seed=42,
    )

    assert res["delta_macro_f1_mean"] > 0.0
    assert res["delta_macro_f1_ci_lower"] <= res["delta_macro_f1_ci_upper"]


def test_holm_bonferroni_correction() -> None:
    p_vals = [0.005, 0.04, 0.08]
    # m = 3
    # rank 1: p=0.005 vs 0.05/3 = 0.0167 -> True
    # rank 2: p=0.04 vs 0.05/2 = 0.025 -> False (stops)
    # rank 3: p=0.08 vs 0.05/1 = 0.05 -> False
    res = holm_bonferroni_correction(p_vals, alpha=0.05)
    assert len(res) == 3
    assert res[0]["is_significant"] is True
    assert res[1]["is_significant"] is False
    assert res[2]["is_significant"] is False


def test_synthesize_dev_canonical_event() -> None:
    run_meta = {
        "run_id": "run-test-esc-01",
        "scenario_id": "SC-ESC-01",
        "class": "container_escape",
    }
    evt = synthesize_dev_canonical_event(run_meta, with_baseline=True)
    assert evt.facts.host_runtime_socket_mounted is True
    assert evt.facts.privileged_container is True
    assert evt.baseline.baseline_deviation_detected is True

    evt_no_base = synthesize_dev_canonical_event(run_meta, with_baseline=False)
    assert evt_no_base.baseline.baseline_deviation_detected is False


def test_run_all_ablations_on_synthetic_dev() -> None:
    synthetic_runs: list[dict[str, Any]] = [
        {"run_id": f"run-{i}", "scenario_id": f"SC-BEN-{i:02d}", "class": "benign"}
        for i in range(10)
    ] + [
        {"run_id": f"run-esc-{i}", "scenario_id": f"SC-ESC-{i:02d}", "class": "container_escape"}
        for i in range(5)
    ]

    results = run_all_ablations(synthetic_runs, n_bootstrap=50)
    assert results["dataset_split"] == "dev"
    assert "primary_hypothesis_abl_base" in results
    assert "abl_telem_source_fusion" in results
    assert "abl_gate_confidence_sweeps" in results
    assert "secondary_classifier_comparisons" in results

    primary = results["primary_hypothesis_abl_base"]
    assert "macro_f1_baseline_on" in primary
    assert "bootstrap_ci_95" in primary
