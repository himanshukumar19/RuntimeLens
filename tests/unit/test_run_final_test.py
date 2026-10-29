"""Unit test suite for single held-out test set evaluation harness (Ticket 12c)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtimelens.eval.run_final_test import (
    evaluate_final_test_set,
    load_test_split_runs,
    log_test_split_access,
)


def test_load_test_split_runs() -> None:
    test_runs = load_test_split_runs()
    assert len(test_runs) == 112
    # Verify every run has scenario_id and class
    for r in test_runs:
        assert "run_id" in r
        assert "class" in r


def test_log_test_split_access(tmp_path: Path) -> None:
    manifest_file = tmp_path / "test_manifest.json"
    manifest_file.write_text(json.dumps({"test_split": [1, 2, 3]}), encoding="utf-8")

    manifest_hash = log_test_split_access(manifest_file, n_runs=3, dry_run=True)
    assert len(manifest_hash) == 64

    log_file = Path("data/audit/test_eval_access.log")
    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    last_entry = json.loads(lines[-1])
    assert last_entry["event"] == "HELD_OUT_TEST_SPLIT_EVALUATION"
    assert last_entry["manifest_sha256"] == manifest_hash


def test_evaluate_final_test_set_synthetic() -> None:
    synthetic_runs: list[dict[str, Any]] = [
        {"run_id": f"test-ben-{i}", "scenario_id": f"SC-BEN-{i:02d}", "class": "benign"}
        for i in range(10)
    ] + [
        {"run_id": f"test-esc-{i}", "scenario_id": f"SC-ESC-{i:02d}", "class": "container_escape"}
        for i in range(5)
    ]

    results = evaluate_final_test_set(synthetic_runs, n_bootstrap=50)
    assert results["evaluation_protocol"] == "SINGLE_PASS_HELD_OUT_TEST_SET"
    assert results["total_test_incidents"] == 15
    assert "primary_hypothesis_h1" in results
    assert "confusion_matrices" in results
    assert "classification_reports" in results

    h1 = results["primary_hypothesis_h1"]
    assert "macro_f1_baseline_on" in h1
    assert "delta_macro_f1" in h1
    assert "formal_verdict" in h1
