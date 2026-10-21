"""Unit tests for the template-grouped cross-validation of the diagnostics.

Decision D-32: the single-feature diagnostic and the label-permutation
baseline must not be computed by fitting the classifier on the rows it then
scores.  Both now use a GroupKFold whose groups are the scenario templates.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from scripts.verify_dataset import (
    DIAGNOSTIC_MIN_GROUPS,
    DIAGNOSTIC_MIN_RUNS,
    diagnostic_status,
    extract_group_labels,
    grouped_macro_f1,
    make_grouped_cv,
)


def _write_run(tmp_path: Path, run_id: str, scenario_id: str) -> Path:
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "index.json").write_text(
        json.dumps({"run_id": run_id, "scenario_id": scenario_id}), encoding="utf-8"
    )
    return run_dir


def test_group_labels_come_from_the_scenario_template(tmp_path: Path) -> None:
    a = _write_run(tmp_path, "run-001", "TMPL-BEN-01")
    b = _write_run(tmp_path, "run-002", "TMPL-BEN-01")
    c = _write_run(tmp_path, "run-003", "TMPL-ESC-05")
    labels = extract_group_labels([a, b, c])
    assert labels == ["TMPL-BEN-01", "TMPL-BEN-01", "TMPL-ESC-05"]
    assert len(set(labels)) == 2


def test_group_labels_fall_back_to_the_directory_name(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-no-index"
    run_dir.mkdir()
    assert extract_group_labels([run_dir]) == ["run-no-index"]


def test_grouped_cv_requires_at_least_two_groups() -> None:
    assert make_grouped_cv(1) is None
    cv = make_grouped_cv(3)
    assert cv is not None
    assert cv.n_splits == 3


def test_grouped_cv_never_trains_on_the_held_out_template() -> None:
    """A template's runs must all land in the same fold."""
    import numpy as np
    from sklearn.model_selection import GroupKFold

    groups = ["A", "A", "A", "B", "B", "C"]
    X = np.arange(6, dtype=np.float32).reshape(-1, 1)
    y = np.array([0, 0, 0, 1, 1, 1])
    cv = GroupKFold(n_splits=3)
    for train_idx, test_idx in cv.split(X, y, np.asarray(groups)):
        train_groups = {groups[i] for i in train_idx}
        test_groups = {groups[i] for i in test_idx}
        assert not (train_groups & test_groups)


def test_grouped_macro_f1_is_zero_without_a_valid_split() -> None:
    X = np.zeros((3, 1), dtype=np.float32)
    y = np.array([0, 1, 0])
    assert grouped_macro_f1(X, y, ["A", "B", "C"], None) == 0.0


def test_grouped_macro_f1_of_a_perfect_group_separator_is_one() -> None:
    """A feature that perfectly separates the groups scores 1.0 out-of-fold.

    Four groups are used so that every fold's training set contains both
    classes; with only two groups each fold would train on a single class.
    """
    X = np.array([[0.0], [0.0], [0.0], [0.0], [1.0], [1.0], [1.0], [1.0]], dtype=np.float32)
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    groups = ["A", "A", "B", "B", "C", "C", "D", "D"]
    cv = make_grouped_cv(4)
    assert cv is not None
    assert grouped_macro_f1(X, y, groups, cv) == 1.0


def test_diagnostic_status_marks_small_corpora_as_diagnostic_only() -> None:
    cv = make_grouped_cv(13)
    assert cv is not None
    status = diagnostic_status(13, 13, cv)
    assert "DIAGNOSTIC ONLY" in status
    assert str(DIAGNOSTIC_MIN_RUNS) in status
    assert str(DIAGNOSTIC_MIN_GROUPS) in status


def test_diagnostic_status_reports_when_the_split_is_impossible() -> None:
    status = diagnostic_status(1, 1, None)
    assert "DIAGNOSTIC ONLY" in status
    assert "not computable" in status
