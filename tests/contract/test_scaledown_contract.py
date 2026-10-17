"""Offline contract test suite for ScaleDown Classify-1 Decisions API.

Uses mock fixture tests/fixtures/scaledown/mock_response.json [ASSUMED FIXTURE].
Will be supplemented by verified real fixtures after user executes live smoke test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURE_PATH = Path("tests/fixtures/scaledown/mock_response.json")


def _load_fixture() -> dict[str, Any]:
    assert FIXTURE_PATH.exists(), f"Fixture missing: {FIXTURE_PATH}"
    result: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return result


def test_contract_response_structure() -> None:
    data = _load_fixture()
    assert data["model"] == "classify-1"
    assert "answers" in data

    answers = data["answers"]
    assert "attack_type" in answers
    assert "severity" in answers
    assert "baseline_deviation" in answers
    assert "shell_unexpected" in answers
    assert "resource_exposure" in answers
    assert "resource_abuse" in answers


def test_contract_choice_probabilities() -> None:
    data = _load_fixture()
    choice_data = data["answers"]["attack_type"]
    assert choice_data["type"] == "choice"
    assert choice_data["choice"] in {
        "benign",
        "container_escape",
        "privilege_abuse",
        "cryptomining",
        "unknown",
    }

    probs = choice_data["probabilities"]
    assert len(probs) == 5
    prob_sum = sum(probs.values())
    assert pytest.approx(prob_sum, abs=1e-2) == 1.0
    assert 0.0 <= choice_data["confidence"] <= 1.0


def test_contract_severity_formula_mapping() -> None:
    data = _load_fixture()
    severity_data = data["answers"]["severity"]
    assert severity_data["type"] == "score"
    score_val = float(severity_data["score"])
    assert 0.0 <= score_val <= 4.0

    # Severity formula verification: Severity = Score + 1.0 (maps [0, 4] to [1, 5])
    computed_severity = score_val + 1.0
    assert 1.0 <= computed_severity <= 5.0
    assert pytest.approx(computed_severity, abs=1e-3) == 4.75


def test_contract_noul_flags() -> None:
    data = _load_fixture()
    answers = data["answers"]

    for flag in ["baseline_deviation", "shell_unexpected", "resource_exposure", "resource_abuse"]:
        flag_data = answers[flag]
        assert flag_data["type"] == "noul"
        p = float(flag_data["noul"])
        assert 0.0 <= p <= 1.0
