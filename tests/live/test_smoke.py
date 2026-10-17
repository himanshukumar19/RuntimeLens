"""Live smoke test for ScaleDown Classify-1 Decisions API (Isolated Behind Flags)."""

import json
import os
import time
from pathlib import Path

import httpx
import pytest

LIVE_ENDPOINT = "https://api.scaledown.xyz/v1/scaledown"
FIXTURE_DIR = Path("tests/fixtures/scaledown")


def _get_api_key() -> str:
    key = os.environ.get("SCALEDOWN_API_KEY")
    if not key or not key.strip():
        pytest.skip("SCALEDOWN_API_KEY environment variable not set. Skipping live API test.")
    return key.strip()


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_API_TESTS") != "1",
    reason="RUN_LIVE_API_TESTS != '1'. Live API tests run only on explicit user invocation.",
)
def test_live_scaledown_classify1_smoke() -> None:
    api_key = _get_api_key()

    # Synthetic security payload for smoke verification
    payload = {
        "model": "classify-1",
        "state": {
            "text": (
                "Workload: tenant-a / payments-service (owner: payment-style)\n"
                "Observed Process: /bin/sh -i (spawned by unexpected user root)\n"
                "Baseline: shell_expected=False, allowed_binaries=[payment-worker]\n"
                "Network: No abnormal egress detected.\n"
                "Fact: Sensitive host path mounted: False."
            )
        },
        "questions": {
            "attack_type": {
                "type": "choice",
                "instructions": (
                    "Which single category best describes the observed Kubernetes activity?"
                ),
                "criteria": {
                    "benign": (
                        "Expected workload operation, routine maintenance, or normal deployment."
                    ),
                    "container_escape": (
                        "Suspicious interaction with the host kernel or runtime sockets."
                    ),
                    "privilege_abuse": (
                        "Misuse of permissions or unexpected process execution into container."
                    ),
                    "cryptomining": (
                        "Sustained abnormal compute coupled with suspicious mining pool flows."
                    ),
                    "unknown": "Telemetry is conflicting, truncated, or insufficient.",
                },
            },
            "severity": {
                "type": "score",
                "instructions": (
                    "Evaluate the operational and security severity of this runtime event."
                ),
                "criteria": [
                    "Informational: Standard expected activity or benign baseline event.",
                    "Low: Minor anomaly with high likelihood of benign intent.",
                    "Medium: Suspicious policy violation requiring investigation.",
                    "High: Clear indicator of compromise or unauthorized privilege access.",
                    "Critical: Active confirmed container breakout or cluster-wide compromise.",
                ],
            },
            "baseline_deviation": {
                "type": "noul",
                "instructions": (
                    "Is this activity inconsistent with the workload's documented baseline profile?"
                ),
            },
            "shell_unexpected": {
                "type": "noul",
                "instructions": ("Is an interactive shell execution unexpected for this workload?"),
            },
            "resource_exposure": {
                "type": "noul",
                "instructions": (
                    "Does this event grant the container unauthorized access to host resources?"
                ),
            },
            "resource_abuse": {
                "type": "noul",
                "instructions": (
                    "Is the observed compute and network behaviour consistent with mining?"
                ),
            },
        },
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }

    start_time = time.perf_counter()
    with httpx.Client(timeout=10.0) as client:
        response = client.post(LIVE_ENDPOINT, json=payload, headers=headers)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # 1. HTTP Status & Latency Verification
    assert response.status_code == 200, f"API error: {response.status_code} - {response.text}"
    assert elapsed_ms < 5000.0, f"Latency exceeded budget: {elapsed_ms:.1f} ms >= 5000 ms"

    data = response.json()
    assert "answers" in data

    answers = data["answers"]

    # 2. Choice Contract Verification
    choice = answers["attack_type"]
    assert choice["type"] == "choice"
    assert choice["choice"] in {
        "benign",
        "container_escape",
        "privilege_abuse",
        "cryptomining",
        "unknown",
    }
    assert 0.0 <= choice["confidence"] <= 1.0

    # 3. Score Contract & Severity Mapping Verification (Severity = Score + 1.0)
    severity_obj = answers["severity"]
    assert severity_obj["type"] == "score"
    score_val = float(severity_obj["score"])
    assert 0.0 <= score_val <= 4.0
    computed_severity = score_val + 1.0
    assert 1.0 <= computed_severity <= 5.0

    # 4. Noul Flags Verification
    for flag in ["baseline_deviation", "shell_unexpected", "resource_exposure", "resource_abuse"]:
        assert flag in answers
        assert answers[flag]["type"] == "noul"
        p = float(answers[flag]["noul"])
        assert 0.0 <= p <= 1.0

    # 5. Save sanitized live response fixture for offline test reuse
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fixture_path = FIXTURE_DIR / "live_smoke_response.json"
    with open(fixture_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(
        f"\n[LIVE SMOKE TEST PASSED] Roundtrip Latency: {elapsed_ms:.1f} ms | "
        f"Choice: {choice['choice']} (conf: {choice['confidence']:.2f}) | "
        f"Score: {score_val:.2f} -> Severity: {computed_severity:.2f} | "
        f"Noul deviation: {answers['baseline_deviation']['noul']:.2f}"
    )
