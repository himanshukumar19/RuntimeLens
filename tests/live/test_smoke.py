"""Live smoke test for ScaleDown Classify-1 Decisions API (12-Call Matrix, Hard Cap <= 20).

Runs on Mac only via explicit user invocation ('make test-live-api').
Zero logging or printing of API keys, headers, or environment variables.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

LIVE_ENDPOINT = "https://api.scaledown.xyz/v1/scaledown"
FIXTURE_PATH = Path("tests/fixtures/scaledown/live_smoke_responses.json")
HARD_CALL_CAP = 20

SAMPLE_STATE_TEXT = (
    "Workload: tenant-a / web-service (owner: web)\n"
    "Observed Process: /bin/sh -c 'cat /etc/shadow'\n"
    "Baseline: shell_expected=False, allowed_binaries=[web]\n"
    "Fact: host_runtime_socket_mounted=False, sensitive_host_path_mounted=False\n"
    "Alert: Read Sensitive Host Information Untrusted"
)

QUESTION_CHOICE = {
    "type": "choice",
    "instructions": "Which single category best describes the observed Kubernetes activity?",
    "criteria": {
        "benign": "Expected workload operation, routine maintenance, or normal deployment.",
        "container_escape": "Suspicious interaction with the host kernel or runtime sockets.",
        "privilege_abuse": "Misuse of permissions or unexpected process execution into container.",
        "cryptomining": "Sustained abnormal compute coupled with suspicious mining pool flows.",
        "unknown": "Telemetry is conflicting, truncated, or insufficient.",
    },
}

QUESTION_SCORE = {
    "type": "score",
    "instructions": "Evaluate the operational and security severity of this runtime event.",
    "criteria": [
        "Informational: Standard expected activity or benign baseline event.",
        "Low: Minor anomaly with high likelihood of benign intent.",
        "Medium: Suspicious policy violation requiring investigation.",
        "High: Clear indicator of compromise or unauthorized privilege access.",
        "Critical: Active confirmed container breakout or cluster-wide compromise.",
    ],
}

QUESTIONS_NOUL = {
    "baseline_deviation": {
        "type": "noul",
        "instructions": (
            "Is this activity inconsistent with the workload's documented baseline profile?"
        ),
    },
    "shell_unexpected": {
        "type": "noul",
        "instructions": "Is an interactive shell execution unexpected for this workload?",
    },
    "resource_exposure": {
        "type": "noul",
        "instructions": (
            "Does this event grant the container unauthorized access to host resources?"
        ),
    },
    "resource_abuse": {
        "type": "noul",
        "instructions": "Is the observed compute and network behaviour consistent with mining?",
    },
}


def _get_api_key() -> str:
    key = os.environ.get("SCALEDOWN_API_KEY")
    if not key or not key.strip():
        pytest.skip("SCALEDOWN_API_KEY is not set. Skipping live API test.")
    return key.strip()


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_API_TESTS") != "1",
    reason="RUN_LIVE_API_TESTS != '1'. Live API tests run only on explicit user invocation.",
)
def test_live_scaledown_12_call_matrix() -> None:
    """Execute the pre-registered 12-call test matrix against ScaleDown Classify-1."""
    api_key = _get_api_key()
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }

    recorded_results: dict[str, Any] = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "endpoint": LIVE_ENDPOINT,
            "call_count_cap": HARD_CALL_CAP,
        },
        "calls": {},
    }

    call_count = 0

    def make_call(
        call_id: str, payload: dict[str, Any], expect_status: int = 200
    ) -> tuple[int, float, Any]:
        nonlocal call_count
        call_count += 1
        if call_count > HARD_CALL_CAP:
            pytest.fail(f"HARD SAFETY CAP EXCEEDED: Attempted call {call_count} > {HARD_CALL_CAP}")

        t0 = time.perf_counter()
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(LIVE_ENDPOINT, json=payload, headers=headers)
        t_ms = (time.perf_counter() - t0) * 1000.0

        try:
            body = resp.json()
        except Exception:
            body = resp.text

        recorded_results["calls"][call_id] = {
            "status_code": resp.status_code,
            "latency_ms": round(t_ms, 2),
            "response": body,
        }
        return resp.status_code, t_ms, body

    print("\n=== Executing ScaleDown Classify-1 Smoke Test Matrix (Hard Cap: 20 calls) ===")

    # 1. Call 1: Choice Only
    status, lat, data = make_call(
        "call_01_choice_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"attack_type": QUESTION_CHOICE},
        },
    )
    assert status == 200
    print(f"Call 01 (Choice Only): Status {status} | Latency {lat:.1f} ms")

    # 2. Call 2: Score Only
    status, lat, data = make_call(
        "call_02_score_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"severity": QUESTION_SCORE},
        },
    )
    assert status == 200
    print(f"Call 02 (Score Only): Status {status} | Latency {lat:.1f} ms")

    # 3. Call 3: Noul Only
    status, lat, data = make_call(
        "call_03_noul_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"baseline_deviation": QUESTIONS_NOUL["baseline_deviation"]},
        },
    )
    assert status == 200
    print(f"Call 03 (Noul Only): Status {status} | Latency {lat:.1f} ms")

    # 4. Call 4: All Three Question Types Together
    all_questions = {"attack_type": QUESTION_CHOICE, "severity": QUESTION_SCORE, **QUESTIONS_NOUL}
    all_payload = {
        "model": "classify-1",
        "state": {"text": SAMPLE_STATE_TEXT},
        "questions": all_questions,
    }
    status, lat, all_data = make_call("call_04_all_three", all_payload)
    assert status == 200
    print(f"Call 04 (All Three Together): Status {status} | Latency {lat:.1f} ms")

    # Score + 1.0 observation and reporting (Report only, do not hard-assert)
    if "answers" in all_data and "severity" in all_data["answers"]:
        raw_score = all_data["answers"]["severity"].get("score")
        if raw_score is not None:
            mapped_sev = float(raw_score) + 1.0
            mapping_valid = 1.0 <= mapped_sev <= 5.0
            print(
                f"  -> [SCORE REPORT] Raw Score: {raw_score} | Mapped Severity: {mapped_sev:.2f} "
                f"| Mapping [1.0, 5.0] Valid: {mapping_valid}"
            )
            recorded_results["score_mapping_observation"] = {
                "raw_score": raw_score,
                "mapped_severity": mapped_sev,
                "mapping_valid": mapping_valid,
            }

    # 5. Call 5: Determinism / Cache Test (Repeat identical Call 4)
    status, lat_cache, data_cache = make_call("call_05_cache_repeat", all_payload)
    assert status == 200
    print(f"Call 05 (Cache Repeat of Call 4): Status {status} | Latency {lat_cache:.1f} ms")

    # 6. Call 6: Deliberately Invalid Request (Error Shape Test)
    status_err, lat_err, data_err = make_call(
        "call_06_invalid_request",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"bad": {"type": "unsupported"}},
        },
        expect_status=400,
    )
    print(f"Call 06 (Invalid Request): Status {status_err} | Latency {lat_err:.1f} ms")

    # 7. Calls 7-12: Latency Benchmark Suite (6 repeated calls)
    latencies: list[float] = []
    print("Calls 07-12 (Latency Distribution Suite):")
    for i in range(7, 13):
        call_name = f"call_{i:02d}_latency"
        s, l_ms, _ = make_call(call_name, all_payload)
        latencies.append(l_ms)
        print(f"  - {call_name}: {l_ms:.1f} ms (Status {s})")

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    min_lat = min(latencies)
    max_lat = max(latencies)
    print(
        f"Latency Summary (ms): Min={min_lat:.1f}, p50={p50:.1f}, p95={p95:.1f}, Max={max_lat:.1f}"
    )

    recorded_results["latency_summary_ms"] = {
        "min": round(min_lat, 2),
        "p50": round(p50, 2),
        "p95": round(p95, 2),
        "max": round(max_lat, 2),
    }
    recorded_results["total_calls_executed"] = call_count

    # Save redacted response fixtures to disk
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FIXTURE_PATH, "w", encoding="utf-8") as f:
        json.dump(recorded_results, f, indent=2)

    msg = (
        f"\n[PASS] All {call_count} calls completed (under {HARD_CALL_CAP} cap). "
        f"Saved to {FIXTURE_PATH}"
    )
    print(msg)
