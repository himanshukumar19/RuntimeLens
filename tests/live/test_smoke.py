"""Live smoke test for ScaleDown Classify-1 Decisions API (14-Call Pre-Registered Matrix).

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

ALLOWLISTED_HEADERS = frozenset(
    {
        "x-request-id",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "model-version",
        "content-type",
    }
)

SAMPLE_STATE_TEXT = (
    "Workload: tenant-a / web-service (owner: web)\n"
    "Observed Process: /bin/sh -c 'cat /etc/shadow'\n"
    "Baseline: shell_expected=False, allowed_binaries=[web]\n"
    "Fact: host_runtime_socket_mounted=False, sensitive_host_path_mounted=False\n"
    "Alert: Read Sensitive Host Information Untrusted"
)

# 6 distinct realistic states for latency benchmarking (Calls 07-12)
LATENCY_STATES = [
    (
        "Workload: tenant-a / web-service (owner: web)\n"
        "Observed Process: /bin/sh -c 'uptime'\n"
        "Baseline: shell_expected=False, allowed_binaries=[web]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
    (
        "Workload: tenant-a / api-service (owner: api)\n"
        "Observed Process: /usr/bin/curl -s http://internal-db:5432\n"
        "Baseline: shell_expected=False, allowed_binaries=[api]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
    (
        "Workload: tenant-b / web-service (owner: web)\n"
        "Observed Process: /bin/sh -c 'date'\n"
        "Baseline: shell_expected=False, allowed_binaries=[web]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
    (
        "Workload: tenant-b / database-service (owner: database)\n"
        "Observed Process: /usr/local/bin/redis-cli ping\n"
        "Baseline: shell_expected=False, allowed_binaries=[database]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
    (
        "Workload: tenant-c / web-service (owner: web)\n"
        "Observed Process: /bin/sh -c 'hostname'\n"
        "Baseline: shell_expected=False, allowed_binaries=[web]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
    (
        "Workload: tenant-c / payment-service (owner: payment-style)\n"
        "Observed Process: /bin/sh -c 'id'\n"
        "Baseline: shell_expected=False, allowed_binaries=[payment-style]\n"
        "Fact: host_runtime_socket_mounted=False, privileged_container=False"
    ),
]

PAIRED_DEBUG_STATE_TEXT = (
    "Workload: tenant-a / debug-pod (owner: debug)\n"
    "Observed Process: /bin/sh -i (spawned by authenticated developer on-call)\n"
    "Baseline: shell_expected=True, allowed_binaries=[sh, bash, curl, nc, gdb]\n"
    "Fact: host_runtime_socket_mounted=False, privileged_container=False\n"
    "Alert: Interactive Shell Spawned in Container"
)

PAIRED_PAYMENT_STATE_TEXT = (
    "Workload: tenant-a / payment-processor (owner: payment-style)\n"
    "Observed Process: /bin/sh -i (spawned by unprivileged service worker)\n"
    "Baseline: shell_expected=False, allowed_binaries=[payment-worker]\n"
    "Fact: host_runtime_socket_mounted=False, privileged_container=False\n"
    "Alert: Interactive Shell Spawned in Non-Debug Container"
)

QUESTION_CHOICE = {
    "type": "choice",
    "instructions": ("Which single category best describes the observed Kubernetes activity?"),
    "criteria": {
        "benign": ("Expected workload operation, routine maintenance, or normal deployment."),
        "container_escape": ("Suspicious interaction with the host kernel or runtime sockets."),
        "privilege_abuse": (
            "Misuse of permissions or unexpected process execution into container."
        ),
        "cryptomining": ("Sustained abnormal compute coupled with suspicious mining pool flows."),
        "unknown": "Telemetry is conflicting, truncated, or insufficient.",
    },
}

QUESTION_SCORE = {
    "type": "score",
    "instructions": ("Evaluate the operational and security severity of this runtime event."),
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
        "instructions": ("Is the observed compute and network behaviour consistent with mining?"),
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
def test_live_scaledown_14_call_matrix() -> None:
    """Execute the pre-registered 14-call test matrix against ScaleDown Classify-1."""
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

    # Local in-memory response cache to demonstrate and test cache bypass
    local_response_cache: dict[str, Any] = {}

    def make_call(
        call_id: str,
        payload: dict[str, Any],
        expect_status: int = 200,
        extra_headers: dict[str, str] | None = None,
        bypass_local_cache: bool = False,
    ) -> tuple[int, float, Any]:
        nonlocal call_count
        call_count += 1
        if call_count > HARD_CALL_CAP:
            pytest.fail(f"HARD SAFETY CAP EXCEEDED: Attempted call {call_count} > {HARD_CALL_CAP}")

        cache_key = json.dumps(payload, sort_keys=True)
        if not bypass_local_cache and cache_key in local_response_cache:
            # Local cache hit
            cached_resp = local_response_cache[cache_key]
            recorded_results["calls"][call_id] = {
                "status_code": 200,
                "latency_ms": 0.05,
                "source": "local_cache_hit",
                "response": cached_resp,
            }
            return 200, 0.05, cached_resp

        req_headers = dict(headers)
        if extra_headers:
            req_headers.update(extra_headers)

        t0 = time.perf_counter()
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(LIVE_ENDPOINT, json=payload, headers=req_headers)
        t_ms = (time.perf_counter() - t0) * 1000.0

        # Abort immediately on unexpected non-2xx status (no retries on 4xx)
        if expect_status == 200 and resp.status_code >= 400:
            err_msg = (
                f"ABORT: Unexpected non-2xx status {resp.status_code} at {call_id}: {resp.text}"
            )
            pytest.fail(err_msg)

        try:
            body = resp.json()
        except Exception:
            body = resp.text

        if resp.status_code == 200 and isinstance(body, dict):
            local_response_cache[cache_key] = body

        safe_resp_headers = {
            k.lower(): v for k, v in resp.headers.items() if k.lower() in ALLOWLISTED_HEADERS
        }

        token_usage = body.get("usage") if isinstance(body, dict) else None

        recorded_results["calls"][call_id] = {
            "status_code": resp.status_code,
            "latency_ms": round(t_ms, 2),
            "headers": safe_resp_headers,
            "usage": token_usage,
            "response": body,
        }
        return resp.status_code, t_ms, body

    print("\n=== Executing ScaleDown Classify-1 Smoke Test Matrix (14 calls, Cap: 20) ===")

    # 1. Call 1: Choice Only
    status, lat, _ = make_call(
        "call_01_choice_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"attack_type": QUESTION_CHOICE},
        },
    )
    print(f"Call 01 (Choice Only): Status {status} | Latency {lat:.1f} ms")

    # 2. Call 2: Score Only
    status, lat, _ = make_call(
        "call_02_score_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"severity": QUESTION_SCORE},
        },
    )
    print(f"Call 02 (Score Only): Status {status} | Latency {lat:.1f} ms")

    # 3. Call 3: Noul Only
    status, lat, _ = make_call(
        "call_03_noul_only",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"baseline_deviation": QUESTIONS_NOUL["baseline_deviation"]},
        },
    )
    print(f"Call 03 (Noul Only): Status {status} | Latency {lat:.1f} ms")

    # 4. Call 4: All Three Question Types Together
    all_questions = {"attack_type": QUESTION_CHOICE, "severity": QUESTION_SCORE, **QUESTIONS_NOUL}
    all_payload = {
        "model": "classify-1",
        "state": {"text": SAMPLE_STATE_TEXT},
        "questions": all_questions,
    }
    status, lat, all_data = make_call("call_04_all_three", all_payload)
    print(f"Call 04 (All Three Together): Status {status} | Latency {lat:.1f} ms")

    # Report Score expected value verification without hard asserting
    if "answers" in all_data and "severity" in all_data["answers"]:
        sev_obj = all_data["answers"]["severity"]
        raw_score = sev_obj.get("score")
        probs = sev_obj.get("probabilities", {})
        if raw_score is not None and probs:
            computed_ev = sum(int(level) * float(p) for level, p in probs.items())
            ev_diff = abs(float(raw_score) - computed_ev)
            ev_matches = ev_diff < 1e-4
            mapped_sev = computed_ev + 1.0
            print(
                f"  -> [SCORE EV CHECK] Reported Score: {raw_score:.6f} | "
                f"Computed EV: {computed_ev:.6f} | Diff: {ev_diff:.2e} | "
                f"EV Match (tol 1e-4): {ev_matches} | Mapped Severity: {mapped_sev:.2f}"
            )
            recorded_results["score_expected_value_verification"] = {
                "reported_score": raw_score,
                "computed_expected_value": computed_ev,
                "diff": ev_diff,
                "ev_matches": ev_matches,
                "mapped_severity": mapped_sev,
            }

    # 5. Call 5: Cache Bypass & Determinism Test (Bypasses local cache in code AND header)
    status, lat_cache, _ = make_call(
        "call_05_cache_bypass",
        all_payload,
        extra_headers={"Cache-Control": "no-cache"},
        bypass_local_cache=True,  # Explicitly forces real network roundtrip
    )
    print(f"Call 05 (Cache Bypass in Code): Status {status} | Latency {lat_cache:.1f} ms")

    # 6. Call 6: Deliberately Invalid Request (Error Shape Test)
    status_err, lat_err, _ = make_call(
        "call_06_deliberate_invalid",
        {
            "model": "classify-1",
            "state": {"text": SAMPLE_STATE_TEXT},
            "questions": {"invalid_q": {"type": "unsupported_question_type"}},
        },
        expect_status=400,
    )
    print(f"Call 06 (Deliberate Invalid Request): Status {status_err} | Latency {lat_err:.1f} ms")

    # 7–12. Calls 7-12: Latency Benchmark Suite across 6 distinct states
    latencies: list[float] = []
    print("Calls 07-12 (Latency Distribution on 6 Distinct States):")
    for idx, distinct_state in enumerate(LATENCY_STATES, start=7):
        call_name = f"call_{idx:02d}_latency"
        distinct_payload = {
            "model": "classify-1",
            "state": {"text": distinct_state},
            "questions": all_questions,
        }
        s, l_ms, _ = make_call(call_name, distinct_payload, bypass_local_cache=True)
        latencies.append(l_ms)
        print(f"  - {call_name}: {l_ms:.1f} ms (Status {s})")

    latencies.sort()
    min_lat = latencies[0]
    median_lat = (latencies[2] + latencies[3]) / 2.0  # Median of 6 elements
    max_lat = latencies[-1]
    print(f"Latency Summary (ms): Min={min_lat:.1f}, Median={median_lat:.1f}, Max={max_lat:.1f}")

    recorded_results["latency_summary_ms"] = {
        "min": round(min_lat, 2),
        "median": round(median_lat, 2),
        "max": round(max_lat, 2),
    }

    # 13. Call 13: Paired Scenario A (Authorized interactive shell in debug container)
    status, lat_debug, data_debug = make_call(
        "call_13_paired_debug_authorized",
        {
            "model": "classify-1",
            "state": {"text": PAIRED_DEBUG_STATE_TEXT},
            "questions": all_questions,
        },
    )
    print(f"Call 13 (Paired: Debug Authorized): Status {status} | Latency {lat_debug:.1f} ms")
    if "answers" in data_debug and "attack_type" in data_debug["answers"]:
        choice_debug = data_debug["answers"]["attack_type"].get("choice")
        conf_debug = data_debug["answers"]["attack_type"].get("confidence")
        print(f"  -> Predicted: {choice_debug} (conf: {conf_debug})")

    # 14. Call 14: Paired Scenario B (Unauthorized interactive shell in payment-style container)
    status, lat_payment, data_payment = make_call(
        "call_14_paired_payment_unauthorized",
        {
            "model": "classify-1",
            "state": {"text": PAIRED_PAYMENT_STATE_TEXT},
            "questions": all_questions,
        },
    )
    print(f"Call 14 (Paired: Payment Unauthorized): Status {status} | Latency {lat_payment:.1f} ms")
    if "answers" in data_payment and "attack_type" in data_payment["answers"]:
        choice_pay = data_payment["answers"]["attack_type"].get("choice")
        conf_pay = data_payment["answers"]["attack_type"].get("confidence")
        print(f"  -> Predicted: {choice_pay} (conf: {conf_pay})")

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
