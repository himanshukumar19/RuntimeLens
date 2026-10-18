# MODEL API SPECIFICATION: ScaleDown Classify-1

> **Status:** [VERIFIED on 2026-10-18 via Live Smoke Test Calls 01–14]
> *Verification Audit:* Statements verified directly against executed ScaleDown API responses (`tests/fixtures/scaledown/live_smoke_responses.json`) are marked `[VERIFIED]`. Items lacking provider telemetry (e.g., rate-limit headers, exact model snapshot SHA) remain strictly marked `[UNVERIFIED]`.

## 1. Overview & Service Contract
ScaleDown Classify-1 provides an SLM decision endpoint that evaluates multiple typed questions concurrently against a single shared text state in a calibrated decode pass.

- **Upstream Model ID:** `classify-1` [VERIFIED 2026-10-18: calls 01–05, 07–14]
- **Base URL:** `https://api.scaledown.xyz` [VERIFIED 2026-10-18]
- **Decisions Endpoint:** `POST /v1/scaledown` [VERIFIED 2026-10-18]
- **Authentication:** HTTP Header `x-api-key: <SCALEDOWN_API_KEY>` [VERIFIED 2026-10-18]
- **Model Version Pinning:** `[UNVERIFIED]` (Provider returns string `model: "classify-1"`; no underlying model commit hash or snapshot version is returned in body or headers).
- **Provider Rate Limits:** `[UNVERIFIED]` (No `x-ratelimit-remaining`, `x-ratelimit-reset`, or `Retry-After` headers were returned in responses).

## 2. Privacy, Data Retention & Training Policy [SOURCE]
- **Zero Data Retention (ZDR):** ScaleDown operates under a published Zero Data Retention posture for inference requests. Prompts and states are processed in volatile memory and are not persisted by the provider.
- **No Training on Customer Data:** ScaleDown's terms state that data sent to `/v1/scaledown` or `/classify` is never used to train or fine-tune models—neither during inference, after inference, nor in aggregate.
- **Client-Side Redaction:** As a mandatory defense-in-depth measure, RuntimeLens strips and redacts all secrets, tokens, credentials, and environment values *before* serializing text to the model.

## 3. Request Schema [VERIFIED 2026-10-18: calls 01–05, 07–14]

- **Choice Field Name:** Uses `criteria` (map of label to description) [VERIFIED 2026-10-18: calls 01, 04, 05, 07–14].
- **Score Field Name:** Uses `criteria` (ordered array of level descriptions) [VERIFIED 2026-10-18: calls 02, 04, 05, 07–14].
- **Noul Field Name:** Uses `instructions` (statement evaluated for truth probability) [VERIFIED 2026-10-18: calls 03, 04, 05, 07–14].

```json
{
  "model": "classify-1",
  "state": {
    "text": "<Serialized Canonical State with Delimited Fields>"
  },
  "questions": {
    "attack_type": {
      "type": "choice",
      "instructions": "Which single category best describes the observed Kubernetes activity?",
      "criteria": {
        "benign": "Expected workload operation, routine maintenance, authorized administrative action, or normal deployment activity.",
        "container_escape": "Suspicious interaction with the host kernel, access to container runtime sockets, host file paths, or privileged container capabilities.",
        "privilege_abuse": "Misuse of Kubernetes orchestration permissions, unexpected service-account token reads, unauthorized Secret access, or execution into adjacent pods.",
        "cryptomining": "Sustained abnormal compute consumption coupled with unexpected outbound network flows to non-standard ports or suspicious binaries running from temporary directories.",
        "unknown": "Telemetry is conflicting, truncated, degraded, or insufficient to confidently determine an attack category."
      }
    },
    "severity": {
      "type": "score",
      "instructions": "Evaluate the operational and security severity of this runtime event.",
      "criteria": [
        "Informational: Standard expected activity or benign baseline event.",
        "Low: Minor anomaly or unusual action with high likelihood of benign intent.",
        "Medium: Suspicious policy violation or unexpected process requiring human investigation.",
        "High: Clear indicator of compromise, sensitive host exposure, or unauthorized credential access.",
        "Critical: Active confirmed container breakout, cluster-wide compromise, or severe denial of service."
      ]
    },
    "baseline_deviation": {
      "type": "noul",
      "instructions": "Is this activity inconsistent with the workload's documented baseline profile?"
    },
    "shell_unexpected": {
      "type": "noul",
      "instructions": "Is an interactive shell execution unexpected for this workload?"
    },
    "resource_exposure": {
      "type": "noul",
      "instructions": "Does this event grant the container unauthorized access to host or cluster resources?"
    },
    "resource_abuse": {
      "type": "noul",
      "instructions": "Is the observed compute and network behaviour consistent with unauthorized resource hijacking or mining?"
    }
  }
}
```

## 4. Response Schema & Empirical Properties [VERIFIED 2026-10-18]

```json
{
  "model": "classify-1",
  "answers": {
    "attack_type": {
      "type": "choice",
      "choice": "privilege_abuse",
      "probabilities": {
        "benign": 0.0484,
        "container_escape": 0.2346,
        "privilege_abuse": 0.6195,
        "cryptomining": 0.0234,
        "unknown": 0.0741
      },
      "confidence": 0.6195
    },
    "severity": {
      "type": "score",
      "score": 2.4060,
      "confidence": 0.4855,
      "legend": {
        "0": "Informational: Standard expected activity...",
        "1": "Low: Minor anomaly...",
        "2": "Medium: Suspicious policy violation...",
        "3": "High: Clear indicator of compromise...",
        "4": "Critical: Active confirmed container breakout..."
      },
      "probabilities": {
        "0": 0.0234,
        "1": 0.0523,
        "2": 0.4290,
        "3": 0.4855,
        "4": 0.0098
      }
    },
    "baseline_deviation": { "type": "noul", "noul": 0.8286 },
    "shell_unexpected": { "type": "noul", "noul": 0.7131 },
    "resource_exposure": { "type": "noul", "noul": 0.6604 },
    "resource_abuse": { "type": "noul", "noul": 0.0554 }
  },
  "usage": {
    "input_tokens": 1910,
    "output_tokens": 6,
    "cost": 0.0000955
  }
}
```

### Verified Empirical Properties [VERIFIED 2026-10-18: calls 01–05, 07–14]
1. **Confidence Metric:** In choice questions, `confidence` is identically equal to the maximum class probability (`confidence = max(probabilities.values())`). In score questions, `confidence` is identically equal to the maximum level probability (`confidence = max(probabilities.values())`).
2. **Score Expected Value Calculation:** ScaleDown calculates continuous `score` strictly as the probability-weighted expected value across 0-indexed levels (`0` through `4`):
   $$\text{Score} = \sum_{i=0}^{4} (i \times P(\text{level}_i))$$
   *Verification:* In Call 04, computed $\sum i \cdot P(i) = 0(0.0234) + 1(0.0523) + 2(0.4290) + 3(0.4855) + 4(0.0098) = 2.406025$, exactly matching the reported `score: 2.4060252222577563` within $| \Delta | < 10^{-6}$.
3. **Severity Mapping:** The mapped continuous severity is:
   $$\text{Severity} = \text{Score} + 1.0 \in [1.0, 5.0]$$
   *Verification:* Verified that continuous Severity smoothly maps expected values from $[0.0, 4.0]$ to $[1.0, 5.0]$.
4. **Latency Distribution:**
   - Min: `895.8 ms`
   - Median: `1048.2 ms`
   - Max: `1056.8 ms`
   - Bound: Well within the 5.0s hard request timeout budget.
5. **Cost & Token Economics:**
   - All 6 questions combined: 1,910 input tokens, 6 output tokens, cost: **$0.0000955** per incident.
   - Single question: ~440 input tokens, 1 output token, cost: **$0.0000220** per incident.

## 5. Error Response Schema [VERIFIED 2026-10-18: call 06]

When an invalid request schema or unsupported question type is passed, ScaleDown returns **HTTP 422 Unprocessable Entity** with FastAPI/Pydantic structured detail errors:

```json
{
  "detail": [
    {
      "type": "literal_error",
      "loc": ["body", "questions", "invalid_q", "ChoiceQuestion", "type"],
      "msg": "Input should be 'choice'",
      "input": "unsupported_question_type",
      "ctx": { "expected": "'choice'" }
    }
  ]
}
```

## 6. Error Handling & Fail-Safe Matrix

| HTTP Status | Interpretation | Policy Action | Retry Strategy | Verified Status |
|:---|:---|:---|:---|:---|
| **401 Unauthorized** | Missing or invalid `x-api-key`. | Abort immediately; report configuration error. | Zero retries. | Verified contract |
| **402 Payment Required** | API credits exhausted. | Enter `degraded_mode=True`; route to human review. | Zero retries. | Unverified |
| **422 Unprocessable** | Malformed request body / criteria schema error. | Log validation failure; route to human review. | Zero retries. | [VERIFIED 2026-10-18: call 06] |
| **429 Rate Limit** | Provider rate limit exceeded. | Exponential backoff respecting `Retry-After` header. | Max 3 retries (1s, 2s, 4s). | [UNVERIFIED: no headers returned] |
| **502 / 503 / 504** | Transient server error or gateway timeout. | Retry with jittered backoff; fallback on failure. | Max 2 retries (hard 5s timeout). | Standard fail-safe |

### Hard Fail-Safe Rule
If retries are exhausted or a non-retriable failure occurs:
1. Set `degraded_mode = True` on `ClassificationResult`.
2. Compute local Rule-Based and Random Forest baseline outputs for informational context.
3. Policy engine strictly routes the event to `human_review` (or low-priority alert if deterministic facts dictate). **Never silently classify as benign.**
4. Degraded events are tallied separately in evaluation reports and are never counted toward ScaleDown accuracy figures.

## 7. Local Response Caching & Offline CI
- **Cache Key:** `SHA256(model_id + ":" + rubric_version + ":" + state_hash)`.
- **Cache Storage:** Local file-based JSON cache under `.cache/scaledown/`. Cache hits bypass network calls, guaranteeing zero cost and sub-millisecond replay during development reruns.
- **CI Isolation:** GitHub Actions CI executes 100% offline. Unit and contract test suites consume recorded mock responses (`tests/contract/fixtures/`). Live API calls are isolated under a manual test target (`make test-live-api`) with strict request-budget limits.

## 7. Minimal Verification Smoke Test Design
```bash
curl -s -X POST https://api.scaledown.xyz/v1/scaledown \
  -H "Content-Type: application/json" \
  -H "x-api-key: $SCALEDOWN_API_KEY" \
  -d '{
    "model": "classify-1",
    "state": { "text": "Workload: tenant-a/web. Process: /bin/sh started by nginx. Facts: sensitive_mount=true." },
    "questions": {
      "attack_type": {
        "type": "choice",
        "instructions": "Select the attack class.",
        "criteria": {
          "benign": "Normal operation",
          "container_escape": "Access to host resources or escape attempt",
          "privilege_abuse": "Unauthorized permissions",
          "cryptomining": "Unauthorized compute/mining",
          "unknown": "Ambiguous"
        }
      }
    }
  }'
```
