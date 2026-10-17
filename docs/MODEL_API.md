# MODEL API SPECIFICATION: ScaleDown Classify-1

> **Status:** [SOURCE: official ScaleDown documentation at docs.scaledown.ai and API reference]
> *Note on Verification:* Only statements derived directly from executed API calls and tests are marked `[VERIFIED]`. Documentation-derived facts are marked `[SOURCE]`. The Severity = Score + 1.0 mapping is an `[ASSUMPTION / DESIGN CHOICE]` until verified in Phase 7.

## 1. Overview & Service Contract [SOURCE]
ScaleDown Classify-1 provides an SLM decision endpoint that mirrors TypeSafe Jev's Decisions API. It evaluates multiple typed questions concurrently against a single shared text state in a calibrated decode pass.

- **Upstream Model ID:** `classify-1` (pinned version 1)
- **Base URL:** `https://api.scaledown.xyz` (Note: `.xyz`, not `.ai`)
- **Decisions Endpoint:** `POST /v1/scaledown`
- **Authentication:** HTTP Header `x-api-key: <SCALEDOWN_API_KEY>`

## 2. Privacy, Data Retention & Training Policy [SOURCE]
- **Zero Data Retention (ZDR):** ScaleDown operates under a published Zero Data Retention posture for inference requests. Prompts and states are processed in volatile memory and are not persisted by the provider.
- **No Training on Customer Data:** ScaleDown's terms state that data sent to `/v1/scaledown` or `/classify` is never used to train or fine-tune models—neither during inference, after inference, nor in aggregate.
- **Client-Side Redaction:** As a mandatory defense-in-depth measure, RuntimeLens strips and redacts all secrets, tokens, credentials, and environment values *before* serializing text to the model.

## 3. Request Schema [SOURCE]

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

## 4. Response Schema [SOURCE]

```json
{
  "model": "classify-1",
  "answers": {
    "attack_type": {
      "type": "choice",
      "choice": "container_escape",
      "probabilities": {
        "benign": 0.02,
        "container_escape": 0.91,
        "privilege_abuse": 0.04,
        "cryptomining": 0.01,
        "unknown": 0.02
      },
      "confidence": 0.91
    },
    "severity": {
      "type": "score",
      "score": 3.75,
      "confidence": 0.84,
      "legend": {
        "0": "Informational: Standard expected activity...",
        "1": "Low: Minor anomaly...",
        "2": "Medium: Suspicious policy violation...",
        "3": "High: Clear indicator of compromise...",
        "4": "Critical: Active confirmed container breakout..."
      },
      "probabilities": {
        "0": 0.01,
        "1": 0.03,
        "2": 0.12,
        "3": 0.84,
        "4": 0.00
      }
    },
    "baseline_deviation": { "type": "noul", "noul": 0.95 },
    "shell_unexpected": { "type": "noul", "noul": 0.98 },
    "resource_exposure": { "type": "noul", "noul": 0.92 },
    "resource_abuse": { "type": "noul", "noul": 0.05 }
  },
  "usage": {
    "input_tokens": 420,
    "output_tokens": 6,
    "cost": 0.000018
  }
}
```

### Score Computation & Severity Mapping [ASSUMPTION / UNVERIFIED UNTIL PHASE 7]
- **Vendor Score Calculation [SOURCE]:** ScaleDown calculates continuous `score` as the probability-weighted expected value across level indices (`0` through `4`):
  $$\text{Score} = \sum_{i=0}^{4} (i \times P(\text{level}_i))$$
- **Severity Mapping [ASSUMPTION]:** Our policy engine maps this 0-indexed float to our canonical 1–5 severity scale:
  $$\text{Severity} = \text{Score} + 1.0$$
  *Status:* This formula remains an engineering assumption and will be marked `[VERIFIED]` only after executing the live smoke test in Phase 7.
- **Fallback Plan:** If the live Score question returns unexpected formatting or fails to calibrate, the adapter falls back immediately to an ordered 5-option Choice question or code-level deterministic severity policy.

## 5. Error Handling & Fail-Safe Matrix [SOURCE]

| HTTP Status | Interpretation | Policy Action | Retry Strategy |
|:---|:---|:---|:---|
| **401 Unauthorized** | Missing or invalid `x-api-key`. | Abort immediately; report configuration error. | Zero retries. |
| **402 Payment Required** | API credits exhausted. | Enter `degraded_mode=True`; route to human review. | Zero retries. |
| **422 Unprocessable** | Malformed request body / criteria schema error. | Log validation failure; route to human review. | Zero retries. |
| **429 Rate Limit** | Provider rate limit exceeded. | Exponential backoff respecting `Retry-After` header. | Max 3 retries (1s, 2s, 4s). |
| **502 / 503 / 504** | Transient server error or gateway timeout. | Retry with jittered backoff; fallback on failure. | Max 2 retries (hard 5s timeout). |

### Hard Fail-Safe Rule
If retries are exhausted or a non-retriable failure occurs:
1. Set `degraded_mode = True` on `ClassificationResult`.
2. Compute local Rule-Based and Random Forest baseline outputs for informational context.
3. Policy engine strictly routes the event to `human_review` (or low-priority alert if deterministic facts dictate). **Never silently classify as benign.**
4. Degraded events are tallied separately in evaluation reports and are never counted toward ScaleDown accuracy figures.

## 6. Local Response Caching & Offline CI
- **Cache Key:** `SHA256(model_version + state_text + canonical_questions_json)`.
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
