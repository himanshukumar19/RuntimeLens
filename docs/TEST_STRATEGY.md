# TEST STRATEGY & VERIFICATION SPECIFICATION

## 1. Testing Philosophy & CI Discipline
RuntimeLens adheres to strict test-driven development (TDD) and SRE verification standards:
- **Zero-Secret CI:** Standard unit, contract, and property-based tests run 100% offline in GitHub Actions without network access or live API keys.
- **Evidence-Based Gates:** A phase exit gate is considered passed ONLY after real test commands execute successfully and output logs are recorded in documentation.
- **Property-Based Testing:** Randomized input fuzzing ensures critical security invariants (e.g., input sanitization, secret scrubbing) cannot be bypassed.

```
                    / \
                   /   \     Live API Smoke Tests (Manual, budget-capped)
                  /     \
                 /  E2E  \    Lab Scenario Integration Tests (kind + Cilium + Falco)
                /---------\
               / Contract  \   ScaleDown Adapter Mock Fixture Tests (tests/contract/)
              /-------------\
             /     Unit      \  Pydantic Schemas, Fact Extractors, Policy Engine,
            /  & Property-Base\  Sanitizer Fuzzing, Leakage Assertion Tests
           +-------------------+
```

## 2. Test Tiers & Execution Protocol

### 2.1 Unit & Property-Based Tests (`tests/unit/`)
- **Schema Validation:** Verifies Pydantic canonical event model, strict absence of extra fields, UTC date-time parsing, and UUID generation.
- **Fact Extraction:** Tests extraction of boolean facts from simulated pod specs and raw syscall payloads (e.g. root UID, host socket mounts, shell execs).
- **Policy Engine Invariants:** Exhaustively tests the pure `evaluate_policy()` function across all combinations of severity, confidence, safety overrides, and Choice-Noul conflict matrices.
- **Sanitizer Fuzzing (Hypothesis):** Uses `hypothesis` to generate arbitrary Unicode, delimiter-breaking sequences (`<untrusted_args>`, `\x00`, bidi overrides, prompt-injection patterns) to prove the sanitizer never outputs unescaped strings, control characters, or exceeds 128 characters.
- **Automated Leakage Test:** Asserts that no feature vector or formatted `state.text` contains forbidden strings matching `run_id`, pod-name randomized suffixes, IP addresses, absolute timestamps, or master seeds.

### 2.2 Contract Tests (`tests/contract/`)
- **Isolation:** Tests the ScaleDown adapter against recorded HTTP fixtures (`tests/contract/fixtures/`).
- **Fixtures Verified:**
  - Standard multi-question response (Choice, Score, Noul).
  - Score question response (expected value float, confidence, probabilities).
  - Rate-limit response (HTTP 429 with `Retry-After`).
  - Credit exhaustion response (HTTP 402 $\rightarrow$ verify `degraded_mode=True`).
  - Gateway error response (HTTP 502/504 $\rightarrow$ verify retry backoff and graceful degradation).
  - Malformed payload response (HTTP 422).

### 2.3 Integration Tests (`tests/integration/`)
- **Pipeline Flow:** Streams synthetic raw JSONL records through normalizer, window buffer ($\pm 30$s), and classifier interface, asserting correct incident emission.
- **RBAC Security Tests:**
  ```bash
  # Must assert SUCCESS (authorized):
  kubectl auth can-i patch pods --as=system:serviceaccount:runtimelens:runtimelens-response-controller -n tenant-a
  # Must assert FAILURE (strictly forbidden):
  kubectl auth can-i delete pods --as=system:serviceaccount:runtimelens:runtimelens-response-controller -n tenant-a
  kubectl auth can-i get pods --as=system:serviceaccount:runtimelens:runtimelens-response-controller -n kube-system
  ```
- **Quarantine & Rollback Controller:** Simulates high-severity event, verifies `quarantine=true` label patched, tests network drop via Cilium eBPF, simulates TTL expiry, and verifies label is cleanly removed.
- **Crash Recovery:** Kills the response controller mid-action, restarts it, and verifies that the reconcile loop restores accurate state without leaking orphaned quarantines.

### 2.4 Scenario Verification Tests (`tests/scenarios/`)
- Orchestrates live test runs using `make lab-verify`.
- Deploys temporary lab scenario pods, triggers Falco alerts, asserts incident creation, and verifies that cleanup scripts leave zero residual artifacts in tenant namespaces.

### 2.5 Live Model Smoke Test (`make test-live-api`)
- **Execution:** Strictly manual, requiring explicit user authorization.
- **Guardrails:** Evaluates at most 3 synthetic events; halts immediately if credit or latency anomalies occur; logs cost and latency to `.cache/scaledown/smoke_test.log`.
