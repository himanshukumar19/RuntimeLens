# RuntimeLens verification map

This directory is the maintained source for verifying the runtime behavior, security guardrails, telemetry collectors, and policy enforcement of RuntimeLens. Read the index before driving the system, then follow the matching feature file recipe.

## Baseline preconditions

- Install Python dependencies via `uv sync --extra dev`.
- Ensure Docker / OrbStack engine is running for container and cluster diagnostics.
- Never run against a live Kubernetes cluster unless the context is explicitly `kind-runtimelens`.
- For webhook tests, bind strictly to `127.0.0.1` using isolated, non-default ports (`18000`-`19000`).
- Always write audit logs to an isolated path: `artifacts/proofs/verify-$RUN_ID/audit.jsonl`.
- Never print or leak secrets or tokens into audit logs, fixtures, or transcripts.

## Driving conventions

- Run diagnostics with `uv run python scripts/control_runtimelens.py doctor`.
- Start daemon instances using `scripts/control_runtimelens.py start-webhook`.
- Drive HTTP interactions with `scripts/control_runtimelens.py post-event`.
- Verify cryptographic audit logs with `scripts/control_runtimelens.py verify-audit`.
- Always stop servers using `scripts/control_runtimelens.py stop-webhook --pid-file <path>`.
- Proof artifacts must survive cleanup in `artifacts/proofs/verify-$RUN_ID/`.

## Features

- [Webhook Ingestion and Policy Classification](./webhook-ingest-classify.md) covers authenticated Falco event ingestion, secret sanitization, canonical event normalization, policy engine decisions, and tamper-evident audit logging.
- [Security Guardrails and Rate Limiting](./security-guardrails.md) covers authentication token enforcement, 64KB payload bounds, sliding window rate limiting, and loopback address binding.
- [Scenario Safety Manifest Linter](./scenario-safety-lint.md) covers manifest validation preventing unauthorized host socket mounts, cluster-admin privileges, and class leakage.
- [Dataset Anti-Leakage and Baseline Verification](./dataset-anti-leakage.md) covers grouped run splits, telemetry completeness, and CPU/baseline deviation checks.
