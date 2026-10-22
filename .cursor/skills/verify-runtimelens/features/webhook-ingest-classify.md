# Webhook Ingestion and Policy Classification

Webhook Ingestion and Policy Classification lets Kubernetes security agents (such as Falco) submit runtime events over HTTP to RuntimeLens. RuntimeLens sanitizes secrets, normalizes the event into a CanonicalEvent, applies classification rules, evaluates deterministic policy safety, and records an atomic, tamper-evident hash-chained audit record.

## Sub-features

- `ingest-falco-event` receives Falco JSON alert payloads over authenticated HTTP.
- `sanitize-secrets` strips embedded passwords, API keys, tokens, and sensitive environment variables before storage.
- `normalize-canonical` converts heterogeneous event fields into a strict Pydantic CanonicalEvent.
- `policy-evaluate` routes the event through the policy engine to select an action (`log`, `alert`, `human_review`, `quarantine`).
- `audit-hashchain` appends the decision to a tamper-evident SHA-256 hash-chained JSONL log.

## How to get to it (user POV)

- Send an HTTP POST request to `http://127.0.0.1:<port>/falco` with an `X-Webhook-Token: <token>` header.
- Send an HTTP POST request with an `Authorization: Bearer <token>` header.
- Send an HTTP POST request to `http://127.0.0.1:<port>/falco?token=<token>` (Falco C++ HTTP output format).
- Run `uv run python scripts/control_runtimelens.py post-event --port <port> --secret <token> --payload <payload>`.

## Driving it with control-runtimelens

Preconditions:
- Python environment ready with `uv sync --extra dev`.
- `artifacts/proofs/verify-$RUN_ID/` created for ephemeral artifacts.
- Webhook receiver running via `scripts/control_runtimelens.py start-webhook`.

- **Start receiver.** Run `uv run python scripts/control_runtimelens.py start-webhook --port 18765 --audit-file artifacts/proofs/verify-$RUN_ID/audit.jsonl --secret "test-token" --pid-file artifacts/proofs/verify-$RUN_ID/server.pid`. Output confirms status `running` with process PID.
- **Post benign event.** Submit an authorized container process event. Run `uv run python scripts/control_runtimelens.py post-event --port 18765 --secret "test-token" --payload '{"output": "Container spawned nginx", "output_fields": {"k8s.ns.name": "tenant-a", "k8s.pod.name": "web-pod-1", "proc.cmdline": "nginx -g daemon off;", "time": "2026-10-23T00:00:00Z"}}'`. Response HTTP status is 200 with action `log`.
- **Post suspicious event.** Submit an unexpected shell invocation in a database container. Run `uv run python scripts/control_runtimelens.py post-event --port 18765 --secret "test-token" --payload '{"output": "Shell spawned in redis container", "output_fields": {"k8s.ns.name": "tenant-b", "k8s.pod.name": "db-redis-0", "proc.name": "sh", "proc.cmdline": "/bin/sh -i", "time": "2026-10-23T00:00:01Z"}}'`. Response HTTP status is 200 with action `alert` or `human_review`.
- **Verify audit chain.** Confirm both records were written and their SHA-256 chain is valid. Run `uv run python scripts/control_runtimelens.py verify-audit --audit-file artifacts/proofs/verify-$RUN_ID/audit.jsonl`. Output shows `valid: true` and `record_count: 2`.
- **Teardown.** Run `uv run python scripts/control_runtimelens.py stop-webhook --pid-file artifacts/proofs/verify-$RUN_ID/server.pid`. Process terminates cleanly.

## Gotchas

- Unauthenticated requests receive HTTP 401 Unauthorized; always pass the matching token.
- Payloads exceeding 64 KB on the Falco endpoint are rejected with HTTP 413 Payload Too Large.
- The policy engine operates in `dry_run=True` by default; quarantine actions emit proposals with a 900-second TTL rather than directly mutating cluster state.
- For shell anomaly detection, `proc.name` must be set (`sh`, `bash`, `zsh`, `dash`) or `proc.cmdline` must contain the absolute path (e.g. `/bin/sh`).
- Audit log directories are created automatically by `AuditWriter`.
