# Security Guardrails and Rate Limiting

Security Guardrails protect RuntimeLens collector endpoints against denial-of-service, unauthenticated access, oversized payloads, and network exposure. Collectors strictly enforce loopback or Kind bridge binding, constant-time token comparison, payload caps (64 KB for Falco, 10 MB for K8s Audit batches), and sliding window rate limiting.

## Sub-features

- `auth-enforcement` rejects requests lacking a valid shared secret with HTTP 401.
- `payload-bounding` rejects payloads exceeding limits (64 KB for Falco, 10 MB for K8s Audit) with HTTP 413.
- `rate-limiting` restricts ingestion bursts via an in-memory sliding window (100 req/s for Falco, 200 req/s for K8s Audit), returning HTTP 429 when exceeded.
- `interface-isolation` refuses startup if configured to bind to public or unapproved network interfaces (allows `127.0.0.1`, `localhost`, and `172.18.0.1`).

## How to get to it (user POV)

- Send an unauthenticated POST request to `http://127.0.0.1:<port>/falco`.
- Send a request exceeding 64 KB in body size to `/falco`.
- Send rapid sequential bursts exceeding rate limits.
- Attempt binding the webhook server to `0.0.0.0`.

## Driving it with control-runtimelens

Preconditions:
- Webhook receiver running via `scripts/control_runtimelens.py start-webhook`.
- Valid secret configured as `test-token`.

- **Test unauthenticated rejection.** Send an event without credentials. Run `uv run python scripts/control_runtimelens.py post-event --port 18765 --secret "invalid-secret" --payload '{"output": "test"}'`. Expected output: HTTP status 401 with error `Unauthorized: Invalid or missing webhook token`.
- **Test oversized payload rejection.** Send a payload larger than 65,536 bytes. Run `uv run python -c "import urllib.request, json; data = json.dumps({'large': 'x' * 70000}).encode(); req = urllib.request.Request('http://127.0.0.1:18765/falco', data=data, headers={'Content-Type': 'application/json', 'X-Webhook-Token': 'test-token'}); urllib.request.urlopen(req)"`. Expected response: HTTP 413 Payload Too Large.
- **Test rate limit.** Rapidly fire requests to trigger rate limiting. When the threshold is passed within the 1-second window, the server returns HTTP 429 Too Many Requests.
- **Test interface binding protection.** Run `uv run python -c "from runtimelens.collector.webhook import run_webhook_server; run_webhook_server(host='0.0.0.0')"` in a test script. It raises `ValueError: Safety violation: Webhook must bind to 127.0.0.1 or 172.18.0.1`.

## Gotchas

- When testing rate limits, requests within the window increment the sliding timestamp buffer; wait 1.5 seconds between tests to reset the window.
- The Falco server drains up to 4 KB of oversized payloads before terminating the connection to prevent buffer exhaustion.
- Never disable or bypass `FALCO_WEBHOOK_SECRET` or `K8S_AUDIT_WEBHOOK_SECRET` in test or production environments.
- Permitted host bindings are strictly `127.0.0.1`, `localhost`, and `172.18.0.1`. Any other IP is refused at startup.
