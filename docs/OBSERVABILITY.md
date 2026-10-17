# OBSERVABILITY & AUDIT SPECIFICATION

## 1. Principles & Resource Sizing
Operating within an Ubuntu VM allocated 6–8 GB of RAM requires a lightweight observability stack:
- **No Heavy Stacks:** ElasticSearch/Logstash/Kibana (ELK) and heavy Kafka clusters are strictly avoided.
- **Unified Five-Source Raw Capture from Run 1:** Append-only rotated JSONL files are maintained under `data/raw/` for all five streams (`falco/`, `audit/`, `hubble/`, `prometheus/`, `trivy/`) across all scenario runs. Normalization of Hubble/Prometheus/Trivy can be staged later, but raw telemetry is archived immediately so the 400-run dataset never needs regeneration.
- **Single VM Clock:** All components reference the host/VM synchronized system clock in UTC.
- **Separation of Metrics & Logs:** Structured JSON logs handle granular audit trails; a lightweight Prometheus exporter handles real-time operational health.
- **Offline Evaluation Metric Exclusion:** Expected Calibration Error (ECE) requires full ground truth and offline probability binning; it is computed exclusively within the evaluation harness and is **not** exposed in the live Prometheus metrics exporter.
- **Phase Staging:** Grafana dashboard visualization is staged in Phase 10 to conserve system memory during early pipeline engineering.

## 2. Prometheus Metrics Specification
The pipeline exposes a Prometheus scrape endpoint (port 9090) instrumented via `prometheus_client`:

### 2.1 Ingestion & Telemetry Health Metrics
- `runtimelens_telemetry_events_total{source="falco|k8s_audit|hubble|trivy|metrics"}`: Total raw events received.
- `runtimelens_telemetry_drops_total{source="..."}`: Buffer drop counter.
- `runtimelens_telemetry_source_up{source="..."}`: Gauge (1 for healthy heartbeat, 0 for degraded/disconnected).

### 2.2 Classification & Pipeline Metrics
- `runtimelens_decisions_total{class="...", model="rules|rf|scaledown", action="log|alert|review|quarantine"}`: Total decisions rendered.
- `runtimelens_classification_duration_seconds{model="...", cache_hit="true|false"}`: Histogram tracking classification latency across p50, p95, and p99 percentiles.
- `runtimelens_degraded_events_total{reason="model_timeout|api_error|credit_limit|telemetry_drop"}`: Rate of degraded fallback executions.

### 2.3 Containment & Operational SRE Metrics
- `runtimelens_quarantines_active{namespace="..."}`: Gauge of currently isolated pods.
- `runtimelens_quarantine_rollbacks_total{reason="ttl_expired|operator_cleared"}`: Auto-rollback counter.
- `runtimelens_recovery_time_seconds`: Histogram tracking elapsed time from quarantine application to clean rollback.
- `runtimelens_review_queue_depth`: Gauge tracking pending items in the human review queue.

## 3. Tamper-Evident Audit Trail
Every incident decision is written atomically to an append-only JSONL log (`data/audit/decisions.jsonl`) with cryptographic hash-chaining:

```json
{
  "audit_record_id": "aud-20261017-00042",
  "prev_record_hash": "a1b2c3d4e5f6...7890",
  "record_hash": "e9f8a7b6c5d4...1234",
  "timestamp": "2026-10-17T14:32:01.120Z",
  "incident_id": "inc-tenant-a-web-20261017-143200",
  "workload": {
    "tenant": "tenant-a",
    "namespace": "tenant-a",
    "pod_name": "web-7d9f8c6b5-x2k4p",
    "pod_uid": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "image_digest": "sha256:d8a2..."
  },
  "raw_event_refs": [
    "data/raw/falco/2026-10-17.jsonl#L412",
    "data/raw/audit/2026-10-17.jsonl#L890"
  ],
  "state_hash": "sha256:4f8e...",
  "state_template_version": "v1.0.0",
  "baseline_version": "git:8a3f2b1",
  "classification": {
    "model_id": "scaledown/classify-1",
    "model_version": "classify-1",
    "predicted_class": "container_escape",
    "confidence": 0.91,
    "severity_score": 3.75,
    "evidence_flags": {
      "baseline_deviation": 0.95,
      "shell_unexpected": 0.98,
      "resource_exposure": 0.92,
      "resource_abuse": 0.05
    },
    "latency_ms": 142.5,
    "degraded_mode": false
  },
  "policy_evaluation": {
    "policy_version": "v1.0.0",
    "action": "quarantine",
    "dry_run": true,
    "reason_codes": ["ACT_QUARANTINE_ESCAPE_HIGH_SEV", "FACT_SOCKET_MOUNTED"],
    "action_id": "act-20261017-0012"
  }
}
```

## 4. Human Review Queue & CLI Tool
- **Storage:** Stored in `data/review/queue.jsonl` with lifecycle states: `PENDING` $\rightarrow$ `IN_REVIEW` $\rightarrow$ `RESOLVED`.
- **Reviewer CLI (`review.py`):**
  - **Standard Mode:** Displays full state, extracted facts, model output, and policy verdict.
  - **Blind Mode:** Displays raw evidence and extracted facts *first*, prompting the analyst for a blind verdict before revealing model predictions, enabling unbiased Cohen's kappa agreement measurement across a stratified 60–80 incident sample (target $\kappa \ge 0.80$).
  - **Feedback Diff Generation (Extension 5):** When an analyst marks an anomalous event as a legitimate workload update, the tool formats a candidate Git diff for `datasets/baselines/<workload>.yaml` (active on dev split only).
