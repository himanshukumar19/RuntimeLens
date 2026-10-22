# RuntimeLens Pipeline Performance and Latency Benchmarks

This document records measured performance metrics for the RuntimeLens vertical slice pipeline: event normalization, classification, deterministic policy evaluation, and cryptographic audit logging.

## Benchmark Methodology

- **Harness:** `scripts/benchmark_pipeline.py`
- **Machine:** Apple Silicon (macOS ARM64, Python 3.12.13 via `uv`)
- **Protocol:** 5 independent trials, 1,000 events per trial (total 5,000 events).
- **Workload:** Representative mix across benign activity, shell privilege abuse, sensitive mount container escape, and cryptomining egress.
- **Verification:** Every trial asserts zero errors and validates the SHA-256 tamper-evident hash chain via `AuditWriter.verify_chain`.

## Summary Results (2026-10-23)

| Metric | Measured Value | Range (5 Trials) |
|---|---|---|
| **Total Events Processed** | 5,000 | 1,000 / trial |
| **Error Count** | 0 (0.00%) | 0 across all trials |
| **Pipeline Throughput** | 12,847.1 events/sec | 12,491.3 – 13,004.1 events/sec |
| **End-to-End Latency (p50)** | 77.2 µs | 75.9 – 78.9 µs |
| **Normalization Latency (p50)** | 22.4 µs | 22.1 – 23.0 µs |
| **Rule Classification Latency (p50)** | 1.3 µs | 1.2 – 1.4 µs |
| **Policy Engine Latency (p50)** | 1.0 µs | 0.9 – 1.1 µs |
| **Audit Write & Hash-Chain (p50)** | 52.5 µs | 51.5 – 53.6 µs |

## Limiter Analysis

- **Primary Limiter:** Atomic disk append and SHA-256 hash chaining account for approximately 68% of total end-to-end processing time (52.5 µs out of 77.2 µs).
- **Core Logic:** In-memory rule evaluation (1.3 µs) and policy engine decisions (1.0 µs) run in near-zero time due to pure functional design without I/O or network calls.
