# RuntimeLens Engineering Handoff

> **Last Updated:** 2026-10-23
> **Operational Status:** Core Pipeline & Offline Extensions Complete; Ready for Ticket 16b (Poster) or Ticket 06a (Cluster Pilot)
> **Governance Document:** `AGENTS.md` Rule 8 (Per-Ticket Review Loop) & Rule 9 (Autopilot with Approval Queue)

---

## 1. Current State & Completed Milestones

The project is governed under Mode A pair programming on macOS ARM64 with an air-gapped Ubuntu 24.04 Multipass VM (`runtimelens-vm`).

### Completed & Tagged Tickets:
- **Ticket `01` (`01-passed`, `9ce91ff`):** Repo foundation, strict secrets CI, property-based string sanitizer with Hypothesis fuzzing.
- **Ticket `02a` (`02a-passed`, `0a13e10`):** Lab VM, kind cluster, Cilium CNI, eBPF BTF verification (`snap-02a`).
- **Ticket `02b` (`02b-passed`, `d941e56`):** Dual API audit policy, 3 tenant namespaces, default-deny NetworkPolicies, 4 hardened workloads, Falco JSON logging.
- **Ticket `03` (`03-passed`, `3029445`):** Minimal vertical slice (webhook receiver, CanonicalEvent v1.0.0, rules classifier, deterministic policy engine, tamper-evident audit writer, `snap-02b`).
- **Ticket `11` (`84adde8`):** Live ScaleDown API smoke test completed on 2026-10-18 (14 calls executed); verified contract in `docs/MODEL_API.md`, real response fixtures in `tests/fixtures/scaledown/live_smoke_responses.json`. *Key is NOT needed again until Ticket 12a.*
- **Ticket `04` (`04-passed`, `a274d06`):** Core telemetry ingestion (Falco + K8s Audit Webhook) with $\pm 30$s temporal correlation window, non-blocking batch mode, TLS cert support.
- **Ticket `05` (`05-passed`, `4638faa`):** Git-versioned declarative YAML baselines (`baselines/`) and deterministic drift comparator.
- **Ticket `09a` (`09a-passed`, `6e18e5b`):** Unified 5-source raw telemetry archiver setup ensuring reproducible file sinks.
- **Ticket `09b` (`09b-passed`):** Hubble network flow, Prometheus cAdvisor resource, and Trivy vulnerability normalizers with capture-sufficiency audit (`audit_capture.py`).
- **Ticket `10` (`10-passed`):** `ScaleDownAdapter` with XML-delimited state serializer, prompt-injection escaping, SHA-256 caching, and offline contract tests.
- **Ticket `12b` (`2208c58`, PR #2):** Adversarial prompt-injection test suite evaluating 10 payloads across 4 defense tiers; ASR reduced from 30.0% to 0.0% under full stack.
- **Ticket `13a` (`13a-passed`):** Pure deterministic policy engine & 14-case exhaustive unit test suite covering all overrides, conflict matrix rows, and confidence thresholds.
- **Ticket `14` (`5a8e248`, PR #1):** Prometheus metrics exporter (`src/runtimelens/observability/exporter.py`) and Grafana SecOps dashboard (`lab/monitoring/grafana/dashboard.json`).
- **Ticket `15` (`5a8e248`, PR #1):** SRE extensions: continuous exposure-based risk scoring (`risk_score.py`) and human feedback baseline diff loop (`feedback.py`).
- **Ticket `16c` (`5a8e248`, PR #1):** 5-minute live interactive and automated demonstration CLI runner (`scripts/demo.py`, `make demo` / `make demo-auto`) and viva defense runbook (`docs/DEMO_RUNBOOK.md`).
- **Verification Harness & Benchmarks (`5a8e248`):** `.cursor/skills/verify-runtimelens/`, `scripts/control_runtimelens.py`, and 5-trial performance benchmark (12,847.1 events/sec, p50 77.2 µs, 0 errors).

### Formally Invalidated Tickets (Decision D-20, Dated 2026-10-18):
- **Ticket `06a`:** INVALIDATED (Synthetic pilot injection, no 5-source capture).
- **Ticket `06b`:** INVALIDATED (Synthetic bootstrap simulation).
- **Ticket `06c`:** INVALIDATED (Synthetic 400-run loop, no 5-source capture; data quarantined to `data/invalid_v0/`).
- **Ticket `07`:** INVALIDATED (Manifest built on synthetic runs; uninspected feature leakage).
- **Ticket `08`:** INVALIDATED (Features derived from ground-truth labels and scenario IDs).

---

## 2. Active & Blocked Tickets

- **Active State:** `READY FOR TICKET 16b OR TICKET 06a`
- **Status:** `UNBLOCKED` (PR #1 and PR #2 merged into `main`; CI 100% green; 171 automated tests passing)
- **Remediation Status:**
  - Stage 0 (doc/node sanitation) COMPLETED.
  - Stage 1 (proof runs + verify_dataset.py gate) COMPLETED.
  - Stage 2 (real 25-run pilot runner with genuine 5-source captures) READY.
- **Snapshot Baseline:** Clean snapshot `snap-s4` remains verified on `runtimelens-vm` post-S4.

---

## 3. Active Branches

- **`main`:** Clean, 171 tests passing, all GitHub Actions CI checks green.
- **`ahead/12b`:** Merged into `main` via PR #2.
- **`feature/offline-extensions-and-tooling`:** Merged into `main` via PR #1.

---

## 4. Open Queue Entries (`docs/APPROVAL_QUEUE.md`)

- *(No active approval items pending.)*

---

## 5. Next Steps for Next Session

1. **Option A (Offline Deliverable): Implement Ticket 16b (Academic Poster):**
   - Create poster text, architecture diagrams, decision trees, and layout assets under `docs/poster/`.
   - Implement the revisions specified in items 1.1–1.9 of `docs/REPORT_REVISION_CHECKLIST.md`.
2. **Option B (Cluster Experiment): Execute Ticket 06a (Stage 2 Pilot):**
   - Transfer clean git archive to `runtimelens-vm`:
     ```bash
     git archive --format=tar HEAD | gzip > /tmp/runtimelens.tar.gz
     multipass transfer /tmp/runtimelens.tar.gz runtimelens-vm:/home/ubuntu/runtimelens.tar.gz
     multipass exec runtimelens-vm -- bash -c "tar -xzf /home/ubuntu/runtimelens.tar.gz -C /home/ubuntu/RuntimeLens"
     ```
   - Run the 5-run ramp and full 25-run pilot on the cluster:
     ```bash
     multipass exec runtimelens-vm -- bash -c "cd /home/ubuntu/RuntimeLens && python3 scripts/stage2_pilot.py --stage ramp-5"
     ```
   - Audit output telemetry for zero class leakage:
     ```bash
     multipass exec runtimelens-vm -- bash -c "cd /home/ubuntu/RuntimeLens && python3 scripts/verify_dataset.py --runs-dir data/raw/runs"
     ```

---

## 6. Anything Fragile & Watchpoints

1. **Cluster eBPF Invariant:** Kind cluster and Cilium require genuine Linux kernel with BTF support (standard Ubuntu 24.04 kernel 6.8 inside `runtimelens-vm`). OrbStack's custom kernel fails Cilium's `FnSetRetval` helper probe (empirically confirmed 2026-10-23).
2. **Host VM Memory & Disk Limits:** Auto-stop triggers immediately if VM memory $\ge 85\%$ (4.93 GiB) or root disk $\ge 80\%$ (30.4 GiB). Current health: 24% memory used (4.4 GiB free), 19% disk used (31 GiB free).
3. **Cluster Safety & Sockets:** No real host sockets (`/var/run/docker.sock`) may ever be mounted into test containers; only synthetic ConfigMap dummy files.
4. **Mining Traffic:** Outbound flows must target only the internal cluster echo service `mock-mining-sink:3333`, never real pools or external IPs.
5. **No Pod Deletion Verbs in RBAC:** Neither the agent nor the response controller can possess pod deletion verbs.
6. **ScaleDown API Key Governance:** Key exists exclusively as `SCALEDOWN_API_KEY` in the environment. It is NOT needed for Ticket 06a or 16b; it is only required for Ticket 12a. Never commit or paste keys.
