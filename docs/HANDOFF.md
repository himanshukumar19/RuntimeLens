# RuntimeLens Engineering Handoff

> **Last Updated:** 2026-10-23
> **Operational Status:** Segment S4 Complete; Ready for Stage 2 Pilot (Ticket 06a)
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
- **Ticket `04` (`04-passed`, `a274d06`):** Core telemetry ingestion (Falco + K8s Audit Webhook) with $\pm 30$s temporal correlation window (unit-tested on fixtures, not run on live events; live wiring pending Ticket `04-live`), non-blocking batch mode, TLS cert support.
- **Ticket `05` (`05-passed`, `4638faa`):** Git-versioned declarative YAML baselines (`baselines/`) and deterministic drift comparator.
- **Ticket `09a` (`09a-passed`, `6e18e5b`):** Unified 5-source raw telemetry archiver setup ensuring reproducible file sinks.
- **Ticket `09b` (`09b-passed`):** Hubble network flow, Prometheus cAdvisor resource, and Trivy vulnerability normalizers with capture-sufficiency audit (`audit_capture.py`).
- **Ticket `10` (`10-passed`):** `ScaleDownAdapter` with XML-delimited state serializer, prompt-injection escaping, SHA-256 caching, and offline contract tests (`tests/contract/test_scaledown_adapter.py`).
- **Ticket `13a` (`13a-passed`):** Pure deterministic policy engine & 14-case exhaustive unit test suite covering all overrides, conflict matrix rows, and confidence thresholds.

### Formally Invalidated Tickets (Decision D-20, Dated 2026-10-18):
- **Ticket `06a`:** INVALIDATED (Synthetic pilot injection, no 5-source capture).
- **Ticket `06b`:** INVALIDATED (Synthetic bootstrap simulation).
- **Ticket `06c`:** INVALIDATED (Synthetic 400-run loop, no 5-source capture; data quarantined to `data/invalid_v0/`).
- **Ticket `07`:** INVALIDATED (Manifest built on synthetic runs; uninspected feature leakage).
- **Ticket `08`:** INVALIDATED (Features derived from ground-truth labels and scenario IDs).
- **Ticket `12b` Claim:** INVALIDATED (Mock string matching evaluation).

---

## 2. Active & Blocked Tickets

- **Active State:** `READY FOR TICKET 06a (Stage 2 Pilot Scenario Run)`
- **Status:** `UNBLOCKED` (Remediation Plan A-006 approved, host connectivity diagnosed in A-007, terminal execution confirmed in A-008)
- **Remediation Status:**
  - Stage 0 (doc/node sanitation) COMPLETED.
  - Stage 1 (proof runs + verify_dataset.py gate) COMPLETED.
  - Stage 2 (real 25-run pilot runner with genuine 5-source captures) READY.
- **Snapshot Baseline:** Clean snapshot `snap-s4` remains verified on `runtimelens-vm` post-S4.

---

## 3. Active Branches

- **`main`:** Clean, fully tested, all CI gates passing.
- **`ahead/12b` (`4063954`):** Adversarial test harness (code structure preserved; mock inference marked for remediation).
- **`ahead/14` (`472a250`):** Prometheus operational metrics exporter & Grafana secops dashboard.
- **`ahead/16c` (`439f6db`):** 5-minute live interactive demonstration script & viva defense runbook.

---

## 4. Open Queue Entries (`docs/APPROVAL_QUEUE.md`)

- *(No active approval items pending.)*

---

## 5. Next Three Steps

1. **Step 1 (Sync to VM):** Export clean git archive of current HEAD and unpack into `/home/ubuntu/RuntimeLens/` inside `runtimelens-vm`.
2. **Step 2 (Receiver & Health Verification):** Run `make lab-verify` and ensure Hubble Relay (4245), Falco webhook (8765), and Audit webhook (8766) are listening.
3. **Step 3 (Execute Stage 2 Pilot):** Run `scripts/stage2_pilot.py` (dry-run, ramp-5, full-25) inside the VM environment and execute `scripts/verify_dataset.py` on the resulting run directory.

---

## 6. Anything Fragile & Watchpoints

1. **Host VM Memory & Disk Limits:** Auto-stop triggers immediately if VM memory $\ge 85\%$ (4.93 GiB) or root disk $\ge 80\%$ (30.4 GiB). Current health: 24% memory used (4.4 GiB free), 19% disk used (31 GiB free).
2. **Cluster Safety & Sockets:** No real host sockets (`/var/run/docker.sock`) may ever be mounted into test containers; only synthetic ConfigMap dummy files.
3. **Mining Traffic:** Outbound flows must target only the internal cluster echo service `mock-mining-sink:3333`, never real pools or external IPs.
4. **Air-Gapped Code Transport:** Multipass folder mounting (`multipass mount`) is strictly forbidden. Files are transferred exclusively via `git archive HEAD` or explicit `multipass transfer`.
5. **No Pod Deletion Verbs in RBAC:** Neither the agent nor the response controller can possess pod deletion verbs.
6. **ScaleDown API Key Governance:** Never paste or request the key in chat. Key is injected solely as `SCALEDOWN_API_KEY` in the user's terminal environment for Ticket 12a.
