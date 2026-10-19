# SCENARIO_PLAN_v2.md — Proposed 400-Run Multi-Source Scenario Plan

> **Status:** PROPOSED (Stage 3 Draft — NOT FROZEN).
> **Governance Notice:** All counts, parameters, and scenario templates in this document are *proposed* specifications subject to Stage 4 human scenario review and formal user authorization. Zero runs have been scheduled or executed under this plan.

---

## 1. Executive Summary & Class Budget Allocation

Following the Stage 2/3 empirical pilot findings and the formal dropping of `exfiltration` as an attack class (Decision D-24), the 400-run dataset is restructured across **three attack classes**, a high-volume **benign baseline class**, and an explicit **unknown/ambiguous class**.

| Threat Class | Proposed Runs | Share (%) | Distinct Templates | Rationale |
|:---|:---:|:---:|:---:|:---|
| **`benign`** | **180** *(proposed)* | 45.0% | 18 | Production Kubernetes clusters are overwhelmingly benign (>99%). A substantial benign envelope of 180 runs is mathematically required to bound benign False Positive Rates ($\text{FPR} \le 2\%$) within tight paired 95% bootstrap confidence intervals ($\pm 1.5\%$). Features diverse developer maintenance, shells, internal service calls, secret reads, and batch CPU jobs. |
| **`container_escape`** | **80** *(proposed)* | 20.0% | 8 | Critical-severity threat targeting shared-kernel boundaries (exposed runtime sockets, sensitive host path mounts, privileged capabilities, and host namespace traversals). Varies features 00, 01, and 02. |
| **`privilege_abuse`** | **80** *(proposed)* | 20.0% | 8 | High-frequency orchestration-layer threat targeting the Kubernetes API server (cross-tenant secret access, unauthorized RBAC enumeration, inter-pod exec misuse). |
| **`cryptomining`** | **40** *(proposed)* | 10.0% | 8 | Resource-hijacking threat exhibiting sustained and throttled CPU busy loops with high-port pool egress signatures. Capped at 40 runs to bound active cluster compute time to ~1.4 hours while ensuring statistical power. |
| **`unknown`** | **20** *(proposed)* | 5.0% | 8 | Insufficient, degraded, or conflicting evidence scenarios designed to test deterministic policy fail-safes and human review escalation (never silently predicting benign). |
| **Total** | **400** *(proposed)* | **100.0%** | **50** | **Balanced across 3 tenant namespaces and 4 workload archetypes.** |

---

## 2. Anti-Leakage & Confounder Rules

To eliminate the trivial classification shortcuts identified in the pilot (where `command_length` alone achieved $F1 = 0.964$ due to uniform script templates), the following constraints are strictly enforced:

1. **Zero Metadata Leakage:** Scenario IDs (`SC-*`), ground-truth class names (`benign`, `cryptomining`, etc.), and run identifiers (`run-*`) are strictly forbidden from appearing inside commands, file paths, arguments, environment variables, or probe payloads.
2. **Command Length Overlap:** Every threat class must have templates distributed across all three command length bins:
   - **Short (30–80 chars):** 2 templates per class.
   - **Medium (81–150 chars):** 3 templates per class.
   - **Long (151–250+ chars):** 3+ templates per class.
3. **Paired Look-Alike Confounders:**
   - Benign scenarios must include interactive shells (`/bin/sh`), high-port internal network connections (e.g. 8080, 8443, 9090, 6379, 5432), in-pod service account token reads, and sustained batch CPU loads.
   - Attack scenarios must include obfuscated and shortened commands, throttled CPU rates, and standard utility wrappers (`wget`, `nc`, `head`, `find`).
4. **Workload & Tenancy Balance:** Templates are distributed evenly across `tenant-a`, `tenant-b`, and `tenant-c`, rotating across all 4 workload types (`web`, `api`, `database`, `payment-style`).

---

## 3. Complete Master Template Registry (50 Templates, 400 Runs)

### 3.1 Class: `benign` (18 Templates, 180 Runs Proposed)

| ID | Description | Length Bin | Dur. (s) | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---|:---:|
| `TMPL-BEN-01` | Routine uptime and local cluster DNS resolution check | 30–80 | 7s | tenant-a / web | Low | low | None / Shell Spawn | Zero state change | 10 |
| `TMPL-BEN-02` | Ephemeral file health check: touch and unlink in `/tmp` | 30–80 | 7s | tenant-b / api | Low | low | Shell Spawn | Cleaned post-run | 10 |
| `TMPL-BEN-03` | Container environment verification: print date and hostname | 30–80 | 7s | tenant-c / database | Low | low | Shell Spawn | Read-only | 10 |
| `TMPL-BEN-04` | Internal microservice HTTP health probe to port 8080 | 81–150 | 8s | tenant-a / api | Low | low | Shell Spawn | Egress to internal svc | 10 |
| `TMPL-BEN-05` | Legitimate service account token read for in-cluster client auth | 81–150 | 8s | tenant-b / payment-style | Low | low | Shell Spawn | Authorized SA read | 10 |
| `TMPL-BEN-06` | Multi-directory disk usage audit: `df -h` and `du -sk /tmp` | 81–150 | 8s | tenant-c / web | Low | low | Shell Spawn | Read-only | 10 |
| `TMPL-BEN-07` | Internal metrics scrape probe to Prometheus port 9090 | 81–150 | 8s | tenant-a / database | Low | low | Shell Spawn | Internal metrics port | 10 |
| `TMPL-BEN-08` | Legitimate mounted TLS certificate inspection in `/etc/ssl` | 81–150 | 8s | tenant-b / web | Low | low | Shell Spawn | Read-only certs | 10 |
| `TMPL-BEN-09` | Developer debug session: process listing and memory inspection | 151–250+ | 12s | tenant-c / api | Medium | low | Shell Spawn | Standard debug | 10 |
| `TMPL-BEN-10` | Database backup maintenance: dump file creation and md5 checksum | 151–250+ | 15s | tenant-a / database | Medium | low | Shell Spawn | Uses `/tmp`, cleaned | 10 |
| `TMPL-BEN-11` | Log compression routine: multi-file gzip in ephemeral storage | 151–250+ | 25s | tenant-b / payment-style | High | burst | Shell Spawn | 30s CPU burst < 80m | 10 |
| `TMPL-BEN-12` | Batch calculation script: iterative prime search in shell loop | 151–250+ | 30s | tenant-c / web | High | burst | Shell Spawn | CPU burst ~75m | 10 |
| `TMPL-BEN-13` | Internal cache connection check: Redis port 6379 ping | 151–250+ | 10s | tenant-a / web | Low | low | Shell Spawn | Internal cache port | 10 |
| `TMPL-BEN-14` | Microservice configuration sync via cluster ConfigMap query | 151–250+ | 10s | tenant-b / api | Low | low | Shell Spawn | Authorized K8s API read | 10 |
| `TMPL-BEN-15` | Multi-tenant isolation verification: cross-tenant egress deny probe | 151–250+ | 10s | tenant-c / database | Low | low | Shell Spawn | Blocked by NetPol | 10 |
| `TMPL-BEN-16` | Web server log rotation script with archive and compression | 151–250+ | 20s | tenant-a / payment-style | Medium | burst | Shell Spawn | Ephemeral files only | 10 |
| `TMPL-BEN-17` | Security compliance self-audit: check non-root UID and caps | 81–150 | 8s | tenant-b / web | Low | low | Shell Spawn | Read-only | 10 |
| `TMPL-BEN-18` | In-cluster DNS benchmark: multi-lookup latency check | 81–150 | 10s | tenant-c / api | Low | low | Shell Spawn | Normal UDP 53 | 10 |

---

### 3.2 Class: `container_escape` (8 Templates, 80 Runs Proposed)

| ID | Description | Length Bin | Dur. (s) | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---|:---:|
| `TMPL-ESC-01` | Read `/etc/shadow` and `/etc/passwd` directly from container | 30–80 | 7s | tenant-a / database | Low | low | Sensitive File Read | Passive read only | 10 |
| `TMPL-ESC-02` | Probe kernel `/proc/kcore` and `/proc/sys/kernel` parameters | 30–80 | 7s | tenant-b / web | Low | low | Sensitive File Read | Read-only inspection | 10 |
| `TMPL-ESC-03` | Exposed runtime socket probe via dummy containerd socket | 81–150 | 8s | tenant-c / payment-style | Medium | low | Launch Sensitive Mount | Dummy socket only | 10 |
| `TMPL-ESC-04` | Sensitive host path inspection via dummy `/opt/runtimelens-dummy/etc` | 81–150 | 8s | tenant-a / api | Medium | low | Launch Sensitive Mount | Inert dummy files | 10 |
| `TMPL-ESC-05` | Cgroup `release_agent` container breakout path traversal attempt | 81–150 | 8s | tenant-b / database | High | low | Sensitive File Read | Read-only path check | 10 |
| `TMPL-ESC-06` | Privileged container capability inspection: `nsenter` / debugfs check | 151–250+ | 10s | tenant-c / web | High | low | Debugfs / Shell Spawn | Ephemeral pod, deleted | 10 |
| `TMPL-ESC-07` | Host PID namespace traversal probe inspecting node process tree | 151–250+ | 10s | tenant-a / web | High | low | Namespace Change / Shell | Read-only process list | 10 |
| `TMPL-ESC-08` | Host device node creation attempt (`mknod` in container) | 151–250+ | 10s | tenant-b / api | High | low | Shell Spawn | Blocked by PSS/caps | 10 |

---

### 3.3 Class: `privilege_abuse` (8 Templates, 80 Runs Proposed)

| ID | Description | Length Bin | Dur. (s) | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---|:---:|
| `TMPL-PRV-01` | Cross-tenant Secrets list attempt against adjacent namespace | 30–80 | 7s | tenant-a / api | Low | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-02` | Cross-tenant Pods enumeration attempt against adjacent namespace | 30–80 | 7s | tenant-b / web | Low | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-03` | Cluster-wide ServiceAccount token enumeration via API server | 81–150 | 8s | tenant-c / database | Medium | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-04` | Unauthorized ConfigMaps extraction from adjacent tenant namespace | 81–150 | 8s | tenant-a / payment-style | Medium | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-05` | ClusterRoleBinding inspection attempt using pod service account | 81–150 | 8s | tenant-b / api | Medium | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-06` | Inter-pod execution probe targeting pod subresource in adjacent tenant | 151–250+ | 10s | tenant-c / payment-style | High | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-07` | Node proxy endpoint reconnaissance attempt via kube-apiserver | 151–250+ | 10s | tenant-a / database | High | low | Shell Spawn | Rejected 403 Forbidden | 10 |
| `TMPL-PRV-08` | Batch multi-namespace resource scraping using extracted token | 151–250+ | 12s | tenant-b / payment-style | High | low | Shell Spawn | All attempts 403 logged | 10 |

---

### 3.4 Class: `cryptomining` (8 Templates, 40 Runs Proposed)

| ID | Description | Length Bin | Dur. (s) | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---|:---:|
| `TMPL-MNR-01` | Full-throttle CPU busy loop with pool port 3333 connect | 30–80 | 130s | tenant-a / web | 200m | high | Suspicious High Port Egress | Throttled by cgroup | 5 |
| `TMPL-MNR-02` | Full-throttle CPU busy loop with pool port 4444 connect | 30–80 | 130s | tenant-b / database | 200m | high | Suspicious High Port Egress | Throttled by cgroup | 5 |
| `TMPL-MNR-03` | Throttled mining loop with 50ms pause on port 3333 | 81–150 | 70s | tenant-c / api | 75m | throttled | Suspicious High Port Egress | Safe throttled load | 5 |
| `TMPL-MNR-04` | Throttled mining loop with 75ms pause on port 5555 | 81–150 | 70s | tenant-a / payment-style | 60m | throttled | Suspicious High Port Egress | Safe throttled load | 5 |
| `TMPL-MNR-05` | Multi-thread simulation: dual background loops with pool connect | 81–150 | 130s | tenant-b / api | 200m | high | Suspicious High Port Egress | Throttled by cgroup | 5 |
| `TMPL-MNR-06` | Obfuscated loop executing from `/tmp` binary wrapper on port 3333 | 151–250+ | 130s | tenant-c / database | 200m | high | Suspicious High Port Egress | Uses `/tmp`, cleaned | 5 |
| `TMPL-MNR-07` | Throttled mining with periodic DNS resolution probes | 151–250+ | 80s | tenant-a / web | 80m | throttled | Suspicious High Port Egress | Controlled CPU rate | 5 |
| `TMPL-MNR-08` | Stratum handshake simulation with intermittent 90m CPU pulses | 151–250+ | 90s | tenant-b / web | 90m | throttled | Suspicious High Port Egress | Controlled CPU rate | 5 |

---

### 3.5 Class: `unknown` (Ambiguous / Degraded Telemetry) (8 Templates, 20 Runs Proposed)

| ID | Description | Length Bin | Dur. (s) | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---|:---:|
| `TMPL-UNK-01` | Sensor dropout: normal command executed during simulated Falco gap | 30–80 | 7s | tenant-a / web | Low | low | None (simulated dropout) | Reversible test flag | 3 |
| `TMPL-UNK-02` | Truncated audit event: API request payload cut off mid-stream | 30–80 | 7s | tenant-b / api | Low | low | Shell Spawn | Synthetic stream test | 3 |
| `TMPL-UNK-03` | Conflicting signal: high-CPU compression without any network flow | 81–150 | 25s | tenant-c / database | Medium | burst | Shell Spawn | Legitimate burst | 3 |
| `TMPL-UNK-04` | Transient unknown binary execution from temporary path | 81–150 | 8s | tenant-a / payment-style | Low | low | Shell Spawn | Cleaned post-run | 3 |
| `TMPL-UNK-05` | Rapid port scan without subsequent process activity | 81–150 | 8s | tenant-b / web | Low | low | None | Egress blocked | 2 |
| `TMPL-UNK-06` | Incomplete K8s RBAC response (interrupted API server stream) | 151–250+ | 10s | tenant-c / api | Low | low | Shell Spawn | Incomplete telemetry | 2 |
| `TMPL-UNK-07` | Legitimate maintenance script triggering unexpected policy alert | 151–250+ | 12s | tenant-a / database | Low | low | Policy Warning | Ambiguous evidence | 2 |
| `TMPL-UNK-08` | Multi-source timestamp skew exceeding correlation window | 151–250+ | 15s | tenant-b / payment-style | Low | low | Shell Spawn | Window boundary test | 2 |

---

## 4. What This Plan Still Cannot Measure

Even after deploying this balanced 400-run plan, the following experimental boundaries remain:

1. **Loopback Egress vs. Real WAN Routing (Decision D-21):**
   - In-pod ephemeral loopback connect (`127.0.0.1:<port>`) simulates high-port network activity safely. It cannot measure WAN packet latency, internet BGP routing anomalies, or genuine remote mining pool protocol negotiations.
2. **Static Image Vulnerability Context (Single Cached Trivy Report):**
   - Because all workloads share a hardened Alpine 3.19 base image, Trivy vulnerability features are static across all runs. The plan cannot measure dynamic multi-image vulnerability variance (e.g., distinguishing vulnerable vs. patched base images).
3. **Single-Node Kind Cluster Topology:**
   - The Kind cluster runs inside a single virtualized control-plane node. Inter-node overlay network latency, cross-node kubelet scheduling jitter, and multi-node kernel variance are unobservable.
4. **Controlled Synthetic Scenarios:**
   - Probes represent simulated, benign-intent security indicators rather than weaponized zero-day exploits. The pipeline measures detection and classification accuracy against controlled attack primitives, not active evasion by sophisticated human adversaries.
