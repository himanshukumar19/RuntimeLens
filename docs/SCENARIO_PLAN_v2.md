# SCENARIO_PLAN_v2.md — Proposed 400-Run Multi-Source Scenario Plan

> **Status:** PROPOSED (Stage 3 Draft — NOT FROZEN).
> **Governance Notice:** Every count, duration, port and profile in this document is a *proposed* specification subject to Stage 4 human scenario review and formal user authorization. Zero runs have been scheduled or executed under this plan.
> **Class scope (Decision D-24):** `container_escape`, `privilege_abuse`, `cryptomining` + `benign` + `unknown`. `exfiltration` is not an attack class.

---

## 1. Proposed Class Budget

| Threat Class | Proposed Runs | Dev | Test | Templates | Runs per template | Rationale |
|:---|--:|--:|--:|--:|:--|:--|
| **`benign`** | **140** *(proposed)* | 101 | 39 | 21 | 7 (×14) and 6 (×7) | 39 test runs is the smallest count that can bound a 2% FPR with a 95% upper bound below ~7% (Clopper–Pearson). Benign is the FPR estimand, so it tolerates the largest absolute count while precision, not recall, is the target. Deliberately hosts six templates on in-list high ports to destroy the port shortcut. |
| **`container_escape`** | **80** *(proposed)* | 58 | 22 | 10 | 8 | Unchanged from the Stage 3 draft. Critical-severity class; 22 test runs adequate for recall CI. Ten templates are used so features 00, 01 and 02 each appear as `True` in at least two templates instead of only one. |
| **`privilege_abuse`** | **80** *(proposed)* | 58 | 22 | 8 | 10 | Unchanged. Every run yields a deterministic 403 audit event, so per-run information content is high and variance low. |
| **`cryptomining`** | **60** *(proposed)* | 43 | 17 | 8 | 8 (×4) and 7 (×4) | Raised from 40. Mining is the only class whose primary signal is a time series (cAdvisor sustained CPU), so it needs enough runs to estimate a distribution rather than a rate. 60 runs also allow 8 templates at n≈7–8. Cost: +20 runs ≈ +43 min of active cluster time. |
| **`unknown`** | **40** *(proposed)* | 29 | 11 | 8 | 5 | Raised from 20. The report claims a deterministic fail-safe that *never* silently returns benign; that claim is untestable at 20 runs. **All 40 runs are real live behaviour** — no telemetry manipulation of any kind. |
| **Total** | **400** *(proposed)* | **289** | **111** | **55** | — | 72.25% / 27.75%, within rounding of the pre-registered 72/28 split. |

Worst-case binomial 95% half-width at the proposed test counts (`p = 0.5`): benign ±15.7 pp (n=39), escape ±20.9 pp (n=22), privilege ±20.9 pp (n=22), mining ±23.8 pp (n=17), unknown ±29.5 pp (n=11).

---

## 2. Anti-Leakage & Confounder Rules

1. **Zero metadata leakage:** Scenario IDs (`SC-*`), ground-truth class names (`benign`, `cryptomining`, `container_escape`, `privilege_abuse`, `unknown`, `exfiltration`) and run identifiers (`run-*`) are forbidden from appearing in any command, argument, file path, env var, service name, pod name, label or probe payload.
2. **Command-length overlap:** every class spans all three bins at approximately 2 / 3 / 3 templates per class, scaled to benign's larger template count.
3. **Shell invariance:** every template is delivered through `kubectl exec ... /bin/sh -c`, so shell presence is 100% in all five classes and carries zero class information.
4. **Port invariance:** the Falco egress rule watches ports 3333, 4444, 5555, 7777, 8888, 9999. In-list ports are used by **benign**, **cryptomining** and **unknown** templates alike; two mining templates deliberately use out-of-list ports (8080, 6379) so mining is not identified by port either.
5. **Feature variation:** features `host_runtime_socket_mounted` (00), `sensitive_host_path_mounted` (01) and `privileged_container` (02) vary inside `container_escape` and are `False` everywhere else.
6. **Workload and tenancy balance:** templates rotate evenly across `tenant-a`, `tenant-b`, `tenant-c` and across `web`, `api`, `database`, `payment-style`.
7. **No telemetry manipulation:** the harness never pauses Falco, never truncates or edits an audit record, never injects timestamp skew and never mutates a cluster component.

### 2.1 Expected Falco Rules — grounded in observed telemetry only

The `Expected Falco Rules` column may name a rule **only if that rule has actually fired in real telemetry captured by this project**. Verified against the 25 collected pilot runs (`data/raw/runs/*/falco/events.jsonl`):

| Rule | Origin | Events / runs observed | Used in this plan |
|:---|:---|:---|:---|
| `Interactive Shell Spawned in Non-Debug Container` | Custom lab rule (`lab/falco/falco-values.yaml`) | 26 events / 25 runs | yes — every template |
| `Suspicious High Port Egress` | Custom lab rule (`lab/falco/falco-values.yaml`) | 16 events / 8 runs | yes — high-port templates |
| `Read Sensitive Host Information Untrusted` | Custom lab rule (`lab/falco/falco-values.yaml`) | 5 events / 5 runs | yes — sensitive-file templates |
| `Launch Sensitive Mount Container` | Custom lab rule (`lab/falco/falco-values.yaml`) | not fired in the 25-run pilot (hostPath mount templates are in `sandbox-workloads` only) | yes — escape mount templates, subject to 4a confirmation |
| `Contact K8S API Server From Container` | **Stock** Falco rule, chart `falco-9.2.0`, `/etc/falco/falco_rules.yaml:840` | **0 events / 0 runs** | **no — removed from this column** |

**`Contact K8S API Server From Container` was removed from the `Expected Falco Rules` column of `TMPL-PRV-01`, `-03`, `-05` and `-07`.** It is a genuine stock rule and its tags (`[maturity_stable, container, network, k8s, mitre_discovery, T1565]`) contain no class names, but it has **never fired in any telemetry this project has collected**: 0 occurrences in the deployed Falco log and 0 across all 25 real pilot runs. Its condition requires the API server to be contacted by DNS name (`fd.sip.name="kubernetes.default.svc.cluster.local"`), whereas the pilot's privilege commands connect to the raw ClusterIP `https://10.96.0.1:443/`, so the condition cannot match as written. Naming it as an *expected* rule would be an unverified claim about a signal that has never been observed.

The privilege templates therefore expect **only** `Shell Spawn` (the `Interactive Shell Spawned in Non-Debug Container` lab rule), and their class-level signal rests on the audit verbs, the Hubble flow band and the CPU band. Whether the stock API-server rule can be made to fire — and therefore whether it should be reintroduced into the plan — is a question for the Stage 4a smoke, and is tracked in `docs/STAGE4_RUNBOOK.md` §2.6.

---

## 3. Master Template Registry (55 templates, 400 runs, all proposed)

### 3.1 Class `benign` — 21 templates, 140 runs (proposed)

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-BEN-01` | Routine uptime and local DNS resolution | 30–80 | 7s | tenant-a / web | Low | low | Shell Spawn | F/F/F | get, create | MID | Zero state change | 7 |
| `TMPL-BEN-02` | Ephemeral file health check: touch and unlink in `/tmp` | 30–80 | 7s | tenant-b / api | Low | low | Shell Spawn | F/F/F | get, create | MID | Cleaned post-run | 6 |
| `TMPL-BEN-03` | Container environment verification: date and hostname | 30–80 | 7s | tenant-c / database | Low | low | Shell Spawn | F/F/F | get, create | MID | Read-only | 6 |
| `TMPL-BEN-04` | Internal health probe to service port **3333** | 30–80 | 8s | tenant-a / api | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-05` | Local cache client ping on port 6379 | 30–80 | 8s | tenant-c / web | Low | low | Shell Spawn | F/F/F | get, create | LOW | Out-of-list port | 6 |
| `TMPL-BEN-06` | Service account token read for in-cluster client auth | 81–150 | 8s | tenant-b / payment-style | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | Authorized SA read | 7 |
| `TMPL-BEN-07` | Internal metrics scrape probe on port **9999** | 81–150 | 8s | tenant-a / database | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-08` | Disk usage audit: `df -h` and `du -sk /tmp` | 81–150 | 8s | tenant-c / web | Low | low | Shell Spawn | F/F/F | get, create | MID | Read-only | 6 |
| `TMPL-BEN-09` | Internal metrics gateway check on port 9090 | 81–150 | 8s | tenant-b / database | Low | low | Shell Spawn | F/F/F | get, create | LOW | Out-of-list port | 6 |
| `TMPL-BEN-10` | Mounted TLS certificate inspection in `/etc/ssl` | 81–150 | 8s | tenant-a / web | Low | low | Shell Spawn | F/F/F | get, create | MID | Read-only certs | 6 |
| `TMPL-BEN-11` | Security compliance self-audit: UID and capability check | 81–150 | 8s | tenant-c / api | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | Read-only self-inspection | 7 |
| `TMPL-BEN-12` | In-cluster DNS benchmark: multi-lookup latency check | 81–150 | 10s | tenant-b / api | Low | low | Shell Spawn | F/F/F | get, create | MID | Normal UDP 53 | 6 |
| `TMPL-BEN-13` | Legacy cache cluster client on port **7777** | 151–250+ | 10s | tenant-c / payment-style | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-14` | Developer debug session: process and memory inspection | 151–250+ | 12s | tenant-a / database | Medium | burst | Shell Spawn | F/F/F | get, create | MID | Standard debug | 7 |
| `TMPL-BEN-15` | Database backup maintenance: dump file and md5 checksum | 151–250+ | 15s | tenant-b / payment-style | Medium | low | Shell Spawn | F/F/F | get, create | LOW | Uses `/tmp`, cleaned | 7 |
| `TMPL-BEN-16` | Log compression routine: multi-file gzip in ephemeral storage | 151–250+ | 25s | tenant-c / web | High | burst | Shell Spawn | F/F/F | get, create | LOW | CPU burst < 80m, cleaned | 7 |
| `TMPL-BEN-17` | Batch calculation script: iterative numeric search loop | 151–250+ | 30s | tenant-a / api | High | burst | Shell Spawn | F/F/F | get, create | LOW | CPU burst ~75m | 7 |
| `TMPL-BEN-18` | Configuration sync via in-cluster ConfigMap query | 151–250+ | 10s | tenant-b / database | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | Authorized API read | 7 |
| `TMPL-BEN-19` | Internal edge proxy health check on port **4444** | 151–250+ | 10s | tenant-c / payment-style | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-20` | Internal queue consumer connection on port **5555** | 151–250+ | 10s | tenant-a / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-21` | Legacy internal file-transfer service on port **8888** | 151–250+ | 12s | tenant-b / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |

### 3.2 Class `container_escape` — 10 templates, 80 runs (proposed)

All escape templates execute in the ephemeral `sandbox-workloads` namespace only, are deleted immediately after the run, and never target a tenant namespace.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-ESC-01` | Read `/etc/shadow` and `/etc/passwd` inside container | 30–80 | 7s | tenant-a / database | Low | low | Shell Spawn, Sensitive File Read | F/F/F | get, create | MID | Passive read only | 8 |
| `TMPL-ESC-02` | Probe `/proc/kcore` and `/proc/sys/kernel` parameters | 30–80 | 7s | tenant-b / web | Low | low | Shell Spawn, Sensitive File Read | F/F/F | get, create | LOW | Read-only inspection | 8 |
| `TMPL-ESC-03` | Runtime socket exposure: `hostPath` **File** mount of `/opt/runtimelens-dummy/docker.sock` | 81–150 | 8s | tenant-c / payment-style | Medium | low | Shell Spawn, Sensitive Mount | **T**/F/F | get, create | MID | Already allowlisted; inert 0-byte file | 8 |
| `TMPL-ESC-04` | Sensitive host path exposure: `hostPath` **Directory** mount of `/opt/runtimelens-dummy/etc` | 81–150 | 8s | tenant-a / api | Medium | low | Shell Spawn, Sensitive Mount | F/**T**/F | get, create | LOW | **Requires linter edit (see §4)** | 8 |
| `TMPL-ESC-05` | Cgroup `release_agent` breakout path traversal check | 81–150 | 8s | tenant-b / database | High | low | Shell Spawn, Sensitive File Read | F/F/F | get, create | LOW | Read-only path existence check | 8 |
| `TMPL-ESC-06` | Privileged container capability probe: debugfs and namespace tool check | 81–150 | 10s | tenant-c / web | High | low | Shell Spawn, Sensitive Mount | F/F/**T** | get, create | MID | `privileged: true`, sandbox ns only | 8 |
| `TMPL-ESC-07` | Container `/proc/1/root` symlink traversal check (readlink only) | 151–250+ | 10s | tenant-a / web | High | low | Shell Spawn, Sensitive File Read | F/F/F | get, create | LOW | No `hostPID`; readlink only | 8 |
| `TMPL-ESC-08` | Device node creation attempt via `mknod` in privileged sandbox | 151–250+ | 10s | tenant-b / api | High | low | Shell Spawn, Sensitive Mount | F/F/**T** | get, create | LOW | Blocked by dropped capabilities | 8 |
| `TMPL-ESC-09` | Sensitive host path multi-file read via `head`, `dd` and `find` on the dummy dir | 151–250+ | 12s | tenant-c / payment-style | High | low | Shell Spawn, Sensitive Mount, Sensitive File Read | F/**T**/F | get, create | MID | Read-only on inert dummy dir | 8 |
| `TMPL-ESC-10` | Privileged capability enumeration via `/proc/self/status` capability walk | 151–250+ | 10s | tenant-a / database | High | low | Shell Spawn, Sensitive Mount, Policy Warning | F/F/**T** | get, create | LOW | `privileged: true`, sandbox ns only | 8 |

### 3.3 Class `privilege_abuse` — 8 templates, 80 runs (proposed)

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-PRV-01` | Cross-tenant Secrets list against adjacent namespace | 30–80 | 7s | tenant-a / api | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | 403 Forbidden | 10 |
| `TMPL-PRV-02` | Cross-tenant Pods enumeration against adjacent namespace | 30–80 | 7s | tenant-b / web | Low | low | Shell Spawn | F/F/F | get, create, list | LOW | 403 Forbidden | 10 |
| `TMPL-PRV-03` | Cluster-wide ServiceAccount token enumeration | 81–150 | 8s | tenant-c / database | Medium | low | Shell Spawn | F/F/F | get, create, list | HIGH | 403 Forbidden | 10 |
| `TMPL-PRV-04` | Unauthorized ConfigMaps extraction from adjacent tenant | 81–150 | 8s | tenant-a / payment-style | Medium | low | Shell Spawn | F/F/F | get, create, list | LOW | 403 Forbidden | 10 |
| `TMPL-PRV-05` | ClusterRoleBinding inspection attempt using pod SA | 81–150 | 10s | tenant-b / api | Medium | low | Shell Spawn | F/F/F | get, create, list | MID | 403 Forbidden | 10 |
| `TMPL-PRV-06` | Inter-pod exec subresource probe in adjacent namespace | 151–250+ | 10s | tenant-c / payment-style | High | low | Shell Spawn | F/F/F | get, create | LOW | 403 Forbidden | 10 |
| `TMPL-PRV-07` | Node proxy endpoint reconnaissance loop via kube-apiserver | 151–250+ | 20s | tenant-a / database | High | burst | Shell Spawn | F/F/F | get, create | MID | 403 Forbidden, short burst | 10 |
| `TMPL-PRV-08` | Batch multi-namespace resource scraping with extracted token | 151–250+ | 12s | tenant-b / payment-style | High | low | Shell Spawn | F/F/F | get, create, list | HIGH | All attempts 403 logged | 10 |

### 3.4 Class `cryptomining` — 8 templates, 60 runs (proposed)

Two templates deliberately use ports **outside** the Falco rule range so that port is not decisive for mining either.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-MNR-01` | Full-throttle CPU loop with pool connect on port **3333** | 30–80 | 130s | tenant-a / web | 200m | high | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | cgroup-capped at 500m | 8 |
| `TMPL-MNR-02` | Full-throttle CPU loop with pool connect on port **4444** | 30–80 | 130s | tenant-b / database | 200m | high | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | cgroup-capped at 500m | 8 |
| `TMPL-MNR-03` | Throttled loop (50 ms pause) on port **8080** (out-of-list) | 81–150 | 70s | tenant-c / api | 75m | throttled | Shell Spawn | F/F/F | get, create | LOW | Safe throttled load | 8 |
| `TMPL-MNR-04` | Throttled loop (75 ms pause) on port **5555** | 81–150 | 70s | tenant-a / payment-style | 60m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | Safe throttled load | 8 |
| `TMPL-MNR-05` | Full-throttle CPU loop with pool connect on port **6379** (out-of-list) | 81–150 | 130s | tenant-b / api | 200m | high | Shell Spawn | F/F/F | get, create | LOW | cgroup-capped at 500m | 7 |
| `TMPL-MNR-06` | Throttled loop (60 ms pause) on port **7777** | 151–250+ | 70s | tenant-c / database | 70m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | Safe throttled load | 7 |
| `TMPL-MNR-07` | Throttled loop with periodic DNS lookups on port **9999** | 151–250+ | 80s | tenant-a / web | 80m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | MID | Controlled CPU rate | 7 |
| `TMPL-MNR-08` | Stratum handshake simulation with 90m pulses on port **8888** | 151–250+ | 90s | tenant-b / web | 90m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | Controlled CPU rate | 7 |

### 3.5 Class `unknown` — 8 templates, 40 runs (proposed)

**All eight are real live behaviour. No telemetry is manipulated, no sensor is paused, no log is truncated or edited, no clock is skewed and no cluster component is mutated.** The ambiguity is intrinsic to the activity, not injected by the harness.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-UNK-04` | Transient execution of a short-lived binary from `/tmp` | 30–80 | 8s | tenant-a / payment-style | Low | low | Shell Spawn | F/F/F | get, create | LOW | Binary deleted post-run | 5 |
| `TMPL-UNK-R3` | Health-check liveness probe to an internal service on port **3333** | 30–80 | 8s | tenant-b / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | Fully authorised; real ambiguity | 5 |
| `TMPL-UNK-03` | Legitimate log compression: high CPU with zero egress | 81–150 | 25s | tenant-c / database | Medium | burst | Shell Spawn | F/F/F | get, create | LOW | Real high-CPU-no-egress case | 5 |
| `TMPL-UNK-05` | Rapid egress probe across 3333–9999 dropped by default-deny | 81–150 | 8s | tenant-a / api | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | HIGH | Blocked by NetworkPolicy | 5 |
| `TMPL-UNK-R2` | Authorised batch recomputation at 110 mcores for 90s | 81–150 | 95s | tenant-b / database | Medium | burst | Shell Spawn | F/F/F | get, create | LOW | No pool egress; real ambiguity | 5 |
| `TMPL-UNK-07` | Maintenance script that trips a policy rule without being malicious | 151–250+ | 12s | tenant-c / payment-style | Low | low | Shell Spawn, Policy Warning | F/F/F | get, create | MID | Ambiguous by design of policy | 5 |
| `TMPL-UNK-R1` | Shared-ServiceAccount contention: two workloads, one identity | 151–250+ | 15s | tenant-a / database | Medium | low | Shell Spawn | F/F/F | get, create, list | HIGH | Real attribution ambiguity | 5 |
| `TMPL-UNK-R4` | Rollout-induced exec burst across four pods in one namespace | 151–250+ | 20s | tenant-b / payment-style | Medium | low | Shell Spawn | F/F/F | get, create | HIGH | Real orchestration burst | 5 |

**Templates removed from the Stage 3 draft:** `TMPL-UNK-01` (sensor dropout), `TMPL-UNK-02` (truncated audit record), `TMPL-UNK-06` (interrupted API stream), `TMPL-UNK-08` (timestamp skew). Each of the four manipulated the harness or the cluster rather than observing real behaviour, and all four are withdrawn so that no `SIMULATED` label is required anywhere in this plan.

---

## 4. Safety Linter Changes Required — **APPLIED 2026-10-20**

`TMPL-ESC-04`, `TMPL-ESC-09` and any future dummy-directory mount required **one** linter change, at `scripts/scenario_safety_lint.py` line 21. That change has been applied:

```python
ALLOWED_DUMMY_HOSTPATHS: Final[frozenset[str]] = frozenset(
    {
        "/opt/runtimelens-dummy/docker.sock",
        "/opt/runtimelens-dummy/containerd.sock",
        # Inert dummy DIRECTORY (type: Directory) for TMPL-ESC-04 / TMPL-ESC-09.
        # Never a real host path: contains no host state, no credentials, no runtime socket.
        "/opt/runtimelens-dummy/etc",
    }
)
```

No other linter rule changed. Already enforced and unchanged, each with a regression test in `tests/unit/test_scenario_safety_lint.py`:

- `hostPath` permitted only in `ALLOWED_LAB_NAMESPACES = {"sandbox-workloads"}` (line 129–136).
- `privileged: true` permitted only in that same namespace (line 146–150).
- `hostPID`, `hostNetwork`, `hostIPC: true` unconditionally forbidden (lines 101–107) — this is why `TMPL-ESC-07` uses a readlink on the container's own `/proc/1/root` instead of a host-PID pod.
- Real runtime sockets `/var/run/docker.sock`, `/run/containerd`, `/var/run/containerd`, `/var/run/crio`, `/run/crio` forbidden (lines 28–34, 116–120).
- External destinations rejected except `*.svc`, `*.cluster.local`, `127.`, `10.`, `172.18.`, `localhost`, `kubernetes.default` (lines 166–186).
- Class-leak tokens in any name, label or container name (lines 36–76, 141–142). Note this includes `esc`, `prv` and `mnr`, so a *cluster resource* may not be named after a template id; template ids are documentation identifiers only.

**Verification (offline, 3 manifest cases, all passing):** the dummy `etc` directory in `sandbox-workloads` PASSes; `/etc/kubernetes` as a hostPath FAILS (`hostPath outside dummy allowlist`); `hostPID: true` in `sandbox-workloads` FAILS (`Forbidden hostPID: true`).

---

## 5. What This Plan Still Cannot Measure

1. **Loopback egress (Decision D-21).** High-port probes use in-pod loopback and inert UDP targets, so WAN latency, real pool-protocol negotiation and internet-scale egress behaviour are unobservable. Ports are therefore observable as a *syscall signature* only.
2. **Single static Trivy report.** All workloads share one hardened Alpine 3.19 base image, so vulnerability features never vary across the 400 runs. Dynamic multi-image CVE variance cannot be measured.
3. **Single-node kind.** One control-plane node means inter-node overlay latency, cross-node scheduling jitter and multi-node kernel variance are all unobservable.
4. **Controlled synthetic scenarios.** Probes are benign-intent simulations of attack primitives. They measure detector and policy behaviour, not evasion by a sophisticated adversary, and escape scenarios simulate the exploit payload rather than performing a real host breakout.
5. **Shell-delivery invariance.** Because every template runs through `kubectl exec ... /bin/sh -c`, `is_shell_process` and `is_root_user` are constant across all 400 runs and therefore contribute nothing to classification. This is deliberate (shell must not separate classes) but it also means those two features are untested by this dataset.

---

## 6. Table F — Telemetry Signature Diversity

Signature = `(Falco rule set | audit verbs | Hubble flow band | CPU band)`. Hubble bands: LOW 0–6 flows, MID 7–11, HIGH 12+. CPU bands: LOW (peak < 40 m), MID (peak 40–100 m), HIGH (median ≥ 100 m).

A class where **≥ 60 %** of runs share one signature is **FLAGGED**: that means one telemetry signature would by itself identify the class, i.e. a trivial shortcut exists.

### 6.1 Plan-level Table F (expected, computed from the registry above)

Computed from this plan's own columns, weighted by the planned run counts. **This is a prediction, not a measurement.**

| Class | Runs | Distinct signatures | Largest single signature | Flagged |
|:---|--:|--:|--:|:--|
| `benign` | 140 | 6 | 30.0 % | no |
| `container_escape` | 80 | 6 | 30.0 % | no |
| `privilege_abuse` | 80 | 5 | 37.5 % | no |
| `cryptomining` | 60 | 5 | 36.7 % | no |
| `unknown` | 40 | 7 | 25.0 % | no |

### 6.2 Real Table F (measured, 25 real pilot runs)

Computed by `scripts/signature_table.py --runs-dir data/raw/runs` over the 25 collected real runs. **This is a measurement, and it contradicts §6.1.**

| Class | Runs | Distinct signatures | Largest single signature | Flagged |
|:---|--:|--:|--:|:--|
| `benign` | 5 | 2 | 80.0 % | **yes** |
| `container_escape` | 5 | 1 | **100.0 %** | **yes** |
| `cryptomining` | 5 | 2 | 80.0 % | **yes** |
| `privilege_abuse` | 5 | 3 | 40.0 % | no |

**Why the two tables disagree, stated plainly:** the pilot executed only **one scenario per class** (`SC-BEN-01`, `SC-ESC-01`, `SC-PRV-01`, `SC-MNR-01`, `SC-EXF-01`), so every run inside a class had the same Falco rule set, the same audit verbs, the same Hubble flow count and the same CPU band. The 100 % figure for `container_escape` is therefore a property of the **pilot's scenario count**, not evidence that this plan is broken. The 55 templates exist precisely to create the signature variety that §6.1 predicts.

**Consequence:** the plan-level table in §6.1 remains an unverified hypothesis. The Stage 4a smoke (1 run per template = 55 runs) is the first measurement that can test it, and the real table produced there replaces §6.1 as the authoritative table. Until then, no claim of signature diversity may be made in the report. The 5 dropped exfiltration runs are reported in the per-run detail and excluded from the per-class statistics.
