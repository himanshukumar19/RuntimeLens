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
2. **Command-length overlap:** every class spans all three bins at approximately 2 / 3 / 3 templates per class, scaled to benign's larger template count. **Amended at Stage 4a Part 2 and Round 2 (see §3.6):** the `privilege_abuse` class provably cannot occupy the `30–80` bin, because no request that produces a captured audit event fits inside 80 characters (the shortest unauthenticated request still captured is 82 characters, and the shortest ServiceAccount-authenticated request is 141 characters). Two templates were therefore re-scoped — `TMPL-PRV-02` to an unauthenticated own-namespace enumeration (88 characters) and `TMPL-PRV-05` to a ServiceAccount-authenticated API group discovery (148 characters) — which gives the class a `0 / 2 / 6` distribution. In addition, **Decision D-28 removes `command_length` from the classifier feature set entirely** (18 features, not 19) and retains it only as a labelled diagnostic, so the residual length confound cannot be exploited by any model. The compensating controls of §3.6.3 remain mandatory.
3. **Shell invariance:** every template is delivered through `kubectl exec ... /bin/sh -c`, so shell presence is 100% in all five classes and carries zero class information.
4. **Port invariance:** the Falco egress rule watches ports 3333, 4444, 5555, 7777, 8888, 9999. In-list ports are used by **benign**, **cryptomining** and **unknown** templates alike; two mining templates deliberately use out-of-list ports (8080, 6379) so mining is not identified by port either.
5. **Feature variation:** features `host_runtime_socket_mounted` (00), `sensitive_host_path_mounted` (01) and `privileged_container` (02) vary inside `container_escape` and are `False` everywhere else.
6. **Workload and tenancy balance:** templates rotate evenly across `tenant-a`, `tenant-b`, `tenant-c` and across `web`, `api`, `database`, `payment-style`.
7. **No telemetry manipulation:** the harness never pauses Falco, never truncates or edits an audit record, never injects timestamp skew and never mutates a cluster component.
8. **Network-observation coverage (Decision D-29):** every template must produce at least one Hubble flow, because the per-run gate requires all five telemetry sources to carry at least one event. A scenario that opens no socket and resolves no name is therefore given exactly **one declared benign network observation** from a shared vocabulary (§3.6.4). The observation type is varied so that it is **not a class marker**: the same A / B / C mix appears in the `benign`, `container_escape`, `privilege_abuse` and `unknown` classes, and the pre-existing type D is shared with the mining and benign classes. The observation is in-cluster, read-only and carries no credential; type C targets the world-readable API discovery document, which the audit collector does not attribute to the workload, so it is audit-neutral.

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
| `TMPL-BEN-02` | Ephemeral file health check: touch and unlink in `/tmp` | 30–80 | 7s | tenant-b / api | Low | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 68 chars | 6 |
| `TMPL-BEN-03` | Container environment verification: date and hostname | 30–80 | 7s | tenant-c / database | Low | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 57 chars | 6 |
| `TMPL-BEN-04` | Internal health probe to service port **3333** | 30–80 | 8s | tenant-a / api | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | In-list port, benign intent | 7 |
| `TMPL-BEN-05` | Local cache client ping on port 6379 | 30–80 | 8s | tenant-c / web | Low | low | Shell Spawn | F/F/F | get, create | LOW | own network activity (**D**); 52 chars | 6 |
| `TMPL-BEN-06` | Service account token read for in-cluster client auth | 151–250+ | 8s | tenant-b / payment-style | Low | low | Shell Spawn | F/F/F | get, create, list | MID | Authorized SA read, BusyBox `--header=` form (181 chars); band predicted from the measured `TMPL-BEN-11` shape (10 flows, own-namespace collection read) | 7 |
| `TMPL-BEN-07` | Internal metrics scrape probe on port **9999** | 81–150 | 8s | tenant-a / database | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 84 chars | 7 |
| `TMPL-BEN-08` | Disk usage audit: `df -h` and `du -sk /tmp` | 81–150 | 8s | tenant-c / web | Low | low | Shell Spawn | F/F/F | get, create | LOW | network observation **A** (D-29); 84 chars | 6 |
| `TMPL-BEN-09` | Internal metrics gateway check on port 9090 | 30–80 | 8s | tenant-b / database | Low | low | Shell Spawn | F/F/F | get, create | LOW | own network activity (**D**); 52 chars | 6 |
| `TMPL-BEN-10` | Mounted TLS certificate inspection in `/etc/ssl` | 30–80 | 8s | tenant-a / web | Low | low | Shell Spawn | F/F/F | get, create | LOW | network observation **D** (D-29); 74 chars | 6 |
| `TMPL-BEN-11` | Security compliance self-audit: UID and capability check | 81–150 | 8s | tenant-c / api | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | Read-only self-inspection | 7 |
| `TMPL-BEN-12` | In-cluster DNS benchmark: multi-lookup latency check | 81–150 | 10s | tenant-b / api | Low | low | Shell Spawn | F/F/F | get, create | LOW | own network activity (**A**); 126 chars | 6 |
| `TMPL-BEN-13` | Legacy cache cluster client on port **7777** | 151–250+ | 10s | tenant-c / payment-style | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 157 chars | 7 |
| `TMPL-BEN-14` | Developer debug session: process and memory inspection | 151–250+ | 90s | tenant-a / database | Medium | burst | Shell Spawn | F/F/F | get, create | MID | Standard debug; **network observation B** (D-29); **~30 s burn in a 90 s window** (D-30), 218 chars | 7 |
| `TMPL-BEN-15` | Database backup maintenance: dump file and md5 checksum | 151–250+ | 15s | tenant-b / payment-style | Medium | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 264 chars | 7 |
| `TMPL-BEN-16` | Log compression routine: throttled multi-cycle gzip in ephemeral storage | 151–250+ | 90s | tenant-c / web | High | burst | Shell Spawn | F/F/F | get, create | MID | ~36 s burn of 8 throttled gzip cycles at ~65–70m (D-30), cleaned; **network observation C** (D-29), 211 chars | 7 |
| `TMPL-BEN-17` | Batch calculation script: iterative numeric search loop | 151–250+ | 90s | tenant-a / api | High | burst | Shell Spawn | F/F/F | get, create | LOW | ~25 s burn at ~90m, ~60% duty of the 200m limit (D-30); **network observation A** (D-29), 174 chars | 7 |
| `TMPL-BEN-18` | Configuration sync via an in-cluster ConfigMap read of the own namespace | 151–250+ | 10s | tenant-b / database | Low | low | Shell Spawn | F/F/F | get, create, list | MID | own network activity (**C**); 187 chars | 7 |
| `TMPL-BEN-19` | Internal edge proxy health check on port **4444** | 81–150 | 10s | tenant-c / payment-style | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 129 chars | 7 |
| `TMPL-BEN-20` | Internal queue consumer connection on port **5555** | 30–80 | 10s | tenant-a / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 52 chars | 7 |
| `TMPL-BEN-21` | Legacy internal file-transfer service on port **8888** | 151–250+ | 12s | tenant-b / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 194 chars | 7 |

### 3.2 Class `container_escape` — 10 templates, 80 runs (proposed)

All escape templates execute in the ephemeral `sandbox-workloads` namespace only, are deleted immediately after the run, and never target a tenant namespace.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-ESC-01` | Read `/etc/shadow` and `/etc/passwd` inside the container's own filesystem | 81–150 | 7s | sandbox-workloads / worker | Low | low | Shell Spawn, Sensitive File Read | F/F/F | get, create | LOW | network observation **A** (D-29); 93 chars | 8 |
| `TMPL-ESC-02` | Probe `/proc/kcore` and `/proc/sys/kernel` parameters | 81–150 | 7s | sandbox-workloads / worker | Low | low | Shell Spawn | F/F/F | get, create | MID | network observation **C** (D-29); 133 chars | 8 |
| `TMPL-ESC-03` | Runtime socket exposure: `hostPath` **File** mount of `/opt/runtimelens-dummy/docker.sock` | 81–150 | 8s | sandbox-workloads / worker | Medium | low | Shell Spawn, Sensitive Mount | **T**/F/F | get, create | MID | Already allowlisted; inert 0-byte file; **rule firing VERIFIED in Stage 4a attempt 2** | 8 |
| `TMPL-ESC-04` | Sensitive host path exposure: `hostPath` **Directory** mount of `/opt/runtimelens-dummy/etc` | 151–250+ | 8s | sandbox-workloads / worker | Medium | low | Shell Spawn, Sensitive Mount, Sensitive File Read | F/**T**/F | get, create | LOW | reads the dummy `shadow` (identity rule) **and** the dummy `hosts` (mount rule) so both rules fire (D-31), 161 chars | 8 |
| `TMPL-ESC-05` | **Cgroup hierarchy exposure in privileged sandbox** (replaces the cgroup v1 `release_agent` traversal) | 151–250+ | 8s | sandbox-workloads / worker | High | low | **Shell Spawn** | F/F/**T** | get, create | LOW | Read-only; uses cgroup v2 paths that exist (`/proc/self/cgroup`, `/proc/self/mountinfo`, `/proc/self/mounts`); **network observation A** (D-29), 228 chars | 8 |
| `TMPL-ESC-06` | Privileged container capability probe: debugfs and namespace tool check | 81–150 | 10s | sandbox-workloads / worker | High | low | **Shell Spawn** | F/F/**T** | get, create | MID | `privileged: true`, sandbox ns only; **no `hostPath` volume, so Sensitive Mount cannot fire** | 8 |
| `TMPL-ESC-07` | Container `/proc/1/root` symlink traversal check (readlink only, no `hostPID`) | 30–80 | 10s | sandbox-workloads / worker | High | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 74 chars | 8 |
| `TMPL-ESC-08` | **Host device namespace enumeration in privileged sandbox** (replaces the `mknod` attempt) | 81–150 | 10s | sandbox-workloads / worker | High | low | **Shell Spawn** | F/F/**T** | get, create | MID | Read-only `/dev` listing; `mknod` removed because the device cgroup blocks it even when privileged; **network observation B** (D-29), 91 chars | 8 |
| `TMPL-ESC-09` | Sensitive host path multi-file read via `head`, `dd` and `find` on the dummy dir | 151–250+ | 12s | sandbox-workloads / worker | High | low | Shell Spawn, Sensitive Mount, Sensitive File Read | F/**T**/F | get, create | MID | Requires the four inert dummy files in `/opt/runtimelens-dummy/etc/` (see §4); reads the dummy identity files **and** the dummy `hosts` so both rules fire (D-31); **network observation C** (D-29), 309 chars | 8 |
| `TMPL-ESC-10` | **Runtime socket (containerd) exposure in privileged sandbox** (replaces the non-existent "Policy Warning" expectation) | 81–150 | 10s | sandbox-workloads / worker | High | low | Shell Spawn, Sensitive Mount | **T**/F/**T** | get, create | MID | `privileged: true` + `hostPath` File mount of the third allowlisted dummy path `/opt/runtimelens-dummy/containerd.sock`; **real read** `head -c 1` so the mount rule fires (D-31), 129 chars | 8 |

### 3.3 Class `privilege_abuse` — 8 templates, 80 runs (proposed)

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-PRV-01` | Cross-tenant Secrets list against adjacent namespace | 151–250+ | 7s | tenant-a / api | Low | low | Shell Spawn | F/F/F | get, create, list | HIGH | 403 Forbidden; SA token auth (219 chars, VERIFIED) | 10 |
| `TMPL-PRV-02` | **Unauthenticated own-namespace Pod collection enumeration** (credential-less API enumeration) | 81–150 | 7s | tenant-b / web | Low | low | Shell Spawn | F/F/F | get, create, list | MID | 403 Forbidden; **no credential presented** (88 chars) | 10 |
| `TMPL-PRV-03` | Cluster-wide ServiceAccount token enumeration | 151–250+ | 8s | tenant-c / database | Medium | low | Shell Spawn | F/F/F | get, create, list | HIGH | 403 Forbidden; SA token auth (207 chars, VERIFIED) | 10 |
| `TMPL-PRV-04` | Unauthorized ConfigMaps extraction from adjacent tenant | 151–250+ | 8s | tenant-a / payment-style | Medium | low | Shell Spawn | F/F/F | get, create, list | MID | 403 Forbidden; SA token auth, BusyBox `--header=` form (187 chars); band predicted from the measured `TMPL-PRV-03` shape (16 flows, no extra DNS probe) | 10 |
| `TMPL-PRV-05` | **API surface reconnaissance using the pod ServiceAccount** (authenticated discovery of the served API paths) | 151–250+ | 10s | tenant-b / api | Medium | low | Shell Spawn | F/F/F | get, create | MID | SA-attributed audit record; BusyBox `--header=` form (153 chars) | 10 |
| `TMPL-PRV-06` | Inter-pod `exec` subresource probe against an adjacent namespace (403) | 151–250+ | 10s | tenant-c / payment-style | High | low | Shell Spawn | F/F/F | get, create | MID | network observation **A** (D-29); 260 chars | 10 |
| `TMPL-PRV-07` | Node proxy endpoint reconnaissance loop via kube-apiserver | 151–250+ | 20s | tenant-a / database | High | **low** | Shell Spawn | F/F/F | get, create | **HIGH** | 403 Forbidden; **I/O-bound, no measurable CPU load — CPU profile re-declared `low` (D-30)**; SA token auth, BusyBox `--header=` form (229 chars); **46 flows measured** (five node-proxy requests, each a full TCP retry sequence) | 10 |
| `TMPL-PRV-08` | Batch multi-namespace resource scraping with the extracted token | 151–250+ | 12s | tenant-b / payment-style | High | low | Shell Spawn | F/F/F | get, create, list | HIGH | network observation **D** (D-29); 270 chars | 10 |

**Length Bin Correction Note (Stage 4a Part 1, re-verified Part 2, corrected Round 2):** in-cluster API queries that authenticate with the pod's ServiceAccount token incur 126 characters of shell overhead (`T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);` = 57 chars, plus `wget -qO- --no-check-certificate --header="Authorization: Bearer $T" ` = 69 chars), so no such request can fit inside the `30–80` or `81–150` bins. `TMPL-PRV-01` (219 chars) and `TMPL-PRV-03` (207 chars) were corrected in Part 1; Part 2 measured the remaining commands; **Round 2 corrected the measurement itself**: the re-scoped commands had been written with the short `-H` header option, which **BusyBox `wget` does not support** (it accepts only `--header`), so those commands aborted before any network request and never reached the API server. All four affected templates (`TMPL-PRV-04`, `TMPL-PRV-05`, `TMPL-BEN-06`, `TMPL-PRV-07`) were restored to the verified `--header=` form, which is 5 characters longer; the corrected lengths are `TMPL-PRV-04` (187), `TMPL-PRV-05` (153), `TMPL-BEN-06` (181) and `TMPL-PRV-07` (229). See §3.6 for the rebalanced bin table, the physical constraint that forces the `privilege_abuse` class into a single bin, and the compensating control.

### 3.4 Class `cryptomining` — 8 templates, 60 runs (proposed)

Two templates deliberately use ports **outside** the Falco rule range so that port is not decisive for mining either.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-MNR-01` | Full-throttle CPU loop with a pool connect on port **3333** | 151–250+ | 130s | tenant-a / web | 200m | high | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**) + observation **A** (D-29); 192 chars; cgroup-capped at 200m; D-22 125 s busy loop; expected 6 Hubble flows (4 DNS + 2 dropped pool egress) | 8 |
| `TMPL-MNR-02` | Full-throttle CPU loop with a pool connect on port **4444** | 151–250+ | 130s | tenant-b / database | 200m | high | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**) + observation **A** (D-29); 192 chars; cgroup-capped at 200m; D-22 125 s busy loop; expected 6 Hubble flows (4 DNS + 2 dropped pool egress) | 8 |
| `TMPL-MNR-03` | Throttled loop (50 ms pause) on port **8080** (out-of-list) | 81–150 | 70s | tenant-c / api | 75m | throttled | Shell Spawn | F/F/F | get, create | LOW | Safe throttled load | 8 |
| `TMPL-MNR-04` | Throttled loop (75 ms pause) on port **5555** | 81–150 | 70s | tenant-a / payment-style | ~80m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 144 chars; D-27 throttled duty cycle, ~80m (measured 80.17 m in Round 5a attempt 2); expected 2 Hubble flows (2 dropped pool egress) | 8 |
| `TMPL-MNR-05` | Full-throttle CPU loop with a pool connect on port **6379** (out-of-list) | 151–250+ | 130s | tenant-b / api | 200m | high | Shell Spawn | F/F/F | get, create | LOW | own network activity (**D**) + observation **A** (D-29); 192 chars; cgroup-capped at 200m; D-22 125 s busy loop; expected 6 Hubble flows (4 DNS + 2 dropped pool egress) | 7 |
| `TMPL-MNR-06` | Throttled loop (90 ms pause) on port **7777** | 81–150 | 70s | tenant-c / database | ~69m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 143 chars; D-27 throttled duty cycle, ~69m (derived from the MNR-04 measurement, 90 ms pause); expected 2 Hubble flows (2 dropped pool egress) | 7 |
| `TMPL-MNR-07` | Throttled loop with periodic DNS lookups on port **9999** | 151–250+ | 80s | tenant-a / web | ~80m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**A**); 239 chars; D-27 throttled duty cycle, ~80m (derived from the MNR-04 measurement, 75 ms pause plus DNS); expected 6 Hubble flows (4 DNS + 2 dropped pool egress) | 7 |
| `TMPL-MNR-08` | Stratum handshake simulation with pulses on port **8888** | 81–150 | 90s | tenant-b / web | ~96m | throttled | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 144 chars; D-27 throttled duty cycle, ~96m (derived from the MNR-04 measurement, 60 ms pause); expected 2 Hubble flows (2 dropped pool egress) | 7 |

### 3.5 Class `unknown` — 8 templates, 40 runs (proposed)

**All eight are real live behaviour. No telemetry is manipulated, no sensor is paused, no log is truncated or edited, no clock is skewed and no cluster component is mutated.** The ambiguity is intrinsic to the activity, not injected by the harness.

| ID | Description | Length Bin | Duration | Tenant / Workload | Intensity | CPU Profile | Expected Falco Rules | Feature Values 00/01/02 | Audit Verbs | Hubble Band | Safety Notes | Runs |
|:---|:---|:---:|:---:|:---|:---:|:---:|:---|:---:|:---|:---:|:---|--:|
| `TMPL-UNK-04` | Transient execution of a short-lived script from `/tmp` | 81–150 | 8s | tenant-a / payment-style | Low | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 81 chars | 5 |
| `TMPL-UNK-R3` | Health-check liveness probe on port **3333** | 30–80 | 8s | tenant-b / web | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | LOW | own network activity (**D**); 52 chars | 5 |
| `TMPL-UNK-03` | Legitimate log compression: high CPU with zero egress | 151–250+ | 25s | tenant-c / database | Medium | burst | Shell Spawn | F/F/F | get, create | LOW | Real high-CPU-no-egress case; **185 chars after the Stage 4a Part 1 burst command was lengthened** | 5 |
| `TMPL-UNK-05` | Rapid egress probe across 3333–9999 dropped by default-deny | 81–150 | 8s | tenant-a / api | Low | low | Shell Spawn, High Port Egress | F/F/F | get, create | HIGH | own network activity (**D**); 99 chars | 5 |
| `TMPL-UNK-R2` | Authorised batch recomputation: ~30 s throttled recomputation burst inside a 90 s window | 151–250+ | 90s | tenant-b / database | Medium | burst | Shell Spawn | F/F/F | get, create | LOW | No pool egress; the only egress is the **network observation A** (D-29); **~30 s burn in a 90 s window** (D-30), 155 chars; real ambiguity | 5 |
| `TMPL-UNK-07` | Maintenance script whose egress is denied by the default-deny NetworkPolicy (a policy trip that is not malicious) | 30–80 | 12s | tenant-c / payment-style | Low | low | Shell Spawn | F/F/F | get, create | MID | own network activity (**B**); 75 chars | 5 |
| `TMPL-UNK-R1` | Shared-ServiceAccount contention: two workloads, one identity | 151–250+ | 15s | tenant-a / database | Medium | low | Shell Spawn | F/F/F | get, create, list | MID | own network activity (**C**); 181 chars | 5 |
| `TMPL-UNK-R4` | Rollout-induced exec burst: four short-lived shells in one workload | 30–80 | 20s | tenant-b / payment-style | Medium | low | Shell Spawn | F/F/F | get, create | MID | network observation **B** (D-29); 74 chars | 5 |

**Templates removed from the Stage 3 draft:** `TMPL-UNK-01` (sensor dropout), `TMPL-UNK-02` (truncated audit record), `TMPL-UNK-06` (interrupted API stream), `TMPL-UNK-08` (timestamp skew). Each of the four manipulated the harness or the cluster rather than observing real behaviour, and all four are withdrawn so that no `SIMULATED` label is required anywhere in this plan.

---

### 3.6 Stage 4a Part 2 Corrections — Expected Falco Rules, Escape Replacements & Length-Bin Rebalance

#### 3.6.1 Every template whose `Expected Falco Rules` column was wrong

The `Expected Falco Rules` column may only name a rule that **can actually fire** under the deployed rule set (`lab/falco/falco-values.yaml`, four rules: `Interactive Shell Spawned in Non-Debug Container`, `Suspicious High Port Egress`, `Launch Sensitive Mount Container`, `Read Sensitive Host Information Untrusted`) and under the command the template actually executes. The Stage 4a Part 1 smoke proved that six rows violated this. All are corrected below.

| Template | Was expected | Why it could never fire | Corrected expectation | Status |
|:---|:---|:---|:---|:---|
| `TMPL-ESC-02` | Shell Spawn, Sensitive File Read | Reads `/proc/kcore` and `/proc/sys/kernel/hostname`; the rule condition is `fd.name in (/etc/shadow, /opt/runtimelens-dummy/etc/shadow) or (fd.name in (/etc/passwd, /opt/runtimelens-dummy/etc/passwd) and not proc.name in (...))`. Neither path is an identity file, so the rule cannot fire. | **Shell Spawn** | expectation corrected |
| `TMPL-ESC-05` | Shell Spawn, Sensitive File Read | Probed the cgroup **v1** `release_agent` file, which does not exist under Linux cgroup v2; no file was opened, so no rule fired. | **Shell Spawn** (template replaced, §3.6.2) | template replaced |
| `TMPL-ESC-06` | Shell Spawn, Sensitive Mount | `privileged: true` only — the pod has **no `hostPath` volume**, so no file descriptor can ever carry a mounted host path and `Launch Sensitive Mount Container` cannot fire. Verified in Stage 4a attempt 2: only `Interactive Shell Spawned in Non-Debug Container` fired. | **Shell Spawn** | expectation corrected |
| `TMPL-ESC-07` | Shell Spawn, Sensitive File Read | `readlink /proc/1/root` opens no identity file; the rule cannot fire. | **Shell Spawn** | expectation corrected |
| `TMPL-ESC-08` | Shell Spawn, Sensitive Mount | `privileged: true` only — **no `hostPath` volume**, so Sensitive Mount cannot fire. In addition `mknod` is rejected by the container runtime device cgroup even in a privileged pod, so the scenario produced no escape-relevant action at all. | **Shell Spawn** (template replaced, §3.6.2) | template replaced |
| `TMPL-ESC-10` | Shell Spawn, Sensitive Mount, Policy Warning | `privileged: true` only — no `hostPath` volume, so Sensitive Mount cannot fire. **`Policy Warning` is not a deployed Falco rule** in this project at all; it was never an observable. | **Shell Spawn, Sensitive Mount** (template replaced, §3.6.2) | template replaced |
| `TMPL-UNK-07` | Shell Spawn, Policy Warning | **`Policy Warning` is not a deployed Falco rule.** No rule with that name exists in `lab/falco/falco-values.yaml` or in the `falco-9.2.0` stock rule set used by this lab. | **Shell Spawn** | expectation corrected |

**Templates whose expectations were already correct and are now empirically confirmed:** `TMPL-ESC-01` (`/etc/shadow` read is unconditionally flagged), `TMPL-ESC-03` and `TMPL-ESC-04` (**both verified firing** in Stage 4a attempt 2 after the dummy-path prefix was added to the mount rule), `TMPL-ESC-09` (Sensitive Mount fires on the dummy path; Sensitive File Read fires on `/opt/runtimelens-dummy/etc/shadow`, which is why the four inert dummy files of §4 are required).

#### 3.6.2 The three escape templates replaced, and the escape budget

`TMPL-ESC-05`, `TMPL-ESC-08` and `TMPL-ESC-10` were replaced in place (same template IDs, same run counts) by safe, real, executable alternatives. **No template was added or removed, so the escape budget is unchanged at 10 templates / 80 runs / 58 dev / 22 test.**

| ID | Proposed real command (exact) | `proc.cmdline` length | Bin | Privileged | `hostPath` mount | Expected rules | Features 00/01/02 |
|:---|:---|--:|:---:|:---:|:---|:---|:---:|
| `TMPL-ESC-05` (replaces cgroup v1 `release_agent` traversal) | `cat /proc/self/cgroup; head -n 30 /proc/self/mountinfo; grep Cap /proc/self/status; ls -l /proc/self/fd 2>&1 \| head -n 10; cat /proc/self/mounts 2>&1 \| head -n 10` | 168 | 151–250+ | yes | none | Shell Spawn | F/F/**T** |
| `TMPL-ESC-08` (replaces `mknod` device-node attempt) | `ls -l /dev \| head -n 20; grep Cap /proc/self/status` | 57 | 30–80 | yes | none | Shell Spawn | F/F/**T** |
| `TMPL-ESC-10` (replaces the non-existent `Policy Warning` expectation) | `head -c 1 /opt/runtimelens-dummy/containerd.sock 2>&1 \|\| true; grep Cap /proc/self/status; nc -z -w 1 10.96.0.10 53 \|\| true` | 129 | 81–150 | yes | `/opt/runtimelens-dummy/containerd.sock` (File) | Shell Spawn, Sensitive Mount | **T**/F/**T** |

Rationale:
* `TMPL-ESC-05` keeps the original intent (cgroup-breakout reconnaissance) but uses cgroup **v2** paths that provably exist in the lab (`/proc/self/cgroup`, `/proc/self/mountinfo`, `/proc/self/mounts`), so the scenario really executes.
* `TMPL-ESC-08` keeps the original intent (host device surface exposure) but enumerates `/dev` read-only instead of calling `mknod`, which the container runtime device cgroup rejects even for a privileged pod. The enumeration is a genuine privilege-escape precursor and is completely safe.
* `TMPL-ESC-10` keeps the original intent (privileged capability enumeration) **and** restores a real `Sensitive Mount` expectation by adding a `hostPath` File mount of the third already-allowlisted dummy path `/opt/runtimelens-dummy/containerd.sock` (present in `ALLOWED_DUMMY_HOSTPATHS`, previously unused). This creates the only `T/F/T` feature combination in the class and restores a distinct telemetry signature.

**Feature-coverage check after the replacements** (plan §2 rule 5): feature 00 is `True` in 2 templates (`ESC-03`, `ESC-10`), feature 01 in 2 (`ESC-04`, `ESC-09`), feature 02 in 4 (`ESC-05`, `ESC-06`, `ESC-08`, `ESC-10`). The §1 rationale ("features 00, 01 and 02 each appear as `True` in at least two templates") still holds.

**Escape length-bin distribution after the replacements:** 3 in `30–80` (`ESC-01`, `ESC-02`, `ESC-08`), 5 in `81–150` (`ESC-03`, `ESC-04`, `ESC-06`, `ESC-07`, `ESC-10`), 2 in `151–250+` (`ESC-05`, `ESC-09`).

#### 3.6.3 Decision D-29 — the benign network-observation vocabulary

The per-run gate requires **all five** telemetry sources to carry at least one event. A scenario that opens no socket and resolves no name produces **zero** Hubble flows and therefore fails that gate even though nothing is wrong with the scenario. Decision D-29 keeps the gate **unchanged** and instead gives every purely local scenario exactly **one declared benign network observation**.

| Type | Observation (exact) | Length | Mechanism | Hubble flows observed in Part 1 | Credential |
|:--:|:---|--:|:---|--:|:---|
| **A** | `nslookup kubernetes.default.svc.cluster.local 2>&1 \|\| true` | 58 | DNS query to the cluster resolver | 3 | none |
| **B** | `nc -z -w 1 10.96.0.10 53 \|\| true` | 32 | TCP probe against the cluster DNS service | 7–8 | none |
| **C** | `wget -qO- --no-check-certificate https://10.96.0.1/api 2>&1 \|\| true` | 67 | HTTP(S) GET of the in-cluster API discovery document | 10 | none (world-readable) |
| **D** | `echo p \| nc -u -w 1 198.51.100.22 8080 \|\| true` | 57 | UDP datagram to the inert external test IP | 1–2 | none |

All four are in-cluster, read-only and carry no credential. Type C is **audit-neutral** for the collector: an unauthenticated request to the non-resource path `/api` is neither namespace-matching nor ServiceAccount-attributed, so it adds no audit event and does not change any template's expected audit verb set.

**Observation type per template (full 55-template registry).** The `Source` column states where the observation comes from: **observation \`X\`** means the template is purely local and *receives* a declared D-29 observation of that type; **own \`X\`** means the template's own scenario already provides that network activity, so no observation is appended; **own \`X\` + observation \`Y\`** means the scenario has its own activity of one type *and* carries a declared observation of a different type, so that the presence of either type is not a class marker.

| Class | Template | Type | Source |
|:---|:---|:--:|:---|
| `benign` | `TMPL-BEN-01` | B | own network activity |
| `benign` | `TMPL-BEN-02` | B | observation **B** |
| `benign` | `TMPL-BEN-03` | B | observation **B** |
| `benign` | `TMPL-BEN-04` | D | own network activity |
| `benign` | `TMPL-BEN-05` | D | own **D** |
| `benign` | `TMPL-BEN-06` | C | own network activity |
| `benign` | `TMPL-BEN-07` | D | own **D** |
| `benign` | `TMPL-BEN-08` | A | observation **A** |
| `benign` | `TMPL-BEN-09` | D | own **D** |
| `benign` | `TMPL-BEN-10` | D | observation **D** |
| `benign` | `TMPL-BEN-11` | C | own network activity |
| `benign` | `TMPL-BEN-12` | A | own **A** |
| `benign` | `TMPL-BEN-13` | D | own **D** |
| `benign` | `TMPL-BEN-14` | B | own network activity |
| `benign` | `TMPL-BEN-15` | B | observation **B** |
| `benign` | `TMPL-BEN-16` | C | own network activity |
| `benign` | `TMPL-BEN-17` | A | own network activity |
| `benign` | `TMPL-BEN-18` | C | own **C** |
| `benign` | `TMPL-BEN-19` | D | own **D** |
| `benign` | `TMPL-BEN-20` | D | own **D** |
| `benign` | `TMPL-BEN-21` | D | own **D** |
| `container_escape` | `TMPL-ESC-01` | A | observation **A** |
| `container_escape` | `TMPL-ESC-02` | C | observation **C** |
| `container_escape` | `TMPL-ESC-03` | B | own network activity |
| `container_escape` | `TMPL-ESC-04` | D | own network activity |
| `container_escape` | `TMPL-ESC-05` | A | own network activity |
| `container_escape` | `TMPL-ESC-06` | B | own network activity |
| `container_escape` | `TMPL-ESC-07` | B | observation **B** |
| `container_escape` | `TMPL-ESC-08` | B | own network activity |
| `container_escape` | `TMPL-ESC-09` | C | own network activity |
| `container_escape` | `TMPL-ESC-10` | B | own network activity |
| `privilege_abuse` | `TMPL-PRV-01` | B | own network activity |
| `privilege_abuse` | `TMPL-PRV-02` | C | own network activity |
| `privilege_abuse` | `TMPL-PRV-03` | B | own network activity |
| `privilege_abuse` | `TMPL-PRV-04` | C | own network activity |
| `privilege_abuse` | `TMPL-PRV-05` | C | own network activity |
| `privilege_abuse` | `TMPL-PRV-06` | A | observation **A** |
| `privilege_abuse` | `TMPL-PRV-07` | C | own network activity |
| `privilege_abuse` | `TMPL-PRV-08` | D | observation **D** |
| `cryptomining` | `TMPL-MNR-01` | A | own **D** + observation **A** |
| `cryptomining` | `TMPL-MNR-02` | A | own **D** + observation **A** |
| `cryptomining` | `TMPL-MNR-03` | D | own network activity |
| `cryptomining` | `TMPL-MNR-04` | D | own **D** |
| `cryptomining` | `TMPL-MNR-05` | A | own **D** + observation **A** |
| `cryptomining` | `TMPL-MNR-06` | D | own **D** |
| `cryptomining` | `TMPL-MNR-07` | A | own **A** |
| `cryptomining` | `TMPL-MNR-08` | D | own **D** |
| `unknown` | `TMPL-UNK-03` | D | own network activity |
| `unknown` | `TMPL-UNK-04` | B | observation **B** |
| `unknown` | `TMPL-UNK-05` | D | own **D** |
| `unknown` | `TMPL-UNK-07` | B | own **B** |
| `unknown` | `TMPL-UNK-R1` | C | own **C** |
| `unknown` | `TMPL-UNK-R2` | A | own network activity |
| `unknown` | `TMPL-UNK-R3` | D | own **D** |
| `unknown` | `TMPL-UNK-R4` | B | observation **B** |

**Per-class observation mix (the anti-confounder check).**

| Class | A | B | C | D | Templates |
|:---|--:|--:|--:|--:|--:|
| `benign` | 4 | 9 | 6 | 2 | 21 |
| `container_escape` | 3 | 4 | 2 | 1 | 10 |
| `privilege_abuse` | 2 | 1 | 7 | 0 | 8 |
| `unknown` | 3 | 4 | 1 | 1 | 8 |
| `cryptomining` | 0 | 0 | 0 | 8 | 8 |

**Why the `privilege_abuse` mix is not widened further inside Round 2.** All eight `privilege_abuse` templates already produce Hubble flows through their own API request (type C), so none of them is in the "predicted zero flows" set and none of them *needs* a D-29 observation. Two of them (`TMPL-PRV-06`, `TMPL-PRV-08`) do receive one so that the class carries the A / B / C mix. Adding an observation to the four Round 2 privilege templates was considered and **rejected**: their API request already yields 10–17 flows, and a second observation would push their total into the `HIGH` Hubble band (>= 12 flows) and concentrate the class's flow-count distribution, which is a *new* confound of exactly the kind D-28 was created to remove.

**Effect on the length bins.** Two Round 2 templates change bin because their command grew: `TMPL-ESC-08` moves from `30–80` to `81–150` (57 -> 91 characters) and `TMPL-UNK-R2` moves from `81–150` to `151–250+` (95 -> 155 characters). `TMPL-PRV-06` (180 -> 214) and `TMPL-PRV-08` (216 -> 276) stay in `151–250+`. The rebalanced table therefore becomes:

| Class | `30–80` | `81–150` | `151–250+` | Templates | Runs |
|:---|--:|--:|--:|--:|--:|
| `benign` | 5 | 6 | 10 | 21 | 140 |
| `container_escape` | 2 | 5 | 3 | 10 | 80 |
| `privilege_abuse` | 0 | 2 | 6 | 8 | 80 |
| `cryptomining` | 2 | 3 | 3 | 8 | 60 |
| `unknown` | 2 | 1 | 5 | 8 | 40 |
| **Total** | 11 | 18 | 26 | **55** | **400** |

*This table is the state after the Stage 4a Part 2 corrections; the Round 4 command-writing round superseded it — see §3.6.5.*

#### 3.6.4 Decision D-30 — Burst calibration against the cAdvisor collection cadence

**The measurement problem.** The kubelet's cAdvisor summary API returns the **last completed collection**, and the collection cadence in this cluster was measured directly at **~18–20 s**:

```text
t=  0.0s  rate=0.00m cum=34.400s     (controlled 6 s CPU burn started at t=0)
t=  8.3s  rate=0.00m cum=34.400s
t= 12.4s  rate=78.56m cum=35.749s   delta=1.3495  <-- first collection closing inside the burn
t= 20.6s  rate=78.56m cum=35.749s
t= 30.9s  rate=0.00m cum=35.749s    <-- next collection, after the burn
```

Consequences that are now part of the design, not of the gate:

1. A CPU burst **shorter than one collection interval can be entirely absent** from both the reported rate and the cumulative counter. `TMPL-BEN-14`'s 6-second loop was measured at **0.00 mcores** for exactly this reason.
2. The reported rate is the **average over the collection window that just closed**, not an instantaneous value.
3. The Decision D-26 band `[20, 150]` is therefore partly a measurement of the **collection phase**. This is the deeper explanation of the `25.77 m` versus `117.34 m` spread of the *identical* `TMPL-UNK-03` command across the two Part 1 attempts.
4. Every tenant workload has a **200 mcores** CPU limit, so an unthrottled burst that is long enough to be observed would report ~200 mcores — **above** the D-26 ceiling of 150. A `burst` template must therefore be **throttled** to land inside the band.

**The calibration anchor.** `TMPL-MNR-03` is the only `burst`-adjacent template with a *measured* rate: 875 iterations of `while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05` produced **89.69 / 100.58 mcores** (median / max) over a 54.58 s run — a throttled duty cycle well inside the D-26 band. The D-30 templates reuse that exact shape and scale only the **outer iteration count** to set the burn duration.

| Template | New command (loop part) | Burn | Reported rate (expected) | Window | Profile | Reason |
|:---|:---|--:|:---|--:|:---:|:---|
| `TMPL-BEN-14` | `for i in $(seq 480); do j=0; while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05; done` | ~30 s | ~90–100 m (MNR-03 anchor) | ~90 s | `burst` | A ~30 s burn outlasts the ~18–20 s collection interval, so a collection window closes inside it; the 90 s window keeps the burn a minority of the samples, so the median stays below 100 m. |
| `TMPL-BEN-16` | `for i in $(seq 8); do dd if=/dev/urandom of=/tmp/a.log bs=1M count=8 2>/dev/null; gzip -f /tmp/a.log; rm -f /tmp/a.log.gz; sleep 3; done` | ~36 s | ~65–70 m | ~90 s | `burst` | A single 12 MiB gzip lasts ~3 s and is invisible. Eight throttled cycles spread ~12 CPU-seconds over ~36 s, giving a duty cycle of ~33 % and a peak disk usage of 8 MiB. |
| `TMPL-BEN-17` | `cat /proc/loadavg; for i in $(seq 400); do j=0; while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05; done` | ~25 s | ~90 m (≈60 % of the 200 m limit) | ~90 s | `burst` | The previous nested loop (1500 × 4000 iterations) was a **20-hour** workload and was never executable. The single-level loop has a ~60 % duty cycle, keeping the reported peak below the 150 m ceiling. |
| `TMPL-PRV-07` | unchanged (five authenticated `wget` requests to the node proxy) | — | ~0 m | 20 s | **`low`** | The scenario is I/O bound: it waits for HTTPS responses and never burns CPU. Declaring it `burst` was simply wrong; the CPU profile is re-declared `low`. |
| `TMPL-UNK-R2` | `for i in $(seq 480); do j=0; while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05; done` | ~30 s | ~90–100 m (MNR-03 anchor) | ~90 s | `burst` | The previous 900-iteration loop produced ~14 s of CPU, right at the collection interval, and was not reliably observable. |

**No gate threshold was changed.** The Decision D-26 band (`peak` in `[20, 150]` mcores, `median < 100` mcores) and the Decision D-27 post-lag rule are untouched; what changed is the *scenario duration* so that the instrument can see the scenario, and the *duty cycle* so that the measurement lands inside the band that was already approved.

#### 3.6.5 Round 4 — the 32 never-run templates, their commands and the two class-level tables

The Round 4 command-writing round produced the commands of the 32 templates that had never been executed. The definitions live in `scripts/stage4a_round4.py`; the runner exposes them as `ROUND5_TEMPLATES` with the four batch selectors `5a`, `5b`, `5c`, `5d`. The per-template detail (exact command, measured `proc.cmdline` length, derived bin, CPU profile, Hubble band, expected rule set, feature triple, audit verbs, observation type) is tabulated in `docs/REPORT_DELTA.md` §13.3, and every registry row above was rewritten from the measured command.

**Nothing was executed in this round.** Every "expected" value below is a *prediction* from the plan and from the measured facts of the earlier rounds — in particular the Hubble bands (a type-D UDP datagram produced 1–2 flows in the Part 1 corpus, a type-B TCP probe 7–8, a type-C API read 10, a cross-tenant read 16–17) and the mining intensities (scaled from the measured `TMPL-MNR-03` anchor).

**Plan-vs-runner consistency check.** `scripts/check_plan_consistency.py` compares every registry row of this plan against the runner's template definition on seven fields — class, length bin, CPU profile, expected Falco rules, the feature triple, the audit verbs and the Hubble band — and reports `templates checked: 55 / mismatches: 0`.

**Table 1 — observation type per class (effective: the declared D-29 observation, or the template's own network activity).**

| Class | A (DNS) | B (TCP to cluster DNS) | C (API discovery) | D (UDP to inert IP) | Templates |
|:---|--:|--:|--:|--:|--:|
| `benign` | 3 | 5 | 4 | 9 | 21 |
| `container_escape` | 2 | 5 | 2 | 1 | 10 |
| `privilege_abuse` | 1 | 2 | 4 | 1 | 8 |
| `cryptomining` | 4 | 0 | 0 | 4 | 8 |
| `unknown` | 1 | 3 | 1 | 3 | 8 |

All four observation types appear in the `benign`, `container_escape` and `privilege_abuse` classes. The `cryptomining` class carries only A and D because a mining client resolves a pool name (A) and opens a pool connection (D) and does nothing else; the `unknown` class carries a single C, from `TMPL-UNK-R1`, whose ServiceAccount-authenticated pods read is the only API request among the unknown scenarios.

**Table 2 — expected Falco rule sets per class** (only rules that can really fire under the deployed rule set).

| Class | Expected rule set | Templates | Share | Flag |
|:---|:---|--:|--:|:---|
| `benign` | `Shell Spawn` | 15 | 71.4 % | **FLAGGED** |
| `benign` | `Shell Spawn` + `High Port Egress` | 6 | 28.6 % | |
| `container_escape` | `Shell Spawn` | 5 | 50.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive Mount` | 2 | 20.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive Mount` + `Sensitive File Read` | 2 | 20.0 % | |
| `container_escape` | `Shell Spawn` + `Sensitive File Read` | 1 | 10.0 % | |
| `privilege_abuse` | `Shell Spawn` | 8 | 100 % | **FLAGGED** |
| `cryptomining` | `Shell Spawn` + `High Port Egress` | 6 | 75.0 % | **FLAGGED** |
| `cryptomining` | `Shell Spawn` | 2 | 25.0 % | |
| `unknown` | `Shell Spawn` | 6 | 75.0 % | **FLAGGED** |
| `unknown` | `Shell Spawn` + `High Port Egress` | 2 | 25.0 % | |

**Four of the five classes are flagged.** This is the intended consequence of the design, not a defect: the Falco rule set is deliberately **not** class-discriminative, so a classifier cannot separate the classes from the rule set alone and must use the CPU band, the audit verbs, the Hubble band and the pod-spec features. The `benign` class is the weakest case (71.4 % of its templates fire the same single rule) and the `privilege_abuse` class is the strongest (100 %), which is consistent with a privilege attempt being a *low-CPU, API-mediated* activity that no Falco rule describes.

#### 3.6.6 Measured command lengths and the rebalanced bin table

All lengths below are the **measured** `proc.cmdline` length (`sh -c ` + command, i.e. `len(command) + 6`) of the exact command the template executes, computed from the command text. `TMPL-PRV-01` (219) and `TMPL-PRV-03` (207) were measured live in Stage 4a; the remainder are computed from the exact command strings.

| Template | Exact command (abbreviated) | Measured length | Bin |
|:---|:---|--:|:---:|
| `TMPL-PRV-01` | `nc -z -w 1 10.96.0.10 53 \|\| true; T=$(cat …/token); wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/namespaces/tenant-b/secrets` | **219** (live) | 151–250+ |
| `TMPL-PRV-02` | `wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-b/pods` | **88** (live) | 81–150 |
| `TMPL-PRV-03` | `nc -z -w 1 10.96.0.10 53 \|\| true; T=$(cat …/token); wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/serviceaccounts` | **207** (live) | 151–250+ |
| `TMPL-PRV-04` | `T=$(cat …/token);wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/namespaces/tenant-b/configmaps` | **187** | 151–250+ |
| `TMPL-PRV-05` | `T=$(cat …/token);wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api` | **153** | 151–250+ |
| `TMPL-PRV-06` | `T=$(cat …/token);wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/namespaces/tenant-c/pods/exec` | **186** | 151–250+ |
| `TMPL-PRV-07` | `T=$(cat …/token);for i in 1 2 3 4 5;do wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/nodes/runtimelens-control-plane/proxy/metrics;done` | **229** | 151–250+ |
| `TMPL-PRV-08` | `T=$(cat …/token);for n in tenant-a tenant-b tenant-c;do wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/namespaces/$n/secrets;done` | **222** | 151–250+ |
| `TMPL-BEN-06` | `T=$(cat …/token);wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api/v1/namespaces/tenant-b/pods` | **181** | 151–250+ |

**Physical constraint (proved, not assumed).** The audit collector (`PerRunTelemetryCapture.capture_k8s_audit_events`) captures an event only when (a) `objectRef.namespace` equals the workload's own namespace, (b) the requesting user is `system:serviceaccount:<ns>:*`, or (c) the request carries the workload pod name in the authentication extra. A **cross-tenant** request can therefore only be captured through (b) or (c), both of which require the ServiceAccount token. The token read costs 57 characters (`T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);`) and the authenticated `wget` invocation costs 69 characters (`wget -qO- --no-check-certificate --header="Authorization: Bearer $T" `), so the shortest *cross-tenant, audit-attributable* request is 57 + 69 + 48 = **174 characters** (`https://10.96.0.1/api/v1/namespaces/tenant-a/pods` is the shortest cross-tenant path), i.e. **180** as `proc.cmdline`. The `81–150` bin allows a command of at most 144 characters, of which 126 are consumed by the token read and the authenticated `wget` invocation, leaving **18 characters for the URL** — while the shortest URL that the API server actually answers is `https://10.96.0.1/api` (21 characters). **No ServiceAccount-authenticated request fits inside the `81–150` band.** Consequences:

* every `privilege_abuse` template that queries a **cross-tenant** resource is necessarily `151–250+`;
* the shortest ServiceAccount-authenticated request that is still audited at all is the API-discovery path `https://10.96.0.1/api` at 57 + 63 + 21 = **141 characters** (`147` including `sh -c `), i.e. it lands in `81–150`;
* the shortest unauthenticated request that is still captured (own-namespace collection `GET`) is `wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-b/pods` at **82 characters** (`88` including `sh -c `), i.e. `81–150`;
* **nothing** that produces a captured audit event fits inside `30–80`, because dropping `--no-check-certificate` makes the TLS handshake fail against the API server's self-signed certificate and the request is never issued.

**Rebalanced length-bin table (55 templates, 400 runs) after all Stage 4a Part 2 corrections:**

| Class | `30–80` | `81–150` | `151–250+` | Templates | Runs |
|:---|--:|--:|--:|--:|--:|
| `benign` | 8 | 5 | 8 | 21 | 140 |
| `container_escape` | 1 | 6 | 3 | 10 | 80 |
| `privilege_abuse` | **0** | **1** | 7 | 8 | 80 |
| `cryptomining` | **0** | 4 | 4 | 8 | 60 |
| `unknown` | 3 | 2 | 3 | 8 | 40 |
| **Total** | 12 | 18 | 25 | **55** | **400** |
**Why `privilege_abuse` and `cryptomining` cannot reach the `30–80` band.** Both classes carry a *structural* length floor that no honest command can go below: a ServiceAccount-authenticated request costs 126 characters before the URL (57 for the token read, 69 for the authenticated `wget`), and a **bounded** busy loop costs at least 50 characters (an unbounded `while :; do :; done` would never terminate the scenario). The `30–80` band therefore contains only the 12 benign, escape and unknown scenarios whose natural commands are short. Per Decision D-28 the raw command length is **not** a classifier feature, so the residual association is a documented confound rather than a live shortcut.


**Declared confound and compensating control.** The `30–80` band contains no `privilege_abuse` template at all, and six of the eight sit in the `151–250+` band. `command_length` was therefore a **declared confound** for this dataset, and Decision D-28 removes it from the classifier feature set entirely (18 features, not 19); it is retained only as a labelled diagnostic in `scripts/verify_dataset.py`. The following controls are mandatory:

1. **Length-bin coverage assertion in the dataset gate.** `scripts/verify_dataset.py` must report the per-class length-bin coverage of the collected runs and fail when a class occupies exactly one bin while another class is empty in that bin, unless the class is on the declared-confound list. (Implemented as an open item; it is not part of this offline change set.)
2. **Feature ablation in the evaluation plan.** `docs/EVALUATION_PLAN.md` must report macro-F1 with and without the `command_length` diagnostic so that the contribution of the length confound is explicit and cannot be silently absorbed into the headline number. The diagnostic value itself is never fed to a classifier.
3. **Both re-scoping options are now APPLIED as a proposed template-edit round** (Stage 4a Round 2). They change what the template *does*, so they are executed only inside the Round 2 review loop:
   * **`TMPL-PRV-02` → unauthenticated own-namespace pod enumeration.** Exact command: `wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-b/pods` — **88 characters** as `proc.cmdline`, bin `81–150`. No credential is presented, so the API server answers **403**; the request is still captured by the audit collector through the `objectRef.namespace == tenant-b` match, with the `list` verb on `pods`. The class meaning is preserved: this is a *credential-less* enumeration of a protected Kubernetes collection, which is a recognised privilege-abuse reconnaissance pattern. It is also the deliberate **credential-presence counterfactual** of `TMPL-BEN-06`, which performs the *same* own-namespace collection read **with** the ServiceAccount token (175 characters).
   * **`TMPL-PRV-05` → ServiceAccount-authenticated API discovery.** Exact command: `T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);wget -qO- --no-check-certificate --header="Authorization: Bearer $T" https://10.96.0.1/api` — **153 characters** as `proc.cmdline`, bin `151–250+`. The request is authenticated with the pod's own ServiceAccount, so the audit record is attributed to `system:serviceaccount:tenant-b:default`. The Kubernetes discovery document is readable by any authenticated identity, so the response is **200 rather than 403**; the class signal is the *equivalent audit record* branch — a workload enumerating the served API paths with its own identity, which is the reconnaissance step of a privilege-escalation chain. **This template was originally specified at 148 characters in the `81–150` bin; that figure was wrong**, because it was derived from the `-H` header option that BusyBox `wget` rejects. With the working `--header=` form the command is 153 characters and the `81–150` band is provably unreachable for any ServiceAccount-authenticated request (see the physical constraint above).

   Applying both gives `privilege_abuse` a **0 / 2 / 6** distribution, moving it one band closer to the 2 / 3 / 3 target and leaving only the `30–80` band unrepresented, which is physically unreachable for this class as proven above.

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
