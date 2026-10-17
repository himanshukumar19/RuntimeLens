# LAB SCENARIO SPECIFICATION & PAIRED COUNTERFACTUAL CATALOG

## 1. Safety, Simulation Principles & Data Origin
The RuntimeLens dataset is collected from **live scenario executions inside an isolated Kubernetes laboratory cluster**.
1. **Live Cluster Capture Across All Five Telemetry Sources:**
   - Events are not produced by a synthetic mock generator; they are captured from live running pods.
   - **Unified Five-Source Raw Capture from Run 1:** Raw telemetry collectors for all five sources—Falco eBPF syscalls, Kubernetes API audit logs, Cilium/Hubble network flows, Prometheus cAdvisor resource metrics, and Trivy image vulnerability reports—are active and archiving unmanipulated raw data from the very first dataset run.
   - Normalizers for Hubble, Prometheus, and Trivy may be staged in later pipeline phases, but the raw multi-source dataset is fully captured during scenario execution so that **the 400-run dataset never needs to be regenerated**.
2. **Pilot Execution & Design Freeze:**
   - Before executing the full 400-run corpus, a **pilot of 20–30 runs** is executed.
   - The pilot verifies the operational health and completeness of all five raw capture collectors, confirms zero telemetry loss, and provides empirical variance data.
   - Following successful review of the pilot data, **the scenario implementations, seed sequences, and raw capture design are permanently frozen**.
3. **Controlled, Benign-Intent Simulation:** Scenarios simulate security indicators without weaponized exploitation:
   - No real kernel rootkits, memory corruptions, or breakout exploits.
   - Container escape tests mount synthetic dummy files (e.g. an empty file named `/var/run/docker.sock` in a test volume), never the real host Docker/containerd socket.
   - Cryptomining tests connect to an in-cluster mock HTTP echo service, never public mining pools or external wallet endpoints.
   - Privilege abuse tests manipulate narrowly scoped test Roles, never `cluster-admin`.
4. **Disclosure Wording:** All publications, reports, and posters must explicitly disclose:
   > *"The evaluation dataset was generated through live executions in an isolated, multi-tenant Kubernetes laboratory cluster running controlled, benign-intent attack simulations. No live malware, weaponized exploits, or external mining pools were deployed. Results reflect lab conditions and may not directly generalize to production enterprise clusters."*
5. **Incident Definition:**
   - An incident is strictly defined by the **scenario execution run (`run_id`)**. All events emitted during a single scenario run correspond to that run's incident.
   - The $\pm 30$s temporal sliding window is used *only* for correlating and joining multi-source events into canonical incident records, not for segmenting or defining incidents.

---

## 2. Threat Class Scenario Catalog

| ID | Class | Scenario Intent | Simulated Indicator | Expected Telemetry & Verified Rules |
|:---|:---|:---|:---|:---|
| **SC-ESC-01** | `container_escape` | Dummy runtime socket access | Pod spec with dummy `/var/run/docker.sock` mount; container executes `cat /var/run/docker.sock` | Falco: `Launch Sensitive Mount Container` / `Read sensitive file untrusted`; fact: `host_runtime_socket_mounted=True` |
| **SC-ESC-02** | `container_escape` | Sensitive host filesystem probe | Pod runs `cat /etc/shadow` or probes host paths from unprivileged container | Falco: `Read sensitive file untrusted`; fact: `sensitive_host_path_mounted=True` |
| **SC-ESC-03** | `container_escape` | Simulated namespace breakout | Mock binary invokes `setns` system call / namespace traversal | Falco: `Change thread namespace`; unexpected syscall alert |
| **SC-PRV-01** | `privilege_abuse` | Unauthorized Secret exfiltration | Test ServiceAccount attempts `kubectl get secrets -n tenant-b` from `tenant-a` | K8s Audit log: verb `get`, resource `secrets`, `403 Forbidden` or unauthorized `200` |
| **SC-PRV-02** | `privilege_abuse` | RBAC privilege escalation | ServiceAccount attempts to bind test role to `ClusterRole` | K8s Audit log: verb `create`, resource `rolebindings` |
| **SC-PRV-03** | `privilege_abuse` | Cross-pod remote execution | ServiceAccount invokes `pods/exec` into adjacent tenant pod | K8s Audit log: subresource `pods/exec`, user/tenant mismatch |
| **SC-MNR-01** | `cryptomining` | Sustained CPU spike + egress | Benchmarking load generator (`stress-ng`) drives container CPU $\ge 3\times$ baseline envelope + opens egress flow to mock port 3333 | Prometheus CPU spike relative to baseline; Hubble egress verdict `FORWARDED` to mock endpoint; requires $\ge 2$ corroborating signals |
| **SC-MNR-02** | `cryptomining` | Volatile path binary execution | Script copies mock compute binary to `/tmp/xmrig_mock` and executes compute loop | Falco execution from `/tmp`; sustained relative CPU anomaly; requires $\ge 2$ corroborating signals |
| **SC-UNK-01** | `unknown` | Sensor drop / missing audit | Execute workload shell spawn while K8s Audit collector is intentionally halted | Telemetry health flags `missing_sources: ["k8s_audit"]`, `telemetry_degraded=True` |
| **SC-UNK-02** | `unknown` | Kernel eBPF buffer overflow | High-frequency syscall burst drops Falco buffer events under artificial stress | Falco health check reports dropped events; `telemetry_degraded=True` (pure design-based drop, no semantic conflicts) |
| **SC-BEN-01** | `benign` | Deployment rolling restart | `kubectl rollout restart deployment/web -n tenant-a` | K8s Audit pod lifecycle events; standard container startup |
| **SC-BEN-02** | `benign` | Routine admin debug session | Authorized operator runs `kubectl exec -it debug-pod -- /bin/sh` in `tenant-a` | Audit log with authorized user; workload baseline specifies `shell_allowed: true` |
| **SC-BEN-03** | `benign` | High load legitimate batch run | Database executes scheduled indexing job causing CPU spike | Prometheus CPU spike within authorized batch baseline window; Hubble confirms internal cluster peers only |
| **SC-BEN-04** | `benign` | Container health probe failure | Workload triggers liveness probe failure and automatic kubelet restart | Routine kubelet events, zero attack indicators |
| **SC-BEN-05** | `benign` | Legitimate service flow on port 3333 | Analytics worker transmits telemetry to internal cluster peer on port 3333 | Hubble captures port 3333 flow matching `expected_peers`; CPU within normal baseline; proves port 3333 is not a mining shortcut |

---

## 3. The Three Paired Counterfactual Families
The core scientific claim requires isolating the causal effect of the baseline context.

### Family A: Interactive Shell Execution
- **Pair 1 (Attack):** Shell spawned in `payment-service` (`tenant-a`).
  - Baseline: `shell_allowed: false`.
  - Facts: `is_shell_process: true`.
  - Ground Truth: `container_escape` indicator (or `privilege_abuse`).
- **Pair 2 (Benign Counterfactual):** Shell spawned in `maintenance-pod` (`tenant-a`).
  - Baseline: `shell_allowed: true`.
  - Facts: `is_shell_process: true`.
  - Ground Truth: `benign`.

### Family B: Abnormal CPU Utilization & Paired Port Traffic
- **Pair 1 (Attack - Cryptomining):** Sustained CPU consumption $\ge 3\times$ baseline envelope in `web` reverse proxy coupled with unauthorized egress flow to internal mock port 3333.
  - Baseline: Expected CPU $\le 25$m; external/non-standard egress prohibited; `expected_peers` excludes mock port.
  - Facts: Relative CPU anomaly detected ($\ge 3\times$ baseline), unauthorized egress flow detected.
  - Ground Truth: `cryptomining` (satisfies $\ge 2$ required signals).
- **Pair 2 (Benign Counterfactual - Legitimate Port 3333 Flow):** Benign telemetry worker connects to internal analytics service on port 3333 while CPU remains within baseline envelope.
  - Baseline: Port 3333 listed in `expected_peers`; CPU rate conforms to baseline.
  - Facts: CPU normal, network flow authorized in baseline.
  - Ground Truth: `benign` (proves model does not trigger on port 3333 alone).
- **Pair 3 (Benign Counterfactual - Scheduled Compute Spike):** 90% CPU consumption in `database` during scheduled nightly compaction with only internal database peers.
  - Baseline: Expected CPU spike allowed during batch hours; external egress prohibited.
  - Facts: Relative CPU within scheduled batch baseline window, network flows strictly internal.
  - Ground Truth: `benign`.

### Family C: Orchestration Secret Access
- **Pair 1 (Attack):** `web` ServiceAccount requests `GET /api/v1/namespaces/tenant-b/secrets`.
  - Baseline: Permitted secret access is strictly `tenant-a/web-tls-cert`.
  - Facts: Cross-tenant secret access attempt.
  - Ground Truth: `privilege_abuse`.
- **Pair 2 (Benign Counterfactual):** `api` ServiceAccount requests `GET /api/v1/namespaces/tenant-a/secrets/database-creds`.
  - Baseline: Authorized secret access explicitly listed.
  - Facts: In-namespace authorized secret read.
  - Ground Truth: `benign`.

---

## 4. Run Count Matrix & Statistical Power Plan

### 4.1 Live Cluster Run Allocation

| Category | Independent Runs Target | Estimated Test Split Runs (~28%) | Estimated Dev Split Runs (~72%) | Estimated Incidents (1 per run) |
|:---|:---:|:---:|:---:|:---:|
| `container_escape` | 60 runs | **17 runs** | 43 runs | 60 incidents |
| `privilege_abuse` | 60 runs | **17 runs** | 43 runs | 60 incidents |
| `cryptomining` | 60 runs | **17 runs** | 43 runs | 60 incidents |
| `unknown` / Degraded Telemetry | 40 runs | **11 runs** | 29 runs | 40 incidents |
| `benign` (rollouts, probes, batch, admin, port pairs) | 180 runs | **50 runs** | 130 runs | 180 incidents |
| **Total Live Cluster Runs** | **400 runs** | **112 runs** | **288 runs** | **400 incidents** |

### 4.2 Statistical Power & CI Width Estimation via Pilot
- Rather than asserting an unverified a priori confidence interval width or power, **statistical power and 95% bootstrap CI width will be estimated empirically by simulation and cluster bootstrap on the 20–30 run pilot dataset**.
- **Paired Primary Hypothesis:** The primary hypothesis ($H_1$) strictly evaluates a **paired comparison** between identical runs evaluated with baseline context vs without baseline context ($\Delta\text{Macro-F1} = \text{Macro-F1}_{\text{baseline}} - \text{Macro-F1}_{\text{no-baseline}}$).
- **Minimum Meaningful Effect Size:** The target minimum effect size will be finalized and calibrated after analyzing the pilot data variance.
- **Exploratory Fallback:** If pilot bootstrap simulations indicate that statistical power is insufficient ($<0.80$) to detect the calibrated effect size within the 400-run budget, the primary research claim will be **explicitly designated as exploratory** rather than confirmatory, and all results will be reported with wide CIs and full methodological transparency.
- **Split Grouping:** All events sharing a `run_id` remain strictly partitioned together into either the Dev set or the Held-out Test set.

---

## 5. Run-Time & Resource Budget (400 Runs)

### 5.1 Execution Time Budget
- **Per-Run Elapsed Time:** ~45–60 seconds per scenario execution:
  - 15s: Pod deployment, scheduling, and container readiness probe.
  - 15s: Workload steady-state observation and baseline activity.
  - 15s: Scenario trigger execution (simulated indicator).
  - 10s: Telemetry drain, buffer flush, and raw capture persistence across all 5 collectors.
  - 5s: Automated teardown and namespace verification.
- **400 Runs Wall-Clock Time:** $400 \times 55\text{s} \approx 6.1$ hours of active cluster execution.
- **Pilot (20–30 runs):** $\approx 25$–$30$ minutes.
- **Total Operational Budget:** **8–10 hours wall-clock time**, accommodating batch pauses, verification checkpoints, and lab resets.

### 5.2 VM Memory & Disk Budget
- **Host VM Allocation:** 4 vCPUs, 6–8 GB RAM, 40 GB virtual disk (Ubuntu 24.04 on Apple Silicon).
- **Memory Budget:**
  - `kind` control plane + Cilium CNI + Falco eBPF daemon + tenant workloads: ~3.8 GB steady-state RAM.
  - Free memory buffer: 2.2–4.2 GB headroom.
  - **Memory Guard:** The scenario orchestrator monitors host VM memory before each batch; if available memory falls below 1.2 GB, execution pauses and triggers a cluster garbage collection / reset.
- **Disk Budget:**
  - Base OS and kind container image cache: $\approx 10$ GB.
  - Raw JSONL telemetry across all 5 collectors for 400 runs: $\approx 500$ MB – $1.2$ GB total.
  - **Disk Guard:** The runner aborts if free disk space falls below 5.0 GB.

### 5.3 Batching, Resumability & Automatic Cleanup
- **Batched Execution:** Runs are scheduled in manageable batches of 25–50 runs.
- **Resumable State Manifest:** Scenario orchestrator maintains an append-only checkpoint file (`data/scenarios/run_checkpoint.json`). If interrupted by VM restart or power loss, execution automatically resumes from the last uncompleted `run_id`.
- **Automated Teardown Hook:** Every scenario execution executes within a guaranteed `try ... finally` lifecycle block:
  - Deletes temporary scenario pods and ephemeral secrets.
  - Restores modified workload configurations.
  - Flushes and syncs raw collector JSONL files to disk.
  - Runs `kubectl get pods -A` sanity check to guarantee zero orphaned resources before the next run begins.
