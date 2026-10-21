# Scenario Safety Sheet: Ticket 06a Live Cluster Pilot Runs (Checkpoint D1)

> **Document Status:** REVISED POST-REVIEW (Pending Final Authorization Queue Item `A-002`)
> **Safety Governance:** `AGENTS.md` Hard Operating Rules & Checkpoint D1 Protocol
> **Execution Scope:** 25 live cluster pilot runs across 5 threat classes and 3 paired counterfactual families.
> **Hard Invariants:** Zero weaponized exploits, zero live host daemon access (inert dummy files only), zero external mining pools (in-cluster mock sink only), namespaced RBAC with zero delete verbs, pre-flight and post-flight idempotent cleanup with interrupt traps, neutral anti-leakage naming, and strict resource bounds ($\le 85\%$ RAM, $\le 80\%$ disk).

---

## 1. Safety Architecture & Safeguards

### 1.1 Cluster Boundary & Isolation Guards
- **Kubernetes Context Guard:** Every scenario script executes `make check-kube-context` to assert `kubectl config current-context == kind-runtimelens`. Execution immediately aborts if any other context is active.
- **Strictly Scoped Namespaces:** All workload activity is confined to `tenant-a`, `tenant-b`, and `tenant-c`. No modifications are permitted in `kube-system`, `cilium`, or `local-path-storage`.
- **Network Isolation:** Pre-installed default-deny NetworkPolicies prevent cross-tenant lateral movement and block all outbound egress to external networks.
- **Dry-Run Containment:** All automated responses operate in dry-run mode (`dry_run=True`), logging planned quarantine actions to the tamper-evident audit record without terminating pods.

### 1.2 Socket & Filesystem Virtualization Guard (Option A Specification)
- **The Extractor Requirement:** `extract_pod_spec_facts()` in `src/runtimelens/normalizer/falco.py` inspects `volumes[].hostPath.path` against `HOST_RUNTIME_SOCKET_PATTERNS` (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) to compute `host_runtime_socket_mounted: true`. If a test pod mounts an empty file via `ConfigMap`, `extract_pod_spec_facts()` evaluates `has_sock = False` because the volume type is `configMap`, not `hostPath`.
- **The Dedicated Dummy Node Directory & Extractor Rule (Option A Refined):**
  - **Symlink Discovery on Node:** Inspection of the kind node container (`runtimelens-control-plane`) reveals that `/var/run` is an active symlink pointing directly to `/run` (`/var/run -> /run`). Creating any dummy file under `/var/run` or `/run` would place files in the live operating system run directory where containerd and system services operate. Therefore, **no files are ever created in `/var/run` or `/run` on the node**.
  - **Dedicated Dummy Directory on Node:** An inert dummy directory is created at `/opt/runtimelens-dummy/` containing an empty 0-byte regular file and dummy etc directory:
    ```bash
    docker exec runtimelens-control-plane mkdir -p /opt/runtimelens-dummy
    docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/docker.sock
    docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/docker.sock
    docker exec runtimelens-control-plane mkdir -p /opt/runtimelens-dummy/etc
    docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/etc/shadow
    docker exec runtimelens-control-plane chmod 0640 /opt/runtimelens-dummy/etc/shadow
    ```
  - **Dedicated Ephemeral Lab Namespace:** Because Kubernetes Pod Security Standards enforce `baseline` in `tenant-a`, `tenant-b`, and `tenant-c` (which strictly forbids `hostPath` volumes), the simulated escape pod executes strictly inside an ephemeral lab namespace (`sandbox-workloads`) configured with `pod-security.kubernetes.io/enforce: privileged`. The namespace is created only for the run and deleted immediately after.
  - **The Extractor Rule:** `extract_pod_spec_facts()` in `src/runtimelens/normalizer/falco.py` explicitly recognizes `SIMULATED_RUNTIME_SOCKET_PATTERNS = ("/opt/runtimelens-dummy/docker.sock", "/opt/runtimelens-dummy/containerd.sock")` in addition to real socket paths.
  - The test pod mounts this path using a standard Kubernetes `hostPath` volume:
    ```yaml
    volumes:
    - name: system-socket-link
      hostPath:
        path: /opt/runtimelens-dummy/docker.sock
        type: File
    ```
  - **Verified Security Properties:**
    1. `extract_pod_spec_facts()` inspects `hostPath.path == "/opt/runtimelens-dummy/docker.sock"`, which matches `SIMULATED_RUNTIME_SOCKET_PATTERNS` and sets `host_runtime_socket_mounted: true`.
    2. The container accesses a 0-byte regular file in an isolated `/opt` subdirectory with zero connection to the node's containerd socket or Docker daemon.
    3. The PSS baseline of tenant namespaces remains completely uncompromised.

### 1.3 Anti-Leakage Resource Naming Guardrail
- **No Class Leakage:** Resource names, pod names, service accounts, and labels must **never** leak the scenario ground truth or threat class. Names containing `escape`, `privilege`, `mining`, `attack`, `benign`, `exploit`, or abbreviations (e.g. `esc`, `prv`, `mnr`) are strictly forbidden in manifests.
- **Production-Style Workload Names:**
  - Pods use neutral operational patterns: `worker-task-*`, `service-agent-*`, `sync-runner-*`, `cache-proxy-*`.
  - In-cluster services use neutral names: `sync-collector:3333` (never `mock-mining-sink`).
  - Roles and bindings use standard operational names: `task-reader-role`, `sync-binding`.
- **Neutral Labels:** Only standard operational metadata is applied:
  ```yaml
  labels:
    app: worker
    component: task
    runtimelens.test: "true"
    runtimelens.run_id: "run-001"
  ```

### 1.4 Cryptomining Simulation Guard & Prometheus Scrape Alignment
- **Duration Alignment (`docs/LABELING_GUIDE.md`):** To satisfy the ground-truth requirement for `cryptomining` ("Sustained container CPU rate exceeding the workload baseline envelope by $\ge 3\times$ or sustained $>80\%$ of container CPU quota"), the mining simulation executes for a **sustained duration of 2 minutes (120 seconds)** for at least 2 to 3 pilot runs (and 15–30s for shorter smoke runs).
- **Prometheus Scrape Interval:** cAdvisor and Prometheus scrape metrics at a **10-second interval**. A 120-second run provides 8–12 consecutive scrape data points, guaranteeing sufficient time-series resolution to detect a sustained relative anomaly rather than a transient burst.
- **Container Limit Bounds:** The container specification enforces:
  ```yaml
  resources:
    limits:
      cpu: "500m"
      memory: "256Mi"
  ```
  This bounds CPU load mathematically to $\le 0.5$ vCPU on the 4-vCPU VM, preventing node starvation.
- **Mock Sink:** Outbound traffic connects to an in-cluster HTTP echo service (`sync-collector:3333` in namespace `tenant-a`). Default-deny NetworkPolicy blocks any egress beyond cluster boundaries.

### 1.5 Execution Location & Data Storage
- **Runner Execution Environment:** The scenario runner executes **strictly inside the VM (`runtimelens-vm`)** directly communicating with the kind cluster and persisting raw captures to `/home/ubuntu/RuntimeLens/data/raw/`.
- **Git Ignore Confirmation:** `data/raw/` is explicitly git-ignored in `.gitignore` (line 15). Raw packet captures and stream logs are never staged or committed.

### 1.6 Idempotent Cleanup & Interruption Resilience
- **Pre-Flight Sweep (Start of Every Run):** Before any pod or resource is created, the runner executes a label-based cleanup sweep:
  ```bash
  kubectl delete pods,jobs,roles,rolebindings,deployments,services -n tenant-a -l runtimelens.test=true --ignore-not-found=true --timeout=30s
  ```
  The runner verifies zero orphaned test resources exist before scheduling the new run:
  ```bash
  test $(kubectl get pods -A -l runtimelens.test=true --no-headers | wc -l) -eq 0
  ```
- **Post-Flight Trap Handler:** Every scenario script wraps execution in a guaranteed Bash trap / Python `try...finally` block:
  ```bash
  trap 'cleanup_scenario "$RUN_ID"' EXIT INT TERM HUP
  ```
- **Idempotency Proof:** `cleanup_scenario` executes `kubectl delete --ignore-not-found=true` for all resources tagged `runtimelens.run_id=${RUN_ID}`. Running it repeatedly or after a hard interruption exits with code `0`.

---

## 2. Resource Budgets & Auto-Stop Thresholds

| Metric | Normal Operating Baseline | Pilot Peak Envelope (25 runs) | Safety Auto-Stop Threshold | Action on Breach |
|:---|:---:|:---:|:---:|:---|
| **VM RAM** | 1.3 GiB (22%) | 2.5 GiB (43%) | **$\ge 85\%$ (4.93 GiB)** | Immediate SIGTERM to runner; cluster reset |
| **VM Disk (`/dev/sda1`)** | 7.0 GiB (19%) | 8.5 GiB (22%) | **$\ge 80\%$ (30.4 GiB)** | Immediate abort; purge temporary captures |
| **Per-Run Elapsed Time** | 35–45s (normal) / 135s (2m mining) | 150s | **$> 180$ seconds** | Timeout killer kills scenario container; cleanup |
| **Total Pilot Duration** | — | 30–35 minutes | **$> 60$ minutes** | Pause execution for human review |
| **Cluster Health** | All nodes/pods Ready | All nodes/pods Ready | **Cluster degraded twice** | Halt runner; queue entry in `APPROVAL_QUEUE.md` |

### Snapshot State & Rollback Protection
- **Pre-Pilot Baseline Snapshot:** `snap-s4` (captured on stopped VM on 2026-10-18 post-S4).
- **Rollback Target:** If any cluster corruption or unrecoverable state occurs, rollback to **`snap-s4`** is executed via `multipass restore runtimelens-vm.snap-s4`.
- **What a Restore Would Lose:**
  - Restoring `snap-s4` preserves all Segment S4 deliverables (dual audit logging, webhook receiver, TLS certs, correlation window, baselines, 5-source raw capture archiver, rotated Falco token).
  - A restore would lose only the ephemeral pilot run captures (`data/raw/` pilot entries) and per-run benchmark logs (`data/scenarios/pilot_metrics.json`) recorded after `snap-s4` was taken.

---

## 3. Pilot 25-Run Stratified Class & Paired Family Mix (Ticket 06a)

All 25 pilot runs are tagged `is_pilot: true, split_phase: "pilot"` and are **strictly excluded from the 28% held-out test split**.

| Threat Class | Pilot Runs | Scenarios Included | Paired Family Mapping | Specific Test Conditions & Durations |
|:---|:---:|:---|:---|:---|
| `container_escape` | 4 | SC-ESC-01 (2), SC-ESC-02 (1), SC-ESC-03 (1) | Family A (Attack counterpart) | SC-ESC-01 mounts inert dummy `/var/run/docker.sock` via `hostPath` |
| `privilege_abuse` | 4 | SC-PRV-01 (2), SC-PRV-02 (1), SC-PRV-03 (1) | Family C (Attack counterpart) | SC-PRV-01 attempts cross-tenant secret exfiltration |
| `cryptomining` | 4 | SC-MNR-01 (3), SC-MNR-02 (1) | Family B (Attack counterpart) | 3 runs execute **sustained 2-minute CPU load** to span 8–12 Prometheus scrape windows |
| `unknown` | 3 | SC-UNK-01 (2), SC-UNK-02 (1) | Unpaired (Telemetry health) | Sensor receiver halted or syscall burst drops |
| `benign` | 10 | SC-BEN-01 (2), SC-BEN-02 (2), SC-BEN-03 (2), SC-BEN-04 (2), SC-BEN-05 (2) | Family A (Pair 2: debug pod), Family B (Pair 2: port 3333 flow, Pair 3: db compaction), Family C (Pair 2: authorized secret) | Routine rollouts, authorized maintenance shell, legitimate port 3333 analytics traffic |
| **Total Pilot Runs** | **25** | **14 unique scenarios** | **All 3 Paired Families Represented** | **Resource baselines measured** |

---

## 4. Detailed Scenario Manifest for Pilot Runs

### 4.1 Threat Class: Container Escape (`container_escape`)

#### SC-ESC-01: Simulated Runtime Socket Access (Option A Refined)
- **Namespaces & Workloads:** `sandbox-workloads` (dedicated ephemeral lab namespace with PSS privileged), pod `worker-task-7f9a`.
- **RBAC Created:** Default unprivileged ServiceAccount.
- **Dummy Socket Mount:** Node dummy regular file `/opt/runtimelens-dummy/docker.sock` mounted via `hostPath`.
- **Exact Command:**
  ```bash
  # Pre-run: create ephemeral lab namespace with privileged PSS
  kubectl create namespace sandbox-workloads --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace sandbox-workloads pod-security.kubernetes.io/enforce=privileged --overwrite

  kubectl run worker-task-7f9a -n sandbox-workloads --restart=Never \
    --image=docker.io/library/alpine:3.19 --labels="app=worker,component=task,runtimelens.test=true,runtimelens.run_id=${RUN_ID}" \
    --overrides='{
      "apiVersion": "v1",
      "spec": {
        "containers": [{
          "name": "worker",
          "image": "docker.io/library/alpine:3.19",
          "command": ["/bin/sh", "-c", "ls -l /opt/runtimelens-dummy/docker.sock && head -n 1 /opt/runtimelens-dummy/docker.sock || true; sleep 5"],
          "volumeMounts": [{"name": "system-socket-link", "mountPath": "/opt/runtimelens-dummy/docker.sock"}],
          "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}}
        }],
        "volumes": [{"name": "system-socket-link", "hostPath": {"path": "/opt/runtimelens-dummy/docker.sock", "type": "File"}}]
      }
    }'
  ```
- **Cleanup:**
  ```bash
  kubectl delete pod worker-task-7f9a -n sandbox-workloads --ignore-not-found=true
  kubectl delete namespace sandbox-workloads --ignore-not-found=true
  ```

#### SC-ESC-02: Sensitive Host Filesystem Probe
- **Namespaces & Workloads:** `tenant-a`, workload `web-6794787bc8-5pnzg`.
- **RBAC Created:** None.
- **Exact Command:**
  ```bash
  POD=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a "$POD" -- /bin/sh -c "cat /etc/shadow 2>&1 || true"
  ```
- **Cleanup:** Ephemeral exec command terminates automatically.

#### SC-ESC-03: Simulated Namespace Breakout (`setns` probe)
- **Namespaces & Workloads:** `tenant-a`, pod `worker-task-8b2c`.
- **Exact Command:**
  ```bash
  kubectl run worker-task-8b2c -n tenant-a --restart=Never \
    --image=docker.io/library/alpine:3.19 --labels="app=worker,component=task,runtimelens.test=true,runtimelens.run_id=${RUN_ID}" \
    -- /bin/sh -c "unshare -m -p -f /bin/sh -c 'echo test_probe' || true; sleep 5"
  ```
- **Cleanup:** `kubectl delete pod worker-task-8b2c -n tenant-a --ignore-not-found=true`

---

### 4.2 Threat Class: Privilege Abuse (`privilege_abuse`)

#### SC-PRV-01: Cross-Tenant Secret Exfiltration Attempt
- **Namespaces & Workloads:** `tenant-a`, workload `api-74cdd4cdbc-cwd6k`.
- **Exact Command:**
  ```bash
  POD=$(kubectl get pod -n tenant-a -l app=api -o jsonpath='{.items[0].metadata.name}')
  TOKEN=$(kubectl exec -n tenant-a "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/tenant-b/secrets
  ```
- **Cleanup:** Ephemeral execution terminates; zero residual artifacts.

#### SC-PRV-02: RBAC RoleBinding Manipulation
- **Namespaces & Workloads:** `tenant-a`, service account `task-runner-sa`.
- **RBAC Created:** Role `task-reader-role` inside `tenant-a` only.
- **Exact Command:**
  ```bash
  kubectl create role task-reader-role --verb=get,list --resource=deployments -n tenant-a --dry-run=client -o yaml | kubectl apply -f -
  kubectl create rolebinding sync-binding --role=task-reader-role --serviceaccount=tenant-a:task-runner-sa -n tenant-a || true
  ```
- **Cleanup:**
  ```bash
  kubectl delete rolebinding sync-binding -n tenant-a --ignore-not-found=true
  kubectl delete role task-reader-role -n tenant-a --ignore-not-found=true
  ```

#### SC-PRV-03: Cross-Pod Remote Execution Probe
- **Namespaces & Workloads:** `tenant-a` workload targeting `tenant-b` pod.
- **Exact Command:**
  ```bash
  POD_B=$(kubectl get pod -n tenant-b -l app=web -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a deployment/api -- curl -s -k https://kubernetes.default.svc/api/v1/namespaces/tenant-b/pods/$POD_B/exec || true
  ```
- **Cleanup:** Ephemeral curl terminates automatically.

---

### 4.3 Threat Class: Cryptomining (`cryptomining`)

#### SC-MNR-01: Sustained CPU Spike + Mock Egress
- **Namespaces & Workloads:** `tenant-a`, workload `web-6794787bc8-5pnzg`.
- **Duration & Scrape Alignment:** **120 seconds** (2 minutes sustained load across 12 Prometheus scrape points).
- **Destination:** In-cluster receiver `sync-collector:3333` in `tenant-a`.
- **Exact Command:**
  ```bash
  POD=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a "$POD" -- /bin/sh -c "nc -w 3 sync-collector 3333 || true; stress-ng --cpu 1 --cpu-load 50% --timeout 120s || true"
  ```
- **Cleanup:** `kubectl delete deployment sync-collector service sync-collector -n tenant-a --ignore-not-found=true`

#### SC-MNR-02: Volatile Path Mock Binary Execution
- **Namespaces & Workloads:** `tenant-a`, workload `database-8cfcc9779-r45hj`.
- **Exact Command:**
  ```bash
  POD=$(kubectl get pod -n tenant-a -l app=database -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a "$POD" -- /bin/sh -c "cp /bin/busybox /tmp/sync_task && /tmp/sync_task sleep 10 && rm -f /tmp/sync_task"
  ```
- **Cleanup:** `kubectl exec -n tenant-a "$POD" -- rm -f /tmp/sync_task`

---

### 4.4 Threat Class: Degraded Telemetry (`unknown`)

#### SC-UNK-01: Sensor Drop / Audit Receiver Halted
- **Exact Command:**
  ```bash
  pkill -STOP -f run_audit_webhook.py || true
  POD=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a "$POD" -- /bin/sh -c "cat /etc/passwd"
  pkill -CONT -f run_audit_webhook.py || true
  ```
- **Cleanup:** Receiver process resumed cleanly.

#### SC-UNK-02: Syscall Burst Buffer Drop
- **Exact Command:**
  ```bash
  POD=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n tenant-a "$POD" -- /bin/sh -c "for i in \$(seq 1 200); do /bin/true; done"
  ```
- **Cleanup:** Ephemeral execution finishes automatically.

---

### 4.5 Threat Class: Benign Counterfactuals (`benign`)

#### SC-BEN-01: Deployment Rolling Restart
- **Exact Command:** `kubectl rollout restart deployment/web -n tenant-a && kubectl rollout status deployment/web -n tenant-a --timeout=60s`

#### SC-BEN-02: Routine Admin Debug Session in Maintenance Pod
- **Workload:** `tenant-a/debug` (baseline configured with `shell_expected: true`).
- **Exact Command:** `kubectl exec -n tenant-a deployment/debug -- /bin/sh -c "uptime && ps aux"`

#### SC-BEN-03: Legitimate Database Batch Run
- **Workload:** `tenant-a/database` (baseline allows scheduled compaction).
- **Exact Command:** `kubectl exec -n tenant-a deployment/database -- /bin/sh -c "dd if=/dev/zero of=/tmp/bench bs=1M count=20 && rm /tmp/bench"`

#### SC-BEN-04: Container Health Probe Routine Restart
- **Exact Command:** `kubectl exec -n tenant-a deployment/api -- /bin/sh -c "touch /tmp/kill-health && sleep 2"`

#### SC-BEN-05: Legitimate Analytics Service Flow on Port 3333
- **Workload:** `tenant-a/analytics` (baseline `expected_peers` contains port 3333).
- **Exact Command:** `kubectl exec -n tenant-a deployment/analytics -- /bin/sh -c "nc -z -w 3 sync-collector 3333"`

---

## 5. Automated Pre-Flight & Post-Flight Health Verification

Every scenario run executes the following automated checks before and after execution:
```bash
# 1. Cluster connectivity & context guard
kubectl config current-context | grep -q "^kind-runtimelens$"

# 2. Node ready status
kubectl get nodes --no-headers | awk '{print $2}' | grep -q "^Ready$"

# 3. Cilium CNI health
cilium status --brief | grep -q "OK"

# 4. Falco eBPF daemon running
kubectl get pods -n falco -l app.kubernetes.io/name=falco --no-headers | grep -q "Running"

# 5. Pre-flight sweep for test resources
kubectl delete pods,jobs,roles,rolebindings,deployments,services -n tenant-a -l runtimelens.test=true --ignore-not-found=true

# 6. Host memory utilization check
MEM_PERCENT=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_PERCENT" -ge 85 ]; then
  echo "SAFETY HALT: Host VM memory at ${MEM_PERCENT}% (>= 85%). Aborting run."
  exit 1
fi

# 7. Host disk utilization check
DISK_PERCENT=$(df / | awk 'NR==2 {gsub("%",""); print $5}')
if [ "$DISK_PERCENT" -ge 80 ]; then
  echo "SAFETY HALT: Host VM disk at ${DISK_PERCENT}% (>= 80%). Aborting run."
  exit 1
fi
```

---

## 6. Queue Reference
- **Active Queue Item:** `A-002` (Final Go for Pilot Scenario Execution)
- **Status:** PENDING HUMAN AUTHORIZATION
- **Action:** Awaiting explicit reply `"APPROVE A-002"` before executing the 25 pilot runs.
