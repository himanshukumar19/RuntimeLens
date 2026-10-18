# WORKLOAD BASELINE SPECIFICATION & GOVERNANCE

## 1. Concept & Role in Threat Classification
In multi-tenant Kubernetes environments, security events cannot be evaluated in isolation. An interactive shell execution (`/bin/sh`) is standard developer practice in an authorized `debug` container, but represents a critical indicator of compromise when spawned by an unprivileged `payments` container.

RuntimeLens operationalizes this context via **declarative workload baselines**. The baseline provides the expected behavioural envelope against which incoming events are compared, computing deterministic deviation facts and contextual state for the typed classifier.

## 2. Declarative Schema

```yaml
version: "v1.0.0"
metadata:
  tenant: "tenant-a"
  workload: "payment-service"
  created_at: "2026-10-17T00:00:00Z"
  approved_by: "himanshu"
  observation_period_minutes: 60
  observation_run_ids:
    - "benign-run-001"
    - "benign-run-002"

runtime:
  shell_allowed: false
  allowed_binaries:
    - "/usr/local/bin/payment-processor"
    - "/usr/bin/curl"
  allowed_parent_processes:
    - "systemd"
    - "containerd-shim"
  permitted_capabilities: []
  allowed_volume_mounts:
    - "/var/run/secrets/kubernetes.io/serviceaccount"
    - "/etc/payment/config"
  disallowed_mount_patterns:
    - "/var/run/*.sock"
    - "/proc/*"
    - "/sys/*"

network:
  allowed_inbound_ports:
    - 8080
  allowed_peers:
    - "database.tenant-a.svc.cluster.local"
    - "api.tenant-a.svc.cluster.local"
  allow_external_egress: false
  allowed_dns_domains: []

resources:
  cpu_baseline_mcores: 25
  cpu_max_envelope_mcores: 100
  memory_baseline_mb: 64
  memory_max_envelope_mb: 256
```

## 3. Four Canonical Lab Profiles

### 3.1 Web Workload (`web`)
- **Role:** Reverse proxy / Nginx static frontend.
- **Shell Allowed:** False.
- **Allowed Binaries:** `/usr/sbin/nginx`.
- **Allowed Inbound:** Port 80, 443.
- **Allowed Peers:** `api.<tenant>.svc.cluster.local`.
- **Egress:** Prohibited.

### 3.2 API Workload (`api`)
- **Role:** Python FastAPI microservice handling business logic.
- **Shell Allowed:** False.
- **Allowed Binaries:** `/usr/local/bin/python`, `/usr/local/bin/uvicorn`.
- **Allowed Inbound:** Port 8000.
- **Allowed Peers:** `database.<tenant>.svc.cluster.local`, `payment-service.<tenant>.svc.cluster.local`.

### 3.3 Database Workload (`database`)
- **Role:** Redis in-memory datastore.
- **Shell Allowed:** False.
- **Allowed Binaries:** `/usr/local/bin/redis-server`.
- **Allowed Inbound:** Port 6379.
- **Allowed Peers:** Incoming connections from `api` and `payment-service` only.
- **Resource Spike Tolerance:** High during scheduled snapshotting/indexing.

### 3.4 Payment Service Workload (`payment-style`)
- **Role:** High-security transaction handler.
- **Shell Allowed:** Strictly False.
- **Allowed Binaries:** `/usr/local/bin/payment-worker`.
- **Allowed Inbound:** Port 9000 from `api` only.
- **Egress:** Only to dedicated mock payment gateway.

## 4. Governance & Anti-Poisoning Policy
1. **Purity Rule:** Baselines are generated strictly from designated benign training runs within the **Dev split**. Events from the held-out test split are cryptographically air-gapped and never contribute to baseline construction.
2. **Zero Auto-Learning:** Automatic baseline expansion in production is prohibited. This prevents "slow-boil" baseline poisoning attacks where an attacker gradually trains the detector to accept malicious behaviors.
3. **Git-Versioned Diff Approval:** When legitimate application updates occur, changes are proposed as Git pull requests containing the baseline YAML diff, commit author, and rationale.
4. **Staleness Tracking:** If a baseline's age exceeds 30 days without re-validation, the normalizer flags `is_baseline_stale=True`, requiring human review for any associated anomalous events.

---

## 5. Rule-Based Baseline Classifiers & Mapping Registry (Locked Prior to Evaluation)

To rigorously evaluate the incremental value of workload baseline context and hosted decision models, RuntimeLens benchmarks three distinct rule-based baselines:

1. **Baseline A: Default Rules Only (`classify_rules_default`)**
   - Evaluates strictly the pinned default Falco rules from `/etc/falco/falco_rules.yaml`.
   - Uses **zero** workload baseline context (no `shell_expected`, no `expected_binaries`, no `expected_peers`).
   - Uses **zero** pod-spec facts (no hostPath / volume mount inspection, no `is_cpu_abnormal`).
   - *Known Baseline Limitation:* Falco's default ruleset contains **no cryptomining rules** (it lacks port 3333 detection or relative CPU baseline tracking) and lacks default rules detecting unprivileged host socket mounts on container launch. Consequently, Baseline A experiences **zero recall** on simulated cryptomining and host mount escape scenarios that lack default rule triggers. This limitation is an authentic characteristic of un-contextualized default IDS rules.

2. **Baseline A+: Default + Pinned Lab Rules (`classify_rules_default_plus_lab`)**
   - Evaluates default Falco rules PLUS custom lab rules (`Launch Sensitive Mount Container`, `Interactive Shell Spawned in Non-Debug Container`, `Suspicious Mining Port Egress`, `Read Sensitive Host Information Untrusted`).
   - Evaluates rules purely based on rule triggers without consulting workload baseline profiles.

3. **Baseline B: Context-Aware Rules (`classify_rules_context`)**
   - Evaluates default and lab rules alongside declarative workload baseline context (`baseline.shell_expected`, `baseline.expected_binaries`, `baseline.expected_peers`) and verified pod-spec facts.

### Rule-to-Class Mapping Registry (Locked Table)

| Rule Name | Rule Origin | Target Threat Class | Heuristic Severity | Scientific Rationale |
|:---|:---:|:---:|:---:|:---|
| `Detect release_agent File Container Escapes` | Default Falco | `container_escape` | 5.0 | Directly exploits cgroup v1 release_agent notification mechanism to execute code in host kernel/namespace. |
| `Debugfs Launched in Privileged Container` | Default Falco | `container_escape` | 5.0 | Debugfs in a privileged container provides direct read/write block device access to the underlying host disk. |
| `Linux Kernel Module Injection Detected` | Default Falco | `container_escape` | 5.0 | Sycalls `init_module` / `finit_module` directly load arbitrary code into the shared host kernel space. |
| `Execution from /dev/shm` | Default Falco | `cryptomining` | 3.5 | In accordance with `docs/LABELING_GUIDE.md` Section 2.4, payload drops in volatile memory (`/dev/shm`) represent primary corroborating evidence for mining loaders. |
| `Drop and execute new binary in container` | Default Falco | `cryptomining` | 3.5 | In unprivileged containers, newly dropped executable binaries represent staging of mining workers or exploitation tools. |
| `Terminal shell in container` | Default Falco | `privilege_abuse` | 3.8 | Default Falco flags any interactive shell spawn as suspicious execution in the absence of baseline context. |
| `Read sensitive file untrusted` | Default Falco | `privilege_abuse` | 3.0 | Default rule without baseline context flags read attempts on `/etc/shadow` or `/etc/passwd`. |
| `Contact K8S API Server From Container` | Default Falco | `privilege_abuse` | 3.0 | Unapproved pod attempts to communicate with the internal Kubernetes API server endpoint for reconnaissance. |
| `Netcat Remote Code Execution in Container` | Default Falco | `privilege_abuse` | 3.8 | Spawning netcat with input redirection represents an interactive reverse shell or lateral privilege abuse. |
| `Launch Sensitive Mount Container` | Custom Lab Rule | `container_escape` | 5.0 | Specifically tags verified host socket mounts (`/var/run/docker.sock`, `containerd.sock`) in lab escape scenarios. |
| `Suspicious Mining Port Egress` | Custom Lab Rule | `cryptomining` | 4.0 | Detects outbound network connection attempts to mining pool ports (3333, 4444, etc.). |
| `Interactive Shell Spawned in Non-Debug Container` | Custom Lab Rule | `privilege_abuse` | 3.8 | Detects interactive shell spawns in production tenant workloads (`web`, `api`, `database`, `payment-style`). |
| `Read Sensitive Host Information Untrusted` | Custom Lab Rule | `reconnaissance-unconfirmed` | 2.0 | Detects identity file access in unprivileged containers; classified as low-severity diagnostic reconnaissance. |

*Governance Notice:* This table is permanently frozen prior to Dev-set model evaluation and will not be altered post-hoc.
