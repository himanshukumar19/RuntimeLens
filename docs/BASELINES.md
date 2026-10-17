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
