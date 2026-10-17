# CANONICAL EVENT SCHEMA: RuntimeLens v1.0.0

## 1. Schema Principles
- **Source of Truth:** Single Pydantic model (`src.runtimelens.schemas.canonical.CanonicalEvent`) with JSON Schema exported to `schemas/event.schema.json`.
- **Validation:** Strict validation; unknown fields are forbidden (`extra = "forbid"`).
- **Temporal Integrity:** Stores both `event_timestamp` (source generation time) and `ingest_timestamp` (pipeline arrival time) in UTC ISO-8601.
- **Traceability:** Every canonical event retains a deterministic `event_id` and a `raw_event_ref` URI pointing to the unmanipulated raw JSONL capture.
- **Explicit Unknowns:** Degraded or missing sensor data is explicitly recorded as `None` or in `missing_sources`, never silently fabricated as zero/false.

## 2. Field Groups & Definitions

### 2.1 Metadata & Workload Identity
Identifies the affected tenant and Kubernetes object without leaking test identifiers into ML representations.
- `event_id` (string, UUIDv4): Unique identifier.
- `schema_version` (string): Fixed at `"1.0.0"`.
- `event_timestamp` (string, ISO-8601 UTC): Time recorded by sensor.
- `ingest_timestamp` (string, ISO-8601 UTC): Time received by normalizer.
- `tenant` (string): Tenant identifier (`tenant-a`, `tenant-b`, `tenant-c`).
- `namespace` (string): Kubernetes namespace.
- `pod_name` (string): Name of the pod.
- `pod_uid` (string): Immutable Kubernetes UID.
- `owner_workload` (string): Deployment/DaemonSet/StatefulSet name.
- `container_name` (string): Name of container within pod.
- `container_id` (string): Containerd/CRI runtime container ID.
- `image_digest` (string): SHA-256 digest of container image.

### 2.2 Extracted Deterministic Facts (`facts`)
Unambiguous boolean and scalar facts verified directly by code before classification:
- `host_runtime_socket_mounted` (boolean): Whether `/var/run/docker.sock` or `containerd.sock` is mapped.
- `sensitive_host_path_mounted` (boolean): Mounts to `/proc`, `/sys`, `/etc`, or host root.
- `privileged_container` (boolean): Pod securityContext `privileged: true`.
- `is_root_user` (boolean): Process UID is 0.
- `is_shell_process` (boolean): Process matches shell binary (`sh`, `bash`, `zsh`).
- `has_critical_vulnerability` (boolean): Image has known unpatched critical CVEs in Trivy report.
- `cpu_usage_mcores` (number): 5-minute container CPU rate from Prometheus.
- `is_cpu_abnormal` (boolean): CPU exceeds baseline envelope by $>2.5\times$.
- `is_outbound_egress` (boolean): Hubble flow targets external non-cluster CIDR.
- `is_cross_tenant_flow` (boolean): Hubble flow targets another tenant namespace without policy.

### 2.3 Runtime Telemetry (`runtime`)
Extracted from Falco eBPF stream:
- `process_name` (string): Binary path (e.g. `/bin/sh`).
- `parent_process` (string): Parent binary name (e.g. `nginx`).
- `command_args_sanitized` (string): Command line arguments truncated to 128 chars with control characters stripped.
- `syscall` (string): Triggering system call (e.g. `execve`, `openat`).

### 2.4 Orchestration Telemetry (`orchestration`)
Extracted from Kubernetes API Audit stream:
- `verb` (string): API verb (`create`, `update`, `patch`, `delete`, `exec`).
- `resource` (string): Kubernetes resource (`pods/exec`, `roles`, `secrets`).
- `subresource` (string, optional): Subresource name.
- `request_user` (string): ServiceAccount or User making request.

### 2.5 Network Telemetry (`network`)
Extracted from Cilium / Hubble flow stream:
- `destination_ip` (string): Target IP address.
- `destination_port` (integer): Target port number.
- `protocol` (string): L4 protocol (`TCP`, `UDP`).
- `verdict` (string): `FORWARDED` or `DROPPED`.
- `dns_query` (string, optional): Resolved domain name.

### 2.6 Workload Baseline Context (`baseline`)
Attached from the versioned declarative baseline store:
- `baseline_version` (string): Commit hash or semantic version of active baseline.
- `is_baseline_stale` (boolean): True if baseline age exceeds observation expiry threshold.
- `shell_expected` (boolean): Whether shell access is authorized for this workload.
- `expected_binaries` (array of strings): Allowlisted executable paths.
- `expected_peers` (array of strings): Authorized service communication targets.
- `baseline_deviation_detected` (boolean): True if any current attribute violates baseline.
- `deviations` (array of strings): List of specific baseline mismatches.

### 2.7 Telemetry Health Status (`health`)
- `is_telemetry_degraded` (boolean): True if any expected sensor is disconnected or late.
- `missing_sources` (array of strings): List of dropped/unavailable sensors (`["hubble"]`).
