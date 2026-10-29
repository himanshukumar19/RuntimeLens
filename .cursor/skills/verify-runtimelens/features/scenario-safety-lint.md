# Scenario Safety Manifest Linter

The Scenario Safety Manifest Linter audits all Kubernetes manifests before deployment to the laboratory cluster. It ensures that synthetic and real experiment manifests strictly adhere to tenant isolation, forbid dangerous host mounts (such as real Docker sockets), prohibit cluster-admin bindings, and prevent scenario label leakage into metadata.

## Sub-features

- `lint-namespace-containment` enforces that workloads deploy only into allowed tenant namespaces (`tenant-a`, `tenant-b`, `tenant-c`, `sandbox-workloads`).
- `lint-hostpath-guard` prohibits mounts of real host sockets (`/var/run/docker.sock`, `/run/containerd`) while allowing only inert test dummies (`/opt/runtimelens-dummy/docker.sock`).
- `lint-rbac-bounds` ensures zero `ClusterRole` or `ClusterRoleBinding` manifests and blocks `cluster-admin` bindings.
- `lint-zero-leakage` scans metadata names, container names, and label keys/values for scenario classification tokens (such as `escape`, `exploit`, `mining`) to prevent classifier cheating.

## How to get to it (user POV)

- Run `make safety-lint`.
- Run `uv run python scripts/scenario_safety_lint.py`.
- Run `uv run python scripts/control_runtimelens.py safety-lint`.

## Driving it with control-runtimelens

Preconditions:
- Python environment ready.
- Lab scenario manifests present in `lab/` or scenario directories.

- **Execute manifest safety check.** Run `uv run python scripts/control_runtimelens.py safety-lint`.
- **Expected output:**
  ```text
  === RuntimeLens Scenario Safety Manifest Linter ===
  Allowed Namespaces: ['sandbox-workloads', 'tenant-a', 'tenant-b', 'tenant-c']
  Allowed Lab Namespace (hostPath permitted): ['sandbox-workloads']
  Allowed Dummy hostPaths: ['/opt/runtimelens-dummy/containerd.sock', '/opt/runtimelens-dummy/docker.sock', '/opt/runtimelens-dummy/etc']
  Zero Class Leakage Enforced.
  PASS: Scenario safety linter initialized and ready.
  ```
- **Exit code:** Returns 0 on a clean pass, non-zero on any safety violation.

## Gotchas

- Any manifest containing a token like `mining`, `escape`, or `privilege` in its metadata fails immediately under the zero class leakage rule.
- Real `/var/run/docker.sock` paths are rejected unconditionally. Only inert paths under `/opt/runtimelens-dummy/` are accepted for simulation templates.
- ClusterRoleBindings are flagged unless strictly namespaced and scoped.
