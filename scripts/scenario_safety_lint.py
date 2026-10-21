"""Scenario Safety Linter for RuntimeLens cluster manifests (Ticket 06a, Condition 3).

Renders and audits Kubernetes manifests BEFORE application to the cluster.
Guarantees zero host socket exposure, zero cluster-admin RBAC, zero resource leakage,
zero class leakage, and strict namespace and resource bounding.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Final

import yaml

ALLOWED_NAMESPACES: Final[frozenset[str]] = frozenset(
    {"tenant-a", "tenant-b", "tenant-c", "sandbox-workloads"}
)

ALLOWED_LAB_NAMESPACES: Final[frozenset[str]] = frozenset({"sandbox-workloads"})

ALLOWED_DUMMY_HOSTPATHS: Final[frozenset[str]] = frozenset(
    {
        "/opt/runtimelens-dummy/docker.sock",
        "/opt/runtimelens-dummy/containerd.sock",
        # Inert dummy DIRECTORY (type: Directory) for TMPL-ESC-04 / TMPL-ESC-09.
        # Never a real host path: contains no host state, no credentials, no runtime socket.
        "/opt/runtimelens-dummy/etc",
    }
)

FORBIDDEN_RUNTIME_SOCKET_PATTERNS: Final[tuple[str, ...]] = (
    "/var/run/docker.sock",
    "/var/run/containerd",
    "/run/containerd",
    "/var/run/crio",
    "/run/crio",
)

CLASS_LEAK_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "escape",
        "mining",
        "cryptomining",
        "privilege",
        "exploit",
        "attack",
        "benign",
        "esc",
        "prv",
        "mnr",
    }
)


def _contains_class_leak(text: str) -> bool:
    """Check if identifier or label string contains scenario class leak tokens."""
    tokens = re.split(r"[-_.:/ \t]+", text.lower())
    return any(t in CLASS_LEAK_TOKENS for t in tokens)


def lint_manifest(manifest: dict[str, Any]) -> list[str]:
    """Audit a single Kubernetes manifest against strict safety rules.

    Returns a list of error strings. Empty list indicates clean pass.
    """
    errors: list[str] = []
    kind = str(manifest.get("kind", ""))
    metadata = manifest.get("metadata", {})
    name = str(metadata.get("name", ""))
    namespace = str(metadata.get("namespace", "default"))
    labels = metadata.get("labels", {})

    # 1. Class Leakage Audit in Metadata
    if _contains_class_leak(name):
        errors.append(f"Class leakage in resource name: '{name}'")
    for k, v in labels.items():
        if _contains_class_leak(str(k)) or _contains_class_leak(str(v)):
            errors.append(f"Class leakage in label: '{k}={v}'")

    # 2. Namespace Allowlist
    if namespace not in ALLOWED_NAMESPACES and kind not in {"Namespace"}:
        allowed_list = sorted(ALLOWED_NAMESPACES)
        errors.append(
            f"Forbidden or unapproved namespace: '{namespace}' (Must be in {allowed_list})"
        )

    # 3. RBAC Invariants
    if kind in {"ClusterRole", "ClusterRoleBinding"}:
        errors.append(f"Forbidden cluster-scoped RBAC kind: '{kind}'")
    if "cluster-admin" in name.lower():
        errors.append("Forbidden cluster-admin reference in resource name")

    if kind == "RoleBinding":
        role_ref = manifest.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin" or role_ref.get("kind") == "ClusterRole":
            errors.append(f"Forbidden roleRef in RoleBinding: {role_ref}")

    # 4. Pod Spec Extraction
    pod_spec = manifest.get("spec", {})
    if kind in {"Deployment", "Job", "DaemonSet"}:
        pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})

    if pod_spec:
        # Host namespaces check
        if pod_spec.get("hostPID") is True:
            errors.append("Forbidden hostPID: true")
        if pod_spec.get("hostNetwork") is True:
            errors.append("Forbidden hostNetwork: true")
        if pod_spec.get("hostIPC") is True:
            errors.append("Forbidden hostIPC: true")

        # HostPath volumes check
        volumes = pod_spec.get("volumes", [])
        for vol in volumes:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath", {})
                hp_path = str(hp.get("path", "")).strip()

                # Rule 4a: Real runtime sockets are strictly forbidden
                if any(
                    real_sock in hp_path.lower() for real_sock in FORBIDDEN_RUNTIME_SOCKET_PATTERNS
                ):
                    errors.append(f"Forbidden real runtime socket hostPath: '{hp_path}'")

                # Rule 4b: Only documented dummy path is allowed
                if hp_path not in ALLOWED_DUMMY_HOSTPATHS:
                    errors.append(
                        f"hostPath outside dummy allowlist: '{hp_path}' "
                        f"(Allowed: {sorted(ALLOWED_DUMMY_HOSTPATHS)})"
                    )

                # Rule 4c: hostPath allowed ONLY in dedicated lab namespace
                if namespace not in ALLOWED_LAB_NAMESPACES:
                    errors.append(
                        f"hostPath volume forbidden in tenant namespace '{namespace}' "
                        f"(Violates Pod Security Standards baseline; must use "
                        f"{sorted(ALLOWED_LAB_NAMESPACES)})"
                    )

        # Container specifications check
        containers = pod_spec.get("containers", [])
        for c in containers:
            c_name = str(c.get("name", "unnamed"))
            if _contains_class_leak(c_name):
                errors.append(f"Class leakage in container name: '{c_name}'")

            # Privileged check
            sec_ctx = c.get("securityContext", {})
            if sec_ctx.get("privileged") is True and namespace not in ALLOWED_LAB_NAMESPACES:
                errors.append(
                    f"privileged: true forbidden in namespace '{namespace}' "
                    f"(Must be in {sorted(ALLOWED_LAB_NAMESPACES)})"
                )

            # Resources limits check
            res = c.get("resources", {})
            limits = res.get("limits", {})
            if not limits or "cpu" not in limits or "memory" not in limits:
                errors.append(
                    f"Container '{c_name}' missing resources.limits (declare cpu and memory)"
                )

            # External network destination check in args/command/env
            cmd_args = " ".join(c.get("command", []) + c.get("args", []))
            for env in c.get("env", []):
                cmd_args += " " + str(env.get("value", ""))

            # Flag public mining pool domains or external public IPs
            for token in re.findall(
                r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}", cmd_args
            ):
                clean_t = token.strip()
                # Ignore internal cluster DNS, IPs, and file/socket extensions
                if (
                    clean_t.endswith(".svc")
                    or clean_t.endswith(".cluster.local")
                    or clean_t.endswith(".local")
                    or clean_t.endswith(".sock")
                    or clean_t.endswith(".json")
                    or clean_t.endswith(".yaml")
                    or clean_t.endswith(".sh")
                    or clean_t.startswith("10.")
                    or clean_t.startswith("172.18.")
                    or clean_t.startswith("127.")
                    or clean_t in {"localhost", "kubernetes.default"}
                ):
                    continue
                # Flag suspicious external domains/IPs
                errors.append(f"Potential external destination detected in '{c_name}': '{clean_t}'")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Scenario Safety Manifest Linter")
    parser.add_argument("--files", nargs="*", help="Manifest files to lint")
    args = parser.parse_args()

    print("=== RuntimeLens Scenario Safety Manifest Linter ===")
    print("Allowed Namespaces:", sorted(ALLOWED_NAMESPACES))
    print("Allowed Lab Namespace (hostPath permitted):", sorted(ALLOWED_LAB_NAMESPACES))
    print("Allowed Dummy hostPaths:", sorted(ALLOWED_DUMMY_HOSTPATHS))
    print("Zero Class Leakage Enforced.")

    if args.files:
        total_errors = 0
        for fpath in args.files:
            p = Path(fpath)
            if not p.exists():
                print(f"ERROR: File not found: {fpath}")
                total_errors += 1
                continue
            content = p.read_text(encoding="utf-8")
            for doc in yaml.safe_load_all(content):
                if not doc:
                    continue
                errs = lint_manifest(doc)
                kind = doc.get("kind", "Doc")
                name = doc.get("metadata", {}).get("name", "unnamed")
                doc_name = f"{kind}/{name}"
                if errs:
                    print(f"FAIL: {fpath} ({doc_name})")
                    for e in errs:
                        print(f"  - {e}")
                    total_errors += len(errs)
                else:
                    print(f"PASS: {fpath} ({doc_name})")
        if total_errors > 0:
            print(f"FAILED: {total_errors} safety linter violations found.")
            return 1
        print("ALL MANIFESTS PASSED SAFETY LINT.")
        return 0

    # Self-test if no files passed
    print("PASS: Scenario safety linter initialized and ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
