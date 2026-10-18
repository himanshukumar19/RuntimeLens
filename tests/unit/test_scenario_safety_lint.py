"""Unit tests for safety linter with invalid manifests (Condition 3)."""

from __future__ import annotations

from typing import Any

from scripts.scenario_safety_lint import lint_manifest


def _valid_pod_manifest() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "worker-task-01",
            "namespace": "tenant-a",
            "labels": {"app": "worker", "component": "task"},
        },
        "spec": {
            "containers": [
                {
                    "name": "worker",
                    "image": "alpine:3.19",
                    "command": ["/bin/sh", "-c", "echo ok"],
                    "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                }
            ]
        },
    }


def test_safety_lint_passes_valid_manifest() -> None:
    manifest = _valid_pod_manifest()
    errors = lint_manifest(manifest)
    assert errors == [], f"Expected clean pass, got errors: {errors}"


def test_safety_lint_fails_on_class_leak_in_name() -> None:
    manifest = _valid_pod_manifest()
    manifest["metadata"]["name"] = "escape-pod-test"
    errors = lint_manifest(manifest)
    assert any("Class leakage in resource name" in e for e in errors)


def test_safety_lint_fails_on_class_leak_in_label() -> None:
    manifest = _valid_pod_manifest()
    manifest["metadata"]["labels"]["threat_class"] = "cryptomining"
    errors = lint_manifest(manifest)
    assert any("Class leakage in label" in e for e in errors)


def test_safety_lint_fails_on_forbidden_namespace() -> None:
    manifest = _valid_pod_manifest()
    manifest["metadata"]["namespace"] = "kube-system"
    errors = lint_manifest(manifest)
    assert any("Forbidden or unapproved namespace" in e for e in errors)


def test_safety_lint_fails_on_cluster_role() -> None:
    manifest = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "test-cluster-reader"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    }
    errors = lint_manifest(manifest)
    assert any("Forbidden cluster-scoped RBAC kind" in e for e in errors)


def test_safety_lint_fails_on_cluster_admin_reference() -> None:
    manifest = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "test-binding", "namespace": "tenant-a"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin",
        },
    }
    errors = lint_manifest(manifest)
    assert any("Forbidden roleRef in RoleBinding" in e for e in errors)


def test_safety_lint_fails_on_host_namespaces() -> None:
    manifest = _valid_pod_manifest()
    manifest["spec"]["hostPID"] = True
    manifest["spec"]["hostNetwork"] = True
    errors = lint_manifest(manifest)
    assert any("Forbidden hostPID: true" in e for e in errors)
    assert any("Forbidden hostNetwork: true" in e for e in errors)


def test_safety_lint_fails_on_real_runtime_socket_mount() -> None:
    manifest = _valid_pod_manifest()
    manifest["spec"]["volumes"] = [{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}]
    errors = lint_manifest(manifest)
    assert any("Forbidden real runtime socket hostPath" in e for e in errors)


def test_safety_lint_fails_on_hostpath_in_tenant_namespace() -> None:
    manifest = _valid_pod_manifest()
    # Dummy path is valid, but namespace is tenant-a (PSS baseline violation)
    manifest["spec"]["volumes"] = [
        {"name": "dummy-sock", "hostPath": {"path": "/opt/runtimelens-dummy/docker.sock"}}
    ]
    errors = lint_manifest(manifest)
    assert any("hostPath volume forbidden in tenant namespace" in e for e in errors)


def test_safety_lint_permits_dummy_hostpath_in_lab_namespace() -> None:
    manifest = _valid_pod_manifest()
    manifest["metadata"]["namespace"] = "sandbox-workloads"
    manifest["spec"]["volumes"] = [
        {"name": "dummy-sock", "hostPath": {"path": "/opt/runtimelens-dummy/docker.sock"}}
    ]
    errors = lint_manifest(manifest)
    assert errors == [], f"Expected clean pass in lab namespace, got: {errors}"


def test_safety_lint_fails_on_privileged_outside_lab_namespace() -> None:
    manifest = _valid_pod_manifest()
    manifest["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    errors = lint_manifest(manifest)
    assert any("privileged: true forbidden in namespace" in e for e in errors)


def test_safety_lint_fails_on_missing_resource_limits() -> None:
    manifest = _valid_pod_manifest()
    del manifest["spec"]["containers"][0]["resources"]["limits"]
    errors = lint_manifest(manifest)
    assert any("missing resources.limits" in e for e in errors)


def test_safety_lint_fails_on_external_destination() -> None:
    manifest = _valid_pod_manifest()
    manifest["spec"]["containers"][0]["command"] = ["curl", "https://xmrpool.eu:3333"]
    errors = lint_manifest(manifest)
    assert any("Potential external destination detected" in e for e in errors)
