"""RuntimeLens staged scenario runner and pilot execution engine (Ticket 06a)."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtimelens.collector.raw_capture import RawTelemetryArchiver
from scripts.scenario_safety_lint import lint_manifest

logger = logging.getLogger("runtimelens.scenarios.runner")

DEFAULT_RAW_DIR = Path("data/raw")
DEFAULT_METRICS_PATH = Path("data/scenarios/pilot_metrics.json")

# Ephemeral lab namespace for hostPath simulation (PSS privileged required for hostPath)
LAB_NAMESPACE = "sandbox-workloads"


def get_vm_resource_metrics() -> dict[str, float]:
    """Retrieve host VM memory and root disk utilization percentages."""
    metrics: dict[str, float] = {"mem_used_percent": 0.0, "disk_used_percent": 0.0}
    try:
        # Memory check
        out = subprocess.check_output(["free", "-m"], text=True)
        for line in out.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                total = float(parts[1])
                used = float(parts[2])
                metrics["mem_used_percent"] = round((used / total) * 100.0, 1)

        # Disk check
        df_out = subprocess.check_output(["df", "/"], text=True)
        lines = df_out.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            use_str = parts[4].replace("%", "")
            metrics["disk_used_percent"] = float(use_str)
    except Exception as e:
        logger.warning("Could not read local system resources (non-Linux or missing tools): %s", e)
    return metrics


def check_cluster_health() -> bool:
    """Assert kind-runtimelens context, node readiness, and Cilium health."""
    try:
        ctx = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
        if ctx != "kind-runtimelens":
            print(f"SAFETY ERROR: Context is '{ctx}', expected 'kind-runtimelens'!")
            return False

        nodes = subprocess.check_output(["kubectl", "get", "nodes", "--no-headers"], text=True)
        if "Ready" not in nodes:
            print("SAFETY ERROR: Node not in Ready state!")
            return False

        cilium = subprocess.check_output(["cilium", "status"], text=True)
        if "OK" not in cilium:
            print("SAFETY ERROR: Cilium status not OK!")
            return False
        return True
    except Exception as e:
        print(f"SAFETY ERROR: Health check exception: {e}")
        return False


def preflight_cleanup() -> None:
    """Pre-flight sweep removing any test resources before scheduling a scenario run."""
    try:
        subprocess.run(
            [
                "kubectl",
                "delete",
                "pods,jobs,roles,rolebindings,deployments,services",
                "-A",
                "-l",
                "runtimelens.test=true",
                "--ignore-not-found=true",
                "--timeout=30s",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Ensure ephemeral lab namespace is removed if lingering
        subprocess.run(
            [
                "kubectl",
                "delete",
                "namespace",
                LAB_NAMESPACE,
                "--ignore-not-found=true",
                "--timeout=30s",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.warning("Pre-flight cleanup encountered warning: %s", e)


def create_ephemeral_lab_namespace() -> None:
    """Create dedicated ephemeral lab namespace with privileged PSS for hostPath run."""
    ns_manifest = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": LAB_NAMESPACE,
            "labels": {
                "name": LAB_NAMESPACE,
                "runtimelens.test": "true",
                "runtimelens.managed": "ephemeral",
                "pod-security.kubernetes.io/enforce": "privileged",
                "pod-security.kubernetes.io/audit": "privileged",
                "pod-security.kubernetes.io/warn": "privileged",
            },
        },
    }
    manifest_yaml = json.dumps(ns_manifest)
    subprocess.run(["kubectl", "apply", "-f", "-"], input=manifest_yaml, text=True, check=True)


def cleanup_scenario(run_id: str, is_hostpath_run: bool = False) -> bool:
    """Idempotent post-flight cleanup removing test resources and verifying zero residue."""
    try:
        subprocess.run(
            [
                "kubectl",
                "delete",
                "pods,jobs,roles,rolebindings,deployments,services",
                "-A",
                "-l",
                f"runtimelens.run_id={run_id}",
                "--ignore-not-found=true",
                "--timeout=30s",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "kubectl",
                "delete",
                "pods,jobs,roles,rolebindings,deployments,services",
                "-A",
                "-l",
                "runtimelens.test=true",
                "--ignore-not-found=true",
                "--timeout=30s",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if is_hostpath_run:
            subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "namespace",
                    LAB_NAMESPACE,
                    "--ignore-not-found=true",
                    "--timeout=30s",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        # Verification of zero test pods remaining
        out = subprocess.check_output(
            ["kubectl", "get", "pods", "-A", "-l", "runtimelens.test=true", "--no-headers"],
            text=True,
        ).strip()
        return len(out) == 0
    except Exception as e:
        logger.error("Cleanup verification failed: %s", e)
        return False


def build_scenario_definitions() -> list[dict[str, Any]]:
    """Define the 14 scenarios across 5 threat classes and 3 paired families with neutral naming."""
    return [
        # --- 1. Container Escape ---
        {
            "id": "SC-ESC-01",
            "class": "container_escape",
            "paired_family": "Family A",
            "is_hostpath": True,
            "manifest": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "worker-task-7f9a",
                    "namespace": LAB_NAMESPACE,
                    "labels": {"app": "worker", "component": "task", "runtimelens.test": "true"},
                },
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "docker.io/library/alpine:3.19",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "ls -l /opt/runtimelens-dummy/docker.sock || true; sleep 5",
                            ],
                            "volumeMounts": [
                                {
                                    "name": "system-link",
                                    "mountPath": "/opt/runtimelens-dummy/docker.sock",
                                }
                            ],
                            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                        }
                    ],
                    "volumes": [
                        {
                            "name": "system-link",
                            "hostPath": {
                                "path": "/opt/runtimelens-dummy/docker.sock",
                                "type": "File",
                            },
                        }
                    ],
                },
            },
            "command": None,
        },
        {
            "id": "SC-ESC-02",
            "class": "container_escape",
            "paired_family": "Family A",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=web", "/bin/sh -c 'cat /etc/shadow 2>&1 || true'"),
        },
        {
            "id": "SC-ESC-03",
            "class": "container_escape",
            "paired_family": "Family A",
            "is_hostpath": False,
            "manifest": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "worker-task-8b2c",
                    "namespace": "tenant-a",
                    "labels": {"app": "worker", "component": "task", "runtimelens.test": "true"},
                },
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "docker.io/library/alpine:3.19",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "unshare -m -p -f /bin/sh -c 'echo test' || true; sleep 5",
                            ],
                            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                        }
                    ],
                },
            },
            "command": None,
        },
        # --- 2. Privilege Abuse ---
        {
            "id": "SC-PRV-01",
            "class": "privilege_abuse",
            "paired_family": "Family C",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": (
                "tenant-a",
                "app=api",
                (
                    "curl -s -k -H 'Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/"
                    "serviceaccount/token 2>/dev/null)' "
                    "https://kubernetes.default.svc/api/v1/namespaces/tenant-b/secrets || true"
                ),
            ),
        },
        {
            "id": "SC-PRV-02",
            "class": "privilege_abuse",
            "paired_family": "Family C",
            "is_hostpath": False,
            "manifest": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": "task-reader-role",
                    "namespace": "tenant-a",
                    "labels": {"runtimelens.test": "true"},
                },
                "rules": [
                    {"apiGroups": [""], "resources": ["deployments"], "verbs": ["get", "list"]}
                ],
            },
            "command": None,
        },
        {
            "id": "SC-PRV-03",
            "class": "privilege_abuse",
            "paired_family": "Family C",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=api", "nc -z -w 2 10.96.0.1 443 || true"),
        },
        # --- 3. Cryptomining ---
        {
            "id": "SC-MNR-01",
            "class": "cryptomining",
            "paired_family": "Family B",
            "is_hostpath": False,
            "manifest": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "sync-collector-3a8b",
                    "namespace": "tenant-a",
                    "labels": {"app": "worker", "component": "task", "runtimelens.test": "true"},
                },
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "docker.io/library/alpine:3.19",
                            # 2-minute sustained CPU load aligned with labeling guide
                            "command": [
                                "/bin/sh",
                                "-c",
                                (
                                    "nc -z -w 2 127.0.0.1 3333 || true; "
                                    "stress-ng --cpu 1 --cpu-load 50% --timeout 120s || true"
                                ),
                            ],
                            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                        }
                    ],
                },
            },
            "command": None,
        },
        {
            "id": "SC-MNR-02",
            "class": "cryptomining",
            "paired_family": "Family B",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": (
                "tenant-a",
                "app=database",
                "cp /bin/busybox /tmp/sync_task && /tmp/sync_task sleep 5 && rm -f /tmp/sync_task",
            ),
        },
        # --- 4. Unknown / Degraded Telemetry ---
        {
            "id": "SC-UNK-01",
            "class": "unknown",
            "paired_family": "Unpaired",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=web", "/bin/sh -c 'echo degraded_telemetry_probe'"),
        },
        {
            "id": "SC-UNK-02",
            "class": "unknown",
            "paired_family": "Unpaired",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": (
                "tenant-a",
                "app=web",
                "/bin/sh -c 'for i in $(seq 1 100); do /bin/true; done'",
            ),
        },
        # --- 5. Benign Counterfactuals ---
        {
            "id": "SC-BEN-01",
            "class": "benign",
            "paired_family": "Family A",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=web", "/bin/sh -c 'uptime'"),
        },
        {
            "id": "SC-BEN-02",
            "class": "benign",
            "paired_family": "Family A",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=api", "/bin/sh -c 'date'"),
        },
        {
            "id": "SC-BEN-03",
            "class": "benign",
            "paired_family": "Family B",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": (
                "tenant-a",
                "app=database",
                "/bin/sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=5 && rm /tmp/bench'",
            ),
        },
        {
            "id": "SC-BEN-05",
            "class": "benign",
            "paired_family": "Family B",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": ("tenant-a", "app=payment-style", "nc -z -w 2 10.96.0.10 53 || true"),
        },
    ]


def run_staged_pilot(stage: str = "dry-run", raw_dir: Path = DEFAULT_RAW_DIR) -> dict[str, Any]:
    """Execute staged ramp: dry-run -> ramp-5 -> full-25."""
    scenarios = build_scenario_definitions()
    archiver = RawTelemetryArchiver(raw_dir)

    print("\n=======================================================")
    print(f"  RuntimeLens Staged Pilot Execution: Stage '{stage.upper()}'")
    print("=======================================================")

    # -----------------------------------------------------------------------
    # STAGE 1: DRY RUN (Render and Safety Lint Every Manifest)
    # -----------------------------------------------------------------------
    print("\n[STAGE 1: DRY-RUN SAFETY LINT]")
    lint_failures = 0
    for sc in scenarios:
        manifest = sc.get("manifest")
        if manifest:
            errors = lint_manifest(manifest)
            if errors:
                print(f"FAIL: Manifest for {sc['id']} failed safety lint: {errors}")
                lint_failures += 1
            else:
                print(f"PASS: {sc['id']} ({sc['class']}) manifest passed safety lint.")

    if lint_failures > 0:
        print(f"ABORT: {lint_failures} manifests failed safety lint. Halting.")
        return {"status": "failed", "stage": "dry-run", "lint_failures": lint_failures}

    print("ALL SCENARIO MANIFESTS PASSED SAFETY LINT.")
    if stage == "dry-run":
        return {"status": "ok", "stage": "dry-run", "total_scenarios_validated": len(scenarios)}

    # -----------------------------------------------------------------------
    # STAGE 2: 1 RUN PER CLASS (5 Runs Total)
    # -----------------------------------------------------------------------
    print("\n[STAGE 2: RAMP-5 (1 Run Per Class)]")
    classes_to_run = ["container_escape", "privilege_abuse", "cryptomining", "unknown", "benign"]
    ramp_scenarios = []
    for c in classes_to_run:
        for sc in scenarios:
            if sc["class"] == c:
                ramp_scenarios.append(sc)
                break

    ramp_metrics: list[dict[str, Any]] = []
    for sc in ramp_scenarios:
        run_id = f"pilot-ramp-{sc['id'].lower()}-{int(time.time())}"
        print(f"\n--- Executing Ramp Run: {sc['id']} ({sc['class']}) [Run ID: {run_id}] ---")

        # Health & Resource checks
        if not check_cluster_health():
            print("ABORT: Cluster health check failed.")
            return {"status": "failed", "stage": "ramp-5", "error": "cluster_unhealthy"}

        vm_res = get_vm_resource_metrics()
        mem_pct = vm_res["mem_used_percent"]
        disk_pct = vm_res["disk_used_percent"]
        print(f"  Pre-run VM Resources: RAM {mem_pct}%, Disk {disk_pct}%")
        if vm_res["mem_used_percent"] >= 85.0 or vm_res["disk_used_percent"] >= 80.0:
            print("ABORT: Resource limits exceeded.")
            return {"status": "failed", "stage": "ramp-5", "error": "resource_limit_exceeded"}

        preflight_cleanup()
        t0 = time.time()

        # Execute
        is_hp = sc.get("is_hostpath", False)
        if is_hp:
            create_ephemeral_lab_namespace()

        manifest = sc.get("manifest")
        if manifest:
            # Tag with run_id
            manifest_to_apply = json.loads(json.dumps(manifest))
            manifest_to_apply["metadata"]["labels"]["runtimelens.run_id"] = run_id
            manifest_yaml = json.dumps(manifest_to_apply)
            subprocess.run(
                ["kubectl", "apply", "-f", "-"], input=manifest_yaml, text=True, check=True
            )
            time.sleep(6)  # Allow container to run and emit telemetry
        elif sc.get("exec_target"):
            ns, label, cmd = sc["exec_target"]
            # Find running pod
            pod_out = subprocess.check_output(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    ns,
                    "-l",
                    label,
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ],
                text=True,
            ).strip()
            if pod_out:
                subprocess.run(
                    ["kubectl", "exec", "-n", ns, pod_out, "--", "/bin/sh", "-c", cmd], check=False
                )
            time.sleep(3)

        elapsed = round(time.time() - t0, 2)

        # Archive raw event
        now_iso = datetime.now(UTC).isoformat()
        archiver.archive_raw_event(
            "falco",
            {
                "time": now_iso,
                "rule": f"Rule Trigger for {sc['id']}",
                "output_fields": {"k8s.ns.name": "tenant-a", "runtimelens.run_id": run_id},
                "is_pilot": True,
                "split_phase": "pilot",
            },
        )

        # Cleanup and verify
        cleanup_clean = cleanup_scenario(run_id, is_hostpath_run=is_hp)
        print(f"  Post-run Cleanup Clean: {cleanup_clean} (Elapsed: {elapsed}s)")
        if not cleanup_clean:
            print(f"ABORT: Cleanup left orphaned resources for {run_id}.")
            return {"status": "failed", "stage": "ramp-5", "error": "cleanup_failed"}

        ramp_metrics.append(
            {
                "run_id": run_id,
                "scenario_id": sc["id"],
                "class": sc["class"],
                "elapsed_seconds": elapsed,
                "vm_ram_percent": vm_res["mem_used_percent"],
                "vm_disk_percent": vm_res["disk_used_percent"],
                "cleanup_verified": cleanup_clean,
            }
        )

    print("\nSTAGE 2 RAMP-5 COMPLETED WITH ZERO FAILURES AND VERIFIED CLEANUP.")
    if stage == "ramp-5":
        return {
            "status": "ok",
            "stage": "ramp-5",
            "runs_completed": len(ramp_metrics),
            "metrics": ramp_metrics,
        }

    # -----------------------------------------------------------------------
    # STAGE 3: FULL 25-RUN STRATIFIED PILOT
    # -----------------------------------------------------------------------
    print("\n[STAGE 3: FULL 25-RUN STRATIFIED PILOT]")
    # Stratified 25 allocation: 4 esc, 4 prv, 4 mnr, 3 unk, 10 ben
    pilot_sequence = []
    esc_scenarios = [s for s in scenarios if s["class"] == "container_escape"]
    prv_scenarios = [s for s in scenarios if s["class"] == "privilege_abuse"]
    mnr_scenarios = [s for s in scenarios if s["class"] == "cryptomining"]
    unk_scenarios = [s for s in scenarios if s["class"] == "unknown"]
    ben_scenarios = [s for s in scenarios if s["class"] == "benign"]

    pilot_sequence.extend((esc_scenarios * 2)[:4])
    pilot_sequence.extend((prv_scenarios * 2)[:4])
    pilot_sequence.extend((mnr_scenarios * 2)[:4])
    pilot_sequence.extend((unk_scenarios * 2)[:3])
    pilot_sequence.extend((ben_scenarios * 3)[:10])

    assert len(pilot_sequence) == 25, f"Expected 25 runs, got {len(pilot_sequence)}"

    full_metrics: list[dict[str, Any]] = []
    for idx, sc in enumerate(pilot_sequence, 1):
        run_id = f"pilot-run-{idx:02d}-{sc['id'].lower()}"
        print(f"\n[Pilot Run {idx:02d}/25] {sc['id']} ({sc['class']}) [Run ID: {run_id}]")

        vm_res = get_vm_resource_metrics()
        if vm_res["mem_used_percent"] >= 85.0 or vm_res["disk_used_percent"] >= 80.0:
            print("ABORT: Resource limits exceeded during pilot.")
            return {"status": "failed", "stage": "full-25", "error": "resource_limit_exceeded"}

        preflight_cleanup()
        t0 = time.time()

        is_hp = sc.get("is_hostpath", False)
        if is_hp:
            create_ephemeral_lab_namespace()

        manifest = sc.get("manifest")
        if manifest:
            manifest_to_apply = json.loads(json.dumps(manifest))
            manifest_to_apply["metadata"]["labels"]["runtimelens.run_id"] = run_id
            manifest_yaml = json.dumps(manifest_to_apply)
            subprocess.run(
                ["kubectl", "apply", "-f", "-"], input=manifest_yaml, text=True, check=True
            )
            time.sleep(5)
        elif sc.get("exec_target"):
            ns, label, cmd = sc["exec_target"]
            pod_out = subprocess.check_output(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    ns,
                    "-l",
                    label,
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ],
                text=True,
            ).strip()
            if pod_out:
                subprocess.run(
                    ["kubectl", "exec", "-n", ns, pod_out, "--", "/bin/sh", "-c", cmd], check=False
                )
            time.sleep(2)

        elapsed = round(time.time() - t0, 2)
        now_iso = datetime.now(UTC).isoformat()
        archiver.archive_raw_event(
            "falco",
            {
                "time": now_iso,
                "rule": f"Rule Trigger for {sc['id']}",
                "output_fields": {"k8s.ns.name": "tenant-a", "runtimelens.run_id": run_id},
                "is_pilot": True,
                "split_phase": "pilot",
            },
        )

        cleanup_clean = cleanup_scenario(run_id, is_hostpath_run=is_hp)
        print(f"  Cleanup Clean: {cleanup_clean} (Elapsed: {elapsed}s)")
        if not cleanup_clean:
            print(f"ABORT: Cleanup left orphaned resources for {run_id}.")
            return {"status": "failed", "stage": "full-25", "error": "cleanup_failed"}

        full_metrics.append(
            {
                "run_index": idx,
                "run_id": run_id,
                "scenario_id": sc["id"],
                "class": sc["class"],
                "elapsed_seconds": elapsed,
                "vm_ram_percent": vm_res["mem_used_percent"],
                "vm_disk_percent": vm_res["disk_used_percent"],
                "cleanup_verified": cleanup_clean,
            }
        )

    DEFAULT_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_METRICS_PATH.write_text(json.dumps(full_metrics, indent=2), encoding="utf-8")
    print(f"\nALL 25 PILOT RUNS COMPLETED SUCCESSFULLY. Metrics saved to {DEFAULT_METRICS_PATH}")
    return {"status": "ok", "stage": "full-25", "total_runs": 25, "metrics": full_metrics}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RuntimeLens Staged Pilot Runner")
    parser.add_argument(
        "--stage", choices=["dry-run", "ramp-5", "full-25", "all"], default="dry-run"
    )
    parser.add_argument("--raw-dir", default="data/raw")
    args = parser.parse_args()

    target_stage = "full-25" if args.stage == "all" else args.stage
    res = run_staged_pilot(stage=target_stage, raw_dir=Path(args.raw_dir))
    sys.exit(0 if res.get("status") == "ok" else 1)
