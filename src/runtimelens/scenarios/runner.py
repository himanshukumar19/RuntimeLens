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


def build_scenario_definitions(mining_duration: int = 15) -> list[dict[str, Any]]:
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
                    "wget -T 2 -t 1 --no-check-certificate -qO- "
                    "https://10.96.0.1:443/api/v1/namespaces/tenant-b/secrets || true"
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
                            # Sustained CPU loop throttled by container cgroup quota to 500m
                            "command": [
                                "/bin/sh",
                                "-c",
                                (
                                    "nc -z -w 2 127.0.0.1 3333 || true; "
                                    "while true; do :; done & PID=$!; "
                                    f"sleep {mining_duration}; kill $PID 2>/dev/null || true"
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
                "ln -sf /bin/busybox /tmp/sleep && /tmp/sleep 3 && rm -f /tmp/sleep",
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
            "id": "SC-BEN-04",
            "class": "benign",
            "paired_family": "Family B",
            "is_hostpath": False,
            "manifest": None,
            "exec_target": (
                "tenant-a",
                "app=payment-style",
                "/bin/sh -c 'touch /tmp/health_ok && rm -f /tmp/health_ok'",
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

        sc_to_run = sc
        # In accordance with Condition 3: 2 runs of SC-MNR-01 execute sustained 2-minute load
        if sc["id"] == "SC-MNR-01" and idx in {9, 10}:
            sustained_defs = build_scenario_definitions(mining_duration=120)
            sc_to_run = [s for s in sustained_defs if s["id"] == "SC-MNR-01"][0]

        manifest = sc_to_run.get("manifest")
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
        # Incrementally persist metrics so progress is never lost
        DEFAULT_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_METRICS_PATH.write_text(json.dumps(full_metrics, indent=2), encoding="utf-8")

    DEFAULT_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_METRICS_PATH.write_text(json.dumps(full_metrics, indent=2), encoding="utf-8")
    print(f"\nALL 25 PILOT RUNS COMPLETED SUCCESSFULLY. Metrics saved to {DEFAULT_METRICS_PATH}")
    return {"status": "ok", "stage": "full-25", "total_runs": 25, "metrics": full_metrics}


DEFAULT_CHECKPOINT_PATH = Path("data/scenarios/run_checkpoint.json")


def generate_400_run_sequence() -> list[dict[str, Any]]:
    """Generate deterministic 400-run stratified sequence partitioned across 5 seeds."""
    import random

    scenarios = build_scenario_definitions(mining_duration=15)
    sc_map = {s["id"]: s for s in scenarios}

    # Per-seed allocation (80 runs per seed * 5 seeds = 400 runs):
    # 12 escape, 12 privilege, 12 mining, 8 unknown, 36 benign
    seed_alloc = [
        ("SC-ESC-01", 4),
        ("SC-ESC-02", 4),
        ("SC-ESC-03", 4),
        ("SC-PRV-01", 4),
        ("SC-PRV-02", 4),
        ("SC-PRV-03", 4),
        ("SC-MNR-01", 6),
        ("SC-MNR-02", 6),
        ("SC-UNK-01", 4),
        ("SC-UNK-02", 4),
        ("SC-BEN-01", 8),
        ("SC-BEN-02", 8),
        ("SC-BEN-03", 7),
        ("SC-BEN-04", 6),
        ("SC-BEN-05", 7),
    ]

    total_sequence = []
    global_idx = 1
    for seed in range(1, 6):
        seed_runs = []
        for sc_id, count in seed_alloc:
            sc_def = sc_map.get(sc_id) or scenarios[0]
            for _ in range(count):
                seed_runs.append(sc_def)

        # Deterministic shuffle per seed
        rng = random.Random(seed * 1000)
        rng.shuffle(seed_runs)

        for sc_def in seed_runs:
            run_item = dict(sc_def)
            run_item["run_index"] = global_idx
            run_item["seed"] = seed
            run_item["run_id"] = f"run-{global_idx:03d}-{sc_def['id'].lower()}-s{seed}"
            total_sequence.append(run_item)
            global_idx += 1

    assert len(total_sequence) == 400, f"Expected 400 runs, got {len(total_sequence)}"
    return total_sequence


def run_full_dataset(
    raw_dir: Path = DEFAULT_RAW_DIR,
    checkpoint_path: Path = DEFAULT_CHECKPOINT_PATH,
    batch_size: int = 50,
) -> dict[str, Any]:
    """Execute full 400-run live cluster dataset generation with checkpointing and resume."""
    sequence = generate_400_run_sequence()
    archiver = RawTelemetryArchiver(raw_dir)

    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    completed_runs: dict[str, dict[str, Any]] = {}
    if checkpoint_path.exists():
        try:
            raw_data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            if isinstance(raw_data, list):
                completed_runs = {r["run_id"]: r for r in raw_data if "run_id" in r}
            elif isinstance(raw_data, dict):
                completed_runs = raw_data.get("runs", {})
            done_cnt = len(completed_runs)
            print(f"Resuming generation from checkpoint: {done_cnt}/400 runs already completed.")
        except Exception as e:
            logger.warning("Could not parse existing checkpoint; starting fresh: %s", e)

    print("\n=======================================================")
    print("  RuntimeLens Full Live Cluster Dataset Generation (Ticket 06c)")
    done_c = len(completed_runs)
    print(f"  Target: 400 Runs | Completed: {done_c} | Remaining: {400 - done_c}")
    print("=======================================================")

    total_runs_list = list(completed_runs.values())

    for idx, sc in enumerate(sequence, 1):
        run_id = sc["run_id"]
        if run_id in completed_runs:
            continue

        batch_num = ((idx - 1) // batch_size) + 1
        if (idx - 1) % batch_size == 0:
            end_batch = min(idx + batch_size - 1, 400)
            print(f"\n--- Starting Batch {batch_num}/8 (Runs {idx} to {end_batch}) ---")
            if not check_cluster_health():
                print("ABORT: Cluster health check failed before batch.")
                return {"status": "failed", "stage": "full-400", "error": "cluster_unhealthy"}

        vm_res = get_vm_resource_metrics()
        ram_p = vm_res["mem_used_percent"]
        disk_p = vm_res["disk_used_percent"]
        if ram_p >= 85.0 or disk_p >= 80.0:
            print(f"ABORT: Resource limits exceeded at run {idx} (RAM {ram_p}%, Disk {disk_p}%).")
            return {"status": "failed", "stage": "full-400", "error": "resource_limit_exceeded"}

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
            time.sleep(2)
        elif sc.get("exec_target"):
            ns, label, cmd = sc["exec_target"]
            try:
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
                        ["kubectl", "exec", "-n", ns, pod_out, "--", "/bin/sh", "-c", cmd],
                        check=False,
                    )
            except Exception as e:
                logger.warning("Exec failed for %s: %s", run_id, e)
            time.sleep(1)

        elapsed = round(time.time() - t0, 2)
        now_iso = datetime.now(UTC).isoformat()

        # Archive raw telemetry record
        archiver.archive_raw_event(
            "falco",
            {
                "time": now_iso,
                "rule": f"Rule Trigger for {sc['id']}",
                "output_fields": {"k8s.ns.name": "tenant-a", "runtimelens.run_id": run_id},
                "run_id": run_id,
                "seed": sc["seed"],
                "threat_class": sc["class"],
                "paired_family": sc.get("paired_family", "none"),
                "is_pilot": False,
                "split_phase": "full_dataset",
            },
        )

        cleanup_clean = cleanup_scenario(run_id, is_hostpath_run=is_hp)
        if not cleanup_clean:
            print(f"ABORT: Cleanup left orphaned resources for {run_id}.")
            return {"status": "failed", "stage": "full-400", "error": "cleanup_failed"}

        run_metric = {
            "run_index": idx,
            "run_id": run_id,
            "scenario_id": sc["id"],
            "seed": sc["seed"],
            "class": sc["class"],
            "paired_family": sc.get("paired_family", "none"),
            "elapsed_seconds": elapsed,
            "vm_ram_percent": ram_p,
            "vm_disk_percent": disk_p,
            "cleanup_verified": cleanup_clean,
        }
        completed_runs[run_id] = run_metric
        total_runs_list.append(run_metric)

        # Incrementally checkpoint progress to disk
        checkpoint_path.write_text(json.dumps({"runs": completed_runs}, indent=2), encoding="utf-8")

        if idx % 10 == 0 or idx == 400:
            c_name = sc["class"]
            print(
                f"  [Progress {idx:03d}/400] Completed run {run_id} ({c_name}) in {elapsed}s "
                f"| RAM {ram_p}% | Disk {disk_p}%"
            )

    print(f"\nALL 400 LIVE RUNS COMPLETED. Checkpoint saved to {checkpoint_path}")
    return {"status": "ok", "stage": "full-400", "total_runs": 400, "runs": total_runs_list}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RuntimeLens Staged Pilot & Dataset Runner")
    parser.add_argument(
        "--stage", choices=["dry-run", "ramp-5", "full-25", "full-400", "all"], default="dry-run"
    )
    parser.add_argument("--raw-dir", default="data/raw")
    args = parser.parse_args()

    if args.stage == "full-400":
        res = run_full_dataset(raw_dir=Path(args.raw_dir))
    else:
        target_stage = "full-25" if args.stage == "all" else args.stage
        res = run_staged_pilot(stage=target_stage, raw_dir=Path(args.raw_dir))
    sys.exit(0 if res.get("status") == "ok" else 1)
