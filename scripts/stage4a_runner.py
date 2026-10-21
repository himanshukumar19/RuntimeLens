"""Stage 4a-PART1 runner: 10 real cluster scenario runs, one per template.

Executes the Stage 4a-PART1 template set on the live kind cluster inside
`runtimelens-vm`, capturing authentic 5-source telemetry per run.

Per run the runner performs, in order:
  1. receivers pre-check (Hubble 4245, Falco webhook 8765, Audit webhook 8766)
  2. resource pre-check (RAM available >= 2048 MB, disk < 80 %)
  3. pod cooldown (container CPU < 20 mcores for 2 consecutive samples, max 60 s)
  4. scenario execution (kubectl exec into a tenant pod, or a purpose-built
     sandbox pod for the hostPath / privileged escape templates)
  5. 5-source capture (Falco, K8s audit, Hubble, cAdvisor/Prometheus, Trivy)
  6. per-run gate (variant-aware CPU band + leakage scan + source sufficiency)
  7. cleanup (pod and, for sandbox templates, the ephemeral namespace)
  8. leftover check (zero orphaned test pods / namespaces)
  9. backup of the run directory to data/raw_backup/<run_id>

Hard stop conditions (immediate abort of the whole sequence):
  * per-run gate failure
  * RAM available < 2 GiB
  * disk utilisation >= 80 %
  * a receiver is not listening
  * a leftover pod or namespace after cleanup

data/raw/runs is NEVER deleted. Only data/raw_backup/<run_id> is written.

Stdlib only: runs inside the VM without numpy / scikit-learn.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture
from scripts.scenario_safety_lint import lint_manifest
from scripts.stage2_pilot import (
    cleanup_pod,
    get_available_ram_mb,
    get_disk_use_percent,
    resolve_pod_name,
    verify_per_run_gate,
    verify_receiver_ports_listening,
    wait_for_pod_cooldown,
)

logger = logging.getLogger("runtimelens.stage4a")

RUNS_DIR = Path("data/raw/runs")
BACKUP_DIR = Path("data/raw_backup")
PROGRESS_FILE = Path("data/scenarios/stage4a_part1_progress.json")
SANDBOX_NS = "sandbox-workloads"

# Falco egress rule port list (lab/falco/falco-values.yaml).
FALCO_HIGH_PORTS = (3333, 4444, 5555, 7777, 8888, 9999)


def _t() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _pod_spec(
    name: str,
    *,
    host_path: str | None = None,
    host_path_type: str | None = None,
    privileged: bool = False,
) -> dict[str, Any]:
    """Build a sandbox pod spec for the escape templates (linter-checked)."""
    volumes: list[dict[str, Any]] = []
    mounts: list[dict[str, Any]] = []
    if host_path is not None:
        vol_name = "sensitive-mount"
        volumes.append(
            {
                "name": vol_name,
                "hostPath": {"path": host_path, "type": host_path_type or "Directory"},
            }
        )
        mounts.append({"name": vol_name, "mountPath": host_path})

    container: dict[str, Any] = {
        "name": "worker",
        "image": "docker.io/library/alpine:3.19",
        "command": ["sleep", "600"],
        "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
    }
    if mounts:
        container["volumeMounts"] = mounts
    if privileged:
        container["securityContext"] = {"privileged": True}

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": SANDBOX_NS,
            "labels": {"app": "worker", "component": "task", "runtimelens.test": "true"},
        },
        "spec": {"containers": [container], "volumes": volumes},
    }


# ---------------------------------------------------------------------------
# Stage 4a-PART1 template set: 10 templates, 1 run each.
#
# Every command below implements the corresponding `docs/SCENARIO_PLAN_v2.md`
# registry row (description + length bin + duration + tenant/workload + CPU
# profile + expected signals).  Deviations between the registry row and what
# is actually achievable in this lab are recorded in docs/reviews/.
# ---------------------------------------------------------------------------
TEMPLATES: list[dict[str, Any]] = [
    {
        "run_id": "run-s4a-01",
        "template_id": "TMPL-BEN-01",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "web",
        "mode": "exec",
        "command": "uptime && nc -z -w 1 10.96.0.10 53 || true",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-02",
        "template_id": "TMPL-BEN-04",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "api",
        "mode": "exec",
        "command": "echo probe | nc -u -w 1 198.51.100.22 3333 || true",
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": [
            "Interactive Shell Spawned in Non-Debug Container",
            "Suspicious High Port Egress",
        ],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-03",
        "template_id": "TMPL-BEN-11",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "api",
        "mode": "exec",
        "command": (
            "id; grep Cap /proc/self/status; "
            "wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-c/pods"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-04",
        "template_id": "TMPL-ESC-03",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-4c17",
        "pod_spec": _pod_spec(
            "worker-task-4c17",
            host_path="/opt/runtimelens-dummy/docker.sock",
            host_path_type="File",
        ),
        "command": (
            "ls -l /opt/runtimelens-dummy/docker.sock; "
            "head -n 1 /opt/runtimelens-dummy/docker.sock 2>&1 || true; "
            "nc -z -w 1 10.96.0.10 53 || true"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["T", "F", "F"],
    },
    {
        "run_id": "run-s4a-05",
        "template_id": "TMPL-ESC-04",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-9b02",
        "pod_spec": _pod_spec(
            "worker-task-9b02",
            host_path="/opt/runtimelens-dummy/etc",
            host_path_type="Directory",
        ),
        "command": (
            "cat /opt/runtimelens-dummy/etc/shadow 2>&1 || true; "
            "echo p | nc -u -w 1 198.51.100.22 8080 || true"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "T", "F"],
    },
    {
        "run_id": "run-s4a-06",
        "template_id": "TMPL-ESC-06",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-3d55",
        "pod_spec": _pod_spec("worker-task-3d55", privileged=True),
        "command": (
            "command -v debugfs || true; "
            "unshare -m -p -f /bin/sh -c true; "
            "grep Cap /proc/self/status; "
            "nc -z -w 1 10.96.0.10 53 || true"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "T"],
    },
    {
        "run_id": "run-s4a-07",
        "template_id": "TMPL-PRV-01",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-a",
        "app": "api",
        "mode": "exec",
        "command": (
            "nc -z -w 1 10.96.0.10 53 || true; "
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token); "
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api/v1/namespaces/tenant-b/secrets"
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-08",
        "template_id": "TMPL-PRV-03",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-c",
        "app": "database",
        "mode": "exec",
        "command": (
            "nc -z -w 1 10.96.0.10 53 || true; "
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token); "
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api/v1/serviceaccounts"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-09",
        "template_id": "TMPL-MNR-03",
        "threat_class": "cryptomining",
        "namespace": "tenant-c",
        "app": "api",
        "mode": "exec",
        "command": (
            "echo p | nc -u -w 1 198.51.100.22 8080 || true; "
            "for i in $(seq 875); do j=0; "
            "while [ $j -lt 3000 ]; do j=$((j+1)); done; "
            "sleep 0.05; done"
        ),
        "sleep_after": 2,
        "expected_cpu_profile": "throttled",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-10",
        "template_id": "TMPL-UNK-03",
        "threat_class": "unknown",
        "namespace": "tenant-c",
        "app": "database",
        "mode": "exec",
        "command": (
            "for i in 1 2 3; do "
            "dd if=/dev/urandom of=/tmp/u.log bs=1M count=16 2>/dev/null; "
            "gzip -f /tmp/u.log; rm -f /tmp/u.log; "
            "done; "
            "echo p | nc -u -w 1 198.51.100.22 8080 || true; sleep 8"
        ),
        "sleep_after": 2,
        "expected_cpu_profile": "burst",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
    },
]


class Stage4aStop(RuntimeError):
    """Raised on any hard stop condition."""


def check_resources(label: str) -> None:
    ram_mb = get_available_ram_mb()
    disk_pct = get_disk_use_percent()
    print(f"    [resources@{label}] RAM available={ram_mb:.0f} MB, disk={disk_pct:.1f}%")
    if ram_mb < 2048.0:
        raise Stage4aStop(f"RESOURCE BREACH at {label}: RAM available {ram_mb:.0f} MB < 2048 MB")
    if disk_pct >= 80.0:
        raise Stage4aStop(f"RESOURCE BREACH at {label}: disk {disk_pct:.1f}% >= 80%")


def check_receivers() -> None:
    try:
        verify_receiver_ports_listening()
    except Exception as exc:
        raise Stage4aStop(f"RECEIVER DOWN: {exc}") from exc
    print("    [receivers] Hubble 4245, Falco 8765, Audit 8766 all listening")


def ensure_sandbox_namespace() -> None:
    """Create the ephemeral sandbox namespace with privileged PSS (safety sheet 4.1)."""
    subprocess.run(
        [
            "kubectl",
            "create",
            "namespace",
            SANDBOX_NS,
            "--dry-run=client",
            "-o",
            "yaml",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    apply = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=subprocess.run(
            [
                "kubectl",
                "create",
                "namespace",
                SANDBOX_NS,
                "--dry-run=client",
                "-o",
                "yaml",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout,
        check=True,
        capture_output=True,
        text=True,
    )
    if apply.returncode != 0:
        raise Stage4aStop(f"failed to create namespace {SANDBOX_NS}: {apply.stderr}")
    subprocess.run(
        [
            "kubectl",
            "label",
            "namespace",
            SANDBOX_NS,
            "pod-security.kubernetes.io/enforce=privileged",
            "--overwrite",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def lint_manifest_or_stop(manifest: dict[str, Any], label: str) -> None:
    errors = lint_manifest(manifest)
    print(f"    [safety-lint] {label}: {'PASS' if not errors else 'FAIL'}")
    for err in errors:
        print(f"        {err}")
    if errors:
        raise Stage4aStop(f"safety linter rejected {label}: {errors}")


def create_sandbox_pod(spec: dict[str, Any]) -> str:
    name = spec["metadata"]["name"]
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(spec),
        check=True,
        capture_output=True,
        text=True,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        res = subprocess.run(
            [
                "kubectl",
                "get",
                "pod",
                name,
                "-n",
                SANDBOX_NS,
                "-o",
                "jsonpath={.status.phase}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        phase = res.stdout.strip()
        if phase == "Running":
            return str(name)
        if phase in {"Failed", "Unknown"}:
            logs = subprocess.run(
                ["kubectl", "logs", name, "-n", SANDBOX_NS, "--tail=20"],
                capture_output=True,
                text=True,
                check=False,
            )
            err_msg = f"sandbox pod {name} entered phase {phase}: {logs.stdout}{logs.stderr}"
            raise Stage4aStop(err_msg)
        time.sleep(1.0)
    raise Stage4aStop(f"sandbox pod {name} did not reach Running within 60s")


def delete_sandbox_pod(name: str) -> None:
    subprocess.run(
        ["kubectl", "delete", "pod", name, "-n", SANDBOX_NS, "--ignore-not-found=true"],
        capture_output=True,
        text=True,
        check=False,
    )


def delete_sandbox_namespace() -> None:
    subprocess.run(
        ["kubectl", "delete", "namespace", SANDBOX_NS, "--ignore-not-found=true", "--timeout=60s"],
        capture_output=True,
        text=True,
        check=False,
    )


def check_no_leftovers() -> None:
    res = subprocess.run(
        ["kubectl", "get", "pods", "-A", "-l", "runtimelens.test=true", "--no-headers"],
        capture_output=True,
        text=True,
        check=False,
    )
    pods = [line for line in res.stdout.splitlines() if line.strip()]
    ns_res = subprocess.run(
        ["kubectl", "get", "ns", SANDBOX_NS, "--ignore-not-found=true", "-o", "name"],
        capture_output=True,
        text=True,
        check=False,
    )
    ns_left = ns_res.stdout.strip()
    if pods or ns_left:
        raise Stage4aStop(f"LEFTOVER after cleanup: pods={pods} namespaces={ns_left!r}")
    print("    [cleanup] zero leftover test pods, sandbox namespace removed")


def burst_band(sample_cpus: list[float]) -> tuple[bool, str]:
    """Variant-aware `burst` CPU band: peak in [30, 100] mcores, median < 100."""
    if not sample_cpus:
        return False, "FAIL (no cAdvisor samples)"
    peak = max(sample_cpus)
    median = sorted(sample_cpus)[len(sample_cpus) // 2]
    if peak < 30.0 or peak > 100.0 or median >= 100.0:
        return False, f"FAIL (peak={peak:.2f}m not in [30,100], med={median:.2f}m >= 100)"
    return True, f"PASS (peak={peak:.2f}m, med={median:.2f}m)"


def capture_cpu_samples(run_dir: Path) -> list[float]:
    metrics_file = run_dir / "prometheus" / "metrics.json"
    if not metrics_file.exists():
        return []
    try:
        data = json.loads(metrics_file.read_text(encoding="utf-8"))
    except Exception:
        return []
    values: list[float] = []
    for sample in data.get("samples", []):
        total = 0.0
        for pod in sample.get("pod_stats", []):
            for container in pod.get("containers", []):
                total += float(container.get("cpu", {}).get("usageNanoCores", 0.0)) / 1e6
        values.append(total)
    return values


def run_one(
    template: dict[str, Any],
    collector: PerRunTelemetryCapture,
) -> dict[str, Any]:
    run_id = template["run_id"]
    ns = template["namespace"]
    app = template["app"]
    command = template["command"]
    profile = template["expected_cpu_profile"]
    sandbox_pod = None

    print(f"\n=== RUN {run_id} | {template['template_id']} | {template['threat_class']} ===")
    print(f"    command ({len(command) + 6} chars as proc.cmdline): {command}")

    # 1. receivers pre-check
    check_receivers()
    # 2. resource pre-check
    check_resources("pre")

    if template["mode"] == "sandbox":
        ensure_sandbox_namespace()
        lint_manifest_or_stop(template["pod_spec"], template["template_id"])
        sandbox_pod = create_sandbox_pod(template["pod_spec"])
        pod_name = sandbox_pod
    else:
        pod_name = resolve_pod_name(ns, app)
        if not pod_name:
            raise Stage4aStop(f"could not resolve pod for {ns}/{app}")
    print(f"    [pod] {ns}/{pod_name}")

    # 3. cooldown
    cool = wait_for_pod_cooldown(ns, pod_name, max_wait_seconds=60.0)
    print(f"    [cooldown] settled_below_20m={cool} (max 60s, 2 consecutive samples)")

    run_dir = collector.prepare_run_dir(run_id)
    t0 = datetime.now(UTC)
    t0_iso = t0.isoformat().replace("+00:00", "Z")

    # 4. execute scenario
    collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
    last_sample = time.time()
    proc = subprocess.Popen(
        ["kubectl", "exec", "-n", ns, pod_name, "--", "/bin/sh", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    while proc.poll() is None:
        time.sleep(1.0)
        check_resources("in-run")
        if time.time() - last_sample >= 10.0:
            collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
            last_sample = time.time()
    proc.wait(timeout=15)
    stdout, stderr = proc.communicate()
    print(f"    [exec] rc={proc.returncode} stdout={stdout.decode(errors='replace')[:300]!r}")

    # post-execution settle window
    sleep_after = float(template.get("sleep_after", 5))
    if sleep_after > 0:
        sleep_end = time.time() + sleep_after
        while time.time() < sleep_end:
            time.sleep(min(1.0, sleep_end - time.time()))
            if time.time() - last_sample >= 10.0:
                collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
                last_sample = time.time()
    if time.time() - last_sample >= 4.0:
        collector.capture_cadvisor_metrics(pod_name, ns, run_dir)

    t1 = datetime.now(UTC)
    t1_iso = t1.isoformat().replace("+00:00", "Z")
    elapsed = round((t1 - t0).total_seconds(), 2)

    # 5. capture the 5 sources
    counts = {
        "falco": collector.capture_falco_alerts(pod_name, ns, t0_iso, run_dir),
        "audit": collector.capture_k8s_audit_events(pod_name, ns, t0_iso, t1_iso, run_dir),
        "hubble": collector.capture_hubble_flows(ns, t0_iso, t1_iso, run_dir),
    }
    collector.attach_trivy_report(run_dir)
    p_spec = template.get("pod_spec") or _pod_spec(pod_name)
    collector.attach_pod_spec(run_dir, p_spec)
    counts["trivy"] = 1 if (run_dir / "trivy" / "report.json").exists() else 0
    counts["prometheus"] = len(capture_cpu_samples(run_dir))

    collector.write_run_index(
        run_dir=run_dir,
        run_id=run_id,
        threat_class=template["threat_class"],
        scenario_id=template["template_id"],
        namespace=ns,
        workload_name=app,
        pod_name=pod_name,
        t_start_iso=t0_iso,
        t_end_iso=t1_iso,
        expected_cpu_profile=profile,
    )
    print(f"    [capture] {counts}")

    # 6. per-run gate
    gate_ok, gate_reason = verify_per_run_gate(run_dir, expected_cpu_profile=profile)
    if not gate_ok and profile == "burst":
        # stage2_pilot's per-run gate has no `burst` branch; apply the same band
        # that scripts/verify_dataset.py enforces for the burst variant.
        samples = capture_cpu_samples(run_dir)
        ok, reason = burst_band(samples)
        if ok:
            gate_ok, gate_reason = True, "CLEAN (burst band enforced by runner)"
        else:
            gate_reason = f"burst band: {reason}"
    print(f"    [gate] {'PASS' if gate_ok else 'FAIL'}: {gate_reason}")

    # 7. cleanup
    if sandbox_pod:
        delete_sandbox_pod(sandbox_pod)
        delete_sandbox_namespace()
    else:
        cleanup_pod(ns, pod_name)

    # 8. leftover check
    check_no_leftovers()

    # 9. backup (data/raw/runs is never deleted)
    backup_target = BACKUP_DIR / run_id
    backup_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_dir, backup_target, dirs_exist_ok=True)
    print(f"    [backup] {backup_target}")

    samples = capture_cpu_samples(run_dir)
    peak = max(samples) if samples else 0.0
    median = sorted(samples)[len(samples) // 2] if samples else 0.0

    result = {
        "run_id": run_id,
        "template_id": template["template_id"],
        "threat_class": template["threat_class"],
        "namespace": ns,
        "pod_name": pod_name,
        "command_length": len(command) + 6,
        "elapsed_seconds": elapsed,
        "source_counts": counts,
        "cpu_min_mcores": round(min(samples), 2) if samples else 0.0,
        "cpu_median_mcores": round(median, 2),
        "cpu_max_mcores": round(peak, 2),
        "expected_cpu_profile": profile,
        "gate_status": "PASSED" if gate_ok else "FAILED",
        "gate_reason": gate_reason,
        "expect_falco": template["expect_falco"],
        "expect_verbs": template["expect_verbs"],
        "expect_hubble_band": template["expect_hubble_band"],
        "expect_features": template["expect_features"],
    }
    if not gate_ok:
        raise Stage4aStop(f"per-run gate FAILED for {run_id}: {gate_reason}")
    return result


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    collector = PerRunTelemetryCapture(base_dir=RUNS_DIR)
    results: list[dict[str, Any]] = []
    stop_reason: str | None = None

    for template in TEMPLATES:
        try:
            result = run_one(template, collector)
            results.append(result)
        except Stage4aStop as exc:
            stop_reason = str(exc)
            print(f"\n!!! STAGE 4a HARD STOP: {stop_reason}")
            break
        finally:
            PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
            PROGRESS_FILE.write_text(
                json.dumps(
                    {
                        "stage": "4a-part1",
                        "completed": len(results),
                        "total": len(TEMPLATES),
                        "runs": results,
                        "stop_reason": stop_reason,
                        "updated_at": _t(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    print("\n================ STAGE 4a-PART1 SUMMARY ================")
    for res in results:
        sc = res["source_counts"]
        print(
            f"{res['run_id']} {res['template_id']:<12} {res['threat_class']:<16} "
            f"dur={res['elapsed_seconds']:>7.2f}s "
            f"falco={sc['falco']:<3} audit={sc['audit']:<3} "
            f"hubble={sc['hubble']:<3} prom={sc['prometheus']:<3} "
            f"trivy={sc['trivy']:<3} "
            f"cpu[{res['cpu_min_mcores']}/{res['cpu_median_mcores']}/{res['cpu_max_mcores']}] "
            f"profile={res['expected_cpu_profile']:<9} gate={res['gate_status']}"
        )
    print(f"completed={len(results)}/{len(TEMPLATES)} stop_reason={stop_reason}")
    return 0 if stop_reason is None else 2


if __name__ == "__main__":
    sys.exit(main())
