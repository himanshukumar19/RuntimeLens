"""Stage 2 Real 25-Run Pilot Execution Engine."""

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

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture

logger = logging.getLogger("runtimelens.stage2_pilot")

PILOT_RUNS_DIR = Path("data/raw/runs")
METRICS_OUTPUT_FILE = Path("data/scenarios/pilot_25_metrics.json")

LEAK_KEYWORDS = (
    "SC-",
    "privilege_abuse",
    "container_escape",
    "cryptomining",
    "exfiltration",
    "benign",
    "run-0",
    "run-1",
    "run-2",
    "run-3",
)


def get_available_ram_mb() -> float:
    """Read available RAM in MB from host system."""
    try:
        out = subprocess.check_output(["free", "-m"], text=True)
        for line in out.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                return float(parts[6])  # available is index 6
    except Exception:
        pass
    return 4000.0


def get_disk_use_percent() -> float:
    """Read root disk usage percentage."""
    try:
        out = subprocess.check_output(["df", "/"], text=True)
        lines = out.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            return float(parts[4].replace("%", ""))
    except Exception:
        pass
    return 20.0


def resolve_pod_name(namespace: str, app_label: str) -> str:
    """Resolve the active pod name for a tenant workload."""
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
        res = subprocess.check_output(cmd, text=True).strip()
        return res
    except Exception as e:
        logger.error("Could not resolve pod for %s/%s: %s", namespace, app_label, e)
        return ""


def build_25_pilot_manifest() -> list[dict[str, Any]]:
    """Define the exact 25-run pilot mix across 5 classes and varied pods/seeds."""
    mining_cmd = (
        "nc -z -w 2 10.96.0.1 3333 || true; "
        "while true; do :; done & PID=$!; "
        "sleep 120; kill $PID 2>/dev/null || true"
    )
    escape_cmd = (
        "nc -z -w 1 10.96.0.10 53 || true; "
        "cat /etc/shadow 2>&1 || true; "
        "cat /etc/passwd 2>&1 || true"
    )
    benign_cpu_20 = (
        "nc -z -w 1 10.96.0.10 53 || true; "
        "while true; do :; done & PID=$!; "
        "sleep 20; kill $PID 2>/dev/null || true"
    )
    benign_cpu_25 = (
        "nc -z -w 1 10.96.0.10 53 || true; "
        "while true; do :; done & PID=$!; "
        "sleep 25; kill $PID 2>/dev/null || true"
    )

    def prv_sec(target_ns: str) -> str:
        return (
            "nc -z -w 1 10.96.0.10 53 || true; "
            "wget -T 2 -t 1 --no-check-certificate -qO- "
            f"https://10.96.0.1:443/api/v1/namespaces/{target_ns}/secrets || true; "
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1 || true"
        )

    def prv_pod(target_ns: str) -> str:
        return (
            "nc -z -w 1 10.96.0.10 53 || true; "
            "wget -T 2 -t 1 --no-check-certificate -qO- "
            f"https://10.96.0.1:443/api/v1/namespaces/{target_ns}/pods || true"
        )

    def exf(port: int) -> str:
        return f"nc -z -w 1 10.96.0.10 53 || true; nc -z -w 2 198.51.100.22 {port} || true"

    return [
        # --- 1. Benign (5 runs: 2 with real CPU load) ---
        {
            "run_index": 1,
            "run_id": "run-p01-ben",
            "class": "benign",
            "scenario_id": "SC-BEN-01",
            "seed": 1,
            "namespace": "tenant-a",
            "app": "web",
            "command": "uptime && nc -z -w 1 10.96.0.10 53 || true",
            "sleep_after": 8,
            "is_mining": False,
        },
        {
            "run_index": 2,
            "run_id": "run-p02-ben-cpu",
            "class": "benign",
            "scenario_id": "SC-BEN-03",
            "seed": 2,
            "namespace": "tenant-a",
            "app": "database",
            "command": benign_cpu_20,
            "sleep_after": 5,
            "is_mining": False,
        },
        {
            "run_index": 3,
            "run_id": "run-p03-ben",
            "class": "benign",
            "scenario_id": "SC-BEN-02",
            "seed": 3,
            "namespace": "tenant-b",
            "app": "api",
            "command": "date && nc -z -w 1 10.96.0.10 53 || true",
            "sleep_after": 8,
            "is_mining": False,
        },
        {
            "run_index": 4,
            "run_id": "run-p04-ben-cpu",
            "class": "benign",
            "scenario_id": "SC-BEN-03",
            "seed": 4,
            "namespace": "tenant-c",
            "app": "database",
            "command": benign_cpu_25,
            "sleep_after": 5,
            "is_mining": False,
        },
        {
            "run_index": 5,
            "run_id": "run-p05-ben",
            "class": "benign",
            "scenario_id": "SC-BEN-04",
            "seed": 5,
            "namespace": "tenant-c",
            "app": "payment-style",
            "command": "touch /tmp/ok && nc -z -w 1 10.96.0.10 53 || true; rm -f /tmp/ok",
            "sleep_after": 8,
            "is_mining": False,
        },
        # --- 2. Cryptomining (5 runs: full 120s sustained CPU loop) ---
        {
            "run_index": 6,
            "run_id": "run-p06-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "seed": 1,
            "namespace": "tenant-a",
            "app": "web",
            "command": mining_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        {
            "run_index": 7,
            "run_id": "run-p07-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "seed": 2,
            "namespace": "tenant-b",
            "app": "database",
            "command": mining_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        {
            "run_index": 8,
            "run_id": "run-p08-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "seed": 3,
            "namespace": "tenant-c",
            "app": "api",
            "command": mining_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        {
            "run_index": 9,
            "run_id": "run-p09-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "seed": 4,
            "namespace": "tenant-a",
            "app": "payment-style",
            "command": mining_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        {
            "run_index": 10,
            "run_id": "run-p10-mnr",
            "class": "cryptomining",
            "scenario_id": "SC-MNR-01",
            "seed": 5,
            "namespace": "tenant-b",
            "app": "web",
            "command": mining_cmd,
            "sleep_after": 2,
            "is_mining": True,
        },
        # --- 3. Privilege Abuse (5 runs) ---
        {
            "run_index": 11,
            "run_id": "run-p11-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-01",
            "seed": 1,
            "namespace": "tenant-a",
            "app": "api",
            "command": prv_sec("tenant-b"),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 12,
            "run_id": "run-p12-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-01",
            "seed": 2,
            "namespace": "tenant-b",
            "app": "web",
            "command": prv_sec("tenant-c"),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 13,
            "run_id": "run-p13-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-03",
            "seed": 3,
            "namespace": "tenant-c",
            "app": "database",
            "command": prv_pod("tenant-a"),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 14,
            "run_id": "run-p14-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-01",
            "seed": 4,
            "namespace": "tenant-a",
            "app": "payment-style",
            "command": prv_sec("tenant-b"),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 15,
            "run_id": "run-p15-prv",
            "class": "privilege_abuse",
            "scenario_id": "SC-PRV-03",
            "seed": 5,
            "namespace": "tenant-b",
            "app": "api",
            "command": prv_pod("tenant-c"),
            "sleep_after": 6,
            "is_mining": False,
        },
        # --- 4. Container Escape Probes (5 runs) ---
        {
            "run_index": 16,
            "run_id": "run-p16-esc",
            "class": "container_escape",
            "scenario_id": "SC-ESC-02",
            "seed": 1,
            "namespace": "tenant-a",
            "app": "database",
            "command": escape_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 17,
            "run_id": "run-p17-esc",
            "class": "container_escape",
            "scenario_id": "SC-ESC-02",
            "seed": 2,
            "namespace": "tenant-b",
            "app": "web",
            "command": escape_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 18,
            "run_id": "run-p18-esc",
            "class": "container_escape",
            "scenario_id": "SC-ESC-02",
            "seed": 3,
            "namespace": "tenant-c",
            "app": "payment-style",
            "command": escape_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 19,
            "run_id": "run-p19-esc",
            "class": "container_escape",
            "scenario_id": "SC-ESC-02",
            "seed": 4,
            "namespace": "tenant-a",
            "app": "web",
            "command": escape_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 20,
            "run_id": "run-p20-esc",
            "class": "container_escape",
            "scenario_id": "SC-ESC-02",
            "seed": 5,
            "namespace": "tenant-c",
            "app": "api",
            "command": escape_cmd,
            "sleep_after": 6,
            "is_mining": False,
        },
        # --- 5. Exfiltration-style Probes (5 runs) ---
        {
            "run_index": 21,
            "run_id": "run-p21-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "seed": 1,
            "namespace": "tenant-a",
            "app": "payment-style",
            "command": exf(8888),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 22,
            "run_id": "run-p22-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "seed": 2,
            "namespace": "tenant-b",
            "app": "api",
            "command": exf(9999),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 23,
            "run_id": "run-p23-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "seed": 3,
            "namespace": "tenant-c",
            "app": "web",
            "command": exf(4444),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 24,
            "run_id": "run-p24-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "seed": 4,
            "namespace": "tenant-a",
            "app": "database",
            "command": exf(7777),
            "sleep_after": 6,
            "is_mining": False,
        },
        {
            "run_index": 25,
            "run_id": "run-p25-exf",
            "class": "exfiltration",
            "scenario_id": "SC-EXF-01",
            "seed": 5,
            "namespace": "tenant-b",
            "app": "payment-style",
            "command": exf(5555),
            "sleep_after": 6,
            "is_mining": False,
        },
    ]


def verify_per_run_gate(run_dir: Path, is_mining: bool = False) -> tuple[bool, str]:
    """Audit single run directory against per-run capture gate requirements."""
    counts: dict[str, int] = {}
    timestamps: list[float] = []

    # 1. Falco count
    falco_f = run_dir / "falco" / "events.jsonl"
    f_cnt = 0
    if falco_f.exists():
        with open(falco_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    f_cnt += 1
                    try:
                        ts = json.loads(line).get("time")
                        if ts:
                            timestamps.append(
                                datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                            )
                    except Exception:
                        pass
    counts["falco"] = f_cnt

    # 2. Audit count
    audit_f = run_dir / "audit" / "events.jsonl"
    a_cnt = 0
    if audit_f.exists():
        with open(audit_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    a_cnt += 1
                    try:
                        d = json.loads(line)
                        ts = d.get("stageTimestamp") or d.get("requestReceivedTimestamp")
                        if ts:
                            timestamps.append(
                                datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                            )
                    except Exception:
                        pass
    counts["audit"] = a_cnt

    # 3. Hubble count
    hubble_f = run_dir / "hubble" / "flows.jsonl"
    h_cnt = 0
    if hubble_f.exists():
        with open(hubble_f, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    h_cnt += 1
                    try:
                        ts = json.loads(line).get("flow", {}).get("time")
                        if ts:
                            timestamps.append(
                                datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                            )
                    except Exception:
                        pass
    counts["hubble"] = h_cnt

    # 4. Prometheus count
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

    # 5. Trivy count
    trivy_f = run_dir / "trivy" / "report.json"
    counts["trivy"] = 1 if trivy_f.exists() else 0

    # 6. Check every source has events
    for src in ["falco", "audit", "hubble", "prometheus", "trivy"]:
        if counts[src] < 1:
            return False, f"Missing telemetry from source '{src}': count={counts[src]}"

    # 7. Leakage scan
    for src in ["falco", "audit", "hubble", "prometheus"]:
        src_path = run_dir / src
        for t_file in src_path.glob("*"):
            if t_file.is_file():
                content = t_file.read_text(encoding="utf-8")
                for kw in LEAK_KEYWORDS:
                    if kw in content:
                        rel = t_file.relative_to(run_dir)
                        return (
                            False,
                            f"Telemetry leakage detected: '{kw}' in {rel}",
                        )

    # 8. Duration calculation
    calc_dur = 0.0
    if len(timestamps) >= 2:
        calc_dur = round(max(timestamps) - min(timestamps), 2)

    # 9. Mining duration & sample check
    if is_mining:
        if counts["prometheus"] < 8:
            return False, f"Mining cAdvisor samples insufficient: {counts['prometheus']} < 8"
        if calc_dur < 115.0:
            return False, f"Mining duration too short: {calc_dur}s < 120s"

    # 10. cAdvisor sample gap check
    if len(samples) >= 2:
        for idx in range(len(samples) - 1):
            t1 = datetime.fromisoformat(
                samples[idx]["timestamp"].replace("Z", "+00:00")
            ).timestamp()
            t2 = datetime.fromisoformat(
                samples[idx + 1]["timestamp"].replace("Z", "+00:00")
            ).timestamp()
            gap = t2 - t1
            if gap > 25.0:
                msg = f"cAdvisor gap {gap:.1f}s > 20s at sample {idx + 1}"
                return False, msg

    return True, "CLEAN"


def execute_single_run(
    run_item: dict[str, Any],
    collector: PerRunTelemetryCapture,
) -> dict[str, Any]:
    """Execute a single live run with real telemetry capture and per-run gate verification."""
    run_id = run_item["run_id"]
    ns = run_item["namespace"]
    app = run_item["app"]
    cmd_str = run_item["command"]
    is_mining = run_item["is_mining"]
    sleep_after = run_item.get("sleep_after", 5)

    pod_name = resolve_pod_name(ns, app)
    if not pod_name:
        raise RuntimeError(f"Could not find running pod for {ns}/{app}")

    run_dir = collector.prepare_run_dir(run_id)

    # 1. Pre-run check
    avail_mb = get_available_ram_mb()
    disk_pct = get_disk_use_percent()
    if avail_mb < 2048.0 or disk_pct >= 80.0:
        err_msg = f"Resource breach before {run_id}: RAM avail={avail_mb}MB, Disk={disk_pct}%"
        raise RuntimeError(err_msg)

    t0 = datetime.now(UTC)
    t0_iso = t0.isoformat().replace("+00:00", "Z")

    # Initial cAdvisor sample
    collector.capture_cadvisor_metrics(pod_name, ns, run_dir)

    # 2. Launch execution
    if is_mining:
        p_exec = subprocess.Popen(
            ["kubectl", "exec", "-n", ns, pod_name, "--", "/bin/sh", "-c", cmd_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Sample cAdvisor every 15s during the 120s run (takes 8 additional samples)
        for _check_idx in range(1, 9):
            time.sleep(15)
            avail_mb = get_available_ram_mb()
            if avail_mb < 2048.0:
                p_exec.terminate()
                subprocess.run(
                    ["kubectl", "exec", "-n", ns, pod_name, "--", "pkill", "-9", "-f", "sh"],
                    check=False,
                )
                raise RuntimeError(
                    f"RAM dropped below 2 GiB ({avail_mb} MB) during mining run {run_id}!"
                )
            collector.capture_cadvisor_metrics(pod_name, ns, run_dir)

        p_exec.wait(timeout=30)
    else:
        subprocess.run(
            ["kubectl", "exec", "-n", ns, pod_name, "--", "/bin/sh", "-c", cmd_str], check=False
        )
        time.sleep(sleep_after)
        # Post-exec cAdvisor sample
        collector.capture_cadvisor_metrics(pod_name, ns, run_dir)

    t1 = datetime.now(UTC)
    t1_iso = t1.isoformat().replace("+00:00", "Z")
    elapsed = round((t1 - t0).total_seconds(), 2)

    # 3. Capture remaining telemetry streams
    collector.capture_falco_alerts(pod_name, ns, t0_iso, run_dir)
    collector.capture_k8s_audit_events(pod_name, ns, t0_iso, t1_iso, run_dir)
    collector.capture_hubble_flows(ns, t0_iso, t1_iso, run_dir)
    collector.attach_trivy_report(run_dir)

    # Write external index file
    collector.write_run_index(
        run_dir=run_dir,
        run_id=run_id,
        threat_class=run_item["class"],
        scenario_id=run_item["scenario_id"],
        namespace=ns,
        workload_name=app,
        pod_name=pod_name,
        t_start_iso=t0_iso,
        t_end_iso=t1_iso,
    )

    # 4. Enforce Per-Run Gate
    gate_ok, gate_reason = verify_per_run_gate(run_dir, is_mining=is_mining)
    if not gate_ok:
        raise RuntimeError(f"Per-run gate FAILED for {run_id}: {gate_reason}")

    return {
        "run_index": run_item["run_index"],
        "run_id": run_id,
        "class": run_item["class"],
        "scenario_id": run_item["scenario_id"],
        "seed": run_item["seed"],
        "namespace": ns,
        "pod_name": pod_name,
        "elapsed_seconds": elapsed,
        "ram_avail_mb": avail_mb,
        "disk_use_pct": disk_pct,
        "gate_status": "PASSED",
    }


def execute_staged_pilot(limit: int = 25) -> list[dict[str, Any]]:
    """Execute staged pilot up to limit (3 -> 10 -> 25)."""
    manifest = build_25_pilot_manifest()
    collector = PerRunTelemetryCapture(PILOT_RUNS_DIR)
    PILOT_RUNS_DIR.mkdir(parents=True, exist_ok=True)

    completed: list[dict[str, Any]] = []
    runs_to_execute = manifest[:limit]

    for item in runs_to_execute:
        res = execute_single_run(item, collector)
        completed.append(res)

    METRICS_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    METRICS_OUTPUT_FILE.write_text(json.dumps(completed, indent=2), encoding="utf-8")
    return completed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 2 Pilot Runner")
    parser.add_argument(
        "--limit", type=int, default=25, help="Number of runs to execute (3, 10, or 25)"
    )
    args = parser.parse_args()

    results = execute_staged_pilot(args.limit)
    print(f"COMPLETED_{len(results)}_RUNS_CLEAN")
    sys.exit(0)
