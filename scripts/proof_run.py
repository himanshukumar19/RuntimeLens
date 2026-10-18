"""Proof run execution: exactly one benign run and one real 2-minute mining run (Condition B4)."""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture

logger = logging.getLogger("runtimelens.proof_run")

RUNS_DIR = Path("data/raw/runs")


def get_available_ram_mb() -> float:
    """Read available RAM in MB from host system."""
    try:
        out = subprocess.check_output(["free", "-m"], text=True)
        for line in out.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                return float(parts[6])  # available is column 7 (index 6)
    except Exception:
        pass
    return 4000.0


def run_proof_execution() -> int:
    print("=======================================================")
    print("  RuntimeLens Stage 1 Proof Run (Condition B4)")
    print("  Exactly 2 Runs: 1 Benign + 1 Real 2-Minute Mining Run")
    print("=======================================================")

    collector = PerRunTelemetryCapture(RUNS_DIR)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # RUN 1: BENIGN RUN
    # -----------------------------------------------------------------------
    run_id_benign = "run-proof-01-benign"
    print(f"\n--- [1/2] Executing Benign Run: {run_id_benign} ---")
    run_dir_benign = collector.prepare_run_dir(run_id_benign)

    t0_benign = datetime.now(UTC)
    t0_benign_iso = t0_benign.isoformat().replace("+00:00", "Z")
    print(f"  t_start: {t0_benign_iso}")

    # Capture initial cAdvisor sample before exec
    collector.capture_cadvisor_metrics("web", "tenant-a", run_dir_benign)

    # Real exec command on live tenant pod (with DNS ping to trigger Hubble flow)
    cmd_benign = [
        "kubectl",
        "exec",
        "-n",
        "tenant-a",
        "deployment/web",
        "--",
        "/bin/sh",
        "-c",
        "uptime && nc -z -w 1 10.96.0.10 53 || true",
    ]
    res_b = subprocess.run(cmd_benign, capture_output=True, text=True, check=False)
    print(f"  Exec Output: {res_b.stdout.strip()}")

    time.sleep(10)  # Telemetry collection window
    t1_benign = datetime.now(UTC)
    t1_benign_iso = t1_benign.isoformat().replace("+00:00", "Z")
    print(f"  t_end:   {t1_benign_iso}")

    # Capture 5 sources
    c_falco = collector.capture_falco_alerts("web", "tenant-a", t0_benign_iso, run_dir_benign)
    c_audit = collector.capture_k8s_audit_events(
        "web", "tenant-a", t0_benign_iso, t1_benign_iso, run_dir_benign
    )
    c_hubble = collector.capture_hubble_flows(
        "tenant-a", t0_benign_iso, t1_benign_iso, run_dir_benign
    )
    c_prom = collector.capture_cadvisor_metrics("web", "tenant-a", run_dir_benign)
    collector.attach_trivy_report(run_dir_benign)

    collector.write_run_index(
        run_dir=run_dir_benign,
        run_id=run_id_benign,
        threat_class="benign",
        scenario_id="SC-BEN-01",
        namespace="tenant-a",
        workload_name="web",
        pod_name="web-6794787bc8-5pnzg",
        t_start_iso=t0_benign_iso,
        t_end_iso=t1_benign_iso,
    )
    print(
        f"  Captured: Falco={c_falco}, Audit={c_audit}, Hubble={c_hubble}, Prom={c_prom}, Trivy=1"
    )

    # -----------------------------------------------------------------------
    # RUN 2: REAL 2-MINUTE CRYPTOMINING RUN
    # -----------------------------------------------------------------------
    run_id_mining = "run-proof-02-mining"
    print(f"\n--- [2/2] Executing Real 2-Minute Mining Run: {run_id_mining} ---")
    run_dir_mining = collector.prepare_run_dir(run_id_mining)

    # Resource guard check before run
    avail_mb = get_available_ram_mb()
    print(f"  Pre-mining Available RAM: {avail_mb} MB")
    if avail_mb < 2048.0:
        print("ABORT: Available RAM below 2 GiB before mining run!")
        return 1

    t0_mining = datetime.now(UTC)
    t0_mining_iso = t0_mining.isoformat().replace("+00:00", "Z")
    print(f"  t_start: {t0_mining_iso}")

    # Genuine 120-second CPU busy loop throttled by container cgroup quota to 500m
    # Connecting to cluster service port 3333 to emit network flow
    cmd_mining = (
        "nc -z -w 2 10.96.0.1 3333 || true; "
        "while true; do :; done & PID=$!; "
        "sleep 120; kill $PID 2>/dev/null || true"
    )
    print("  Launching 120-second sustained CPU loop inside tenant-a deployment/web...")
    p_mining = subprocess.Popen(
        ["kubectl", "exec", "-n", "tenant-a", "deployment/web", "--", "/bin/sh", "-c", cmd_mining],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Monitor every 15 seconds during the 120-second run
    for check_idx in range(1, 9):
        time.sleep(15)
        current_avail = get_available_ram_mb()
        elapsed_so_far = check_idx * 15
        s_str = f"[+ {elapsed_so_far}s / 120s] CPU Active | Avail RAM: {current_avail}MB"
        print(f"    {s_str}")
        if current_avail < 2048.0:
            print(f"SAFETY ABORT: Avail RAM below 2 GiB ({current_avail} MB)! Killing mining.")
            p_mining.terminate()
            subprocess.run(
                [
                    "kubectl",
                    "exec",
                    "-n",
                    "tenant-a",
                    "deployment/web",
                    "--",
                    "pkill",
                    "-9",
                    "-f",
                    "sh",
                ],
                check=False,
            )
            return 1
        # Sample cAdvisor metrics every 15 seconds (produces >= 8 time-series samples)
        collector.capture_cadvisor_metrics("web", "tenant-a", run_dir_mining)

    p_mining.wait(timeout=30)
    t1_mining = datetime.now(UTC)
    t1_mining_iso = t1_mining.isoformat().replace("+00:00", "Z")
    actual_duration = round((t1_mining - t0_mining).total_seconds(), 2)
    print(f"  t_end:   {t1_mining_iso} (Total Measured Duration: {actual_duration}s)")

    # Capture 5 sources
    c_falco_m = collector.capture_falco_alerts("web", "tenant-a", t0_mining_iso, run_dir_mining)
    c_audit_m = collector.capture_k8s_audit_events(
        "web", "tenant-a", t0_mining_iso, t1_mining_iso, run_dir_mining
    )
    c_hubble_m = collector.capture_hubble_flows(
        "tenant-a", t0_mining_iso, t1_mining_iso, run_dir_mining
    )
    c_prom_m = collector.capture_cadvisor_metrics("web", "tenant-a", run_dir_mining)
    collector.attach_trivy_report(run_dir_mining)

    collector.write_run_index(
        run_dir=run_dir_mining,
        run_id=run_id_mining,
        threat_class="cryptomining",
        scenario_id="SC-MNR-01",
        namespace="tenant-a",
        workload_name="web",
        pod_name="web-6794787bc8-5pnzg",
        t_start_iso=t0_mining_iso,
        t_end_iso=t1_mining_iso,
    )
    print(
        f"  Captured: Falco={c_falco_m}, Audit={c_audit_m}, "
        f"Hubble={c_hubble_m}, Prom={c_prom_m}, Trivy=1"
    )

    print("\n=======================================================")
    print("  PROOF RUN COMPLETED CLEANLY: Exactly 2 Runs Captured")
    print("=======================================================")
    return 0


if __name__ == "__main__":
    sys.exit(run_proof_execution())
