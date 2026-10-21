"""Per-run multi-source raw telemetry capture module (Decision D-07, D-20, Stage 1).

Archives real cluster telemetry from all 5 sources into isolated per-run directories:
data/raw/runs/<run_id>/{falco,audit,hubble,prometheus,trivy}/
Ensures zero scenario metadata or ground truth labels leak into telemetry files.

Capture windows
---------------
Every collector must read **at least the whole run window**. A collector that
pre-filters with a *fixed relative* window silently loses the earliest events
of any run that is longer than that window. This is not hypothetical: the
Stage 4a Round 5a run ``run-s4a-r4-02`` lasted 300.81 s and the Falco
collector, which asked ``kubectl logs --since=300s``, cut its window off at
``t_start + 0.81 s`` and therefore discarded the two events that the Falco
rules had emitted at ``t_start + 0.18 s`` (both inside the run window). The
per-run gate then failed with ``Missing telemetry from source 'falco'``.

The rule adopted after that measurement:

* the **Falco** collector uses an **absolute** cutoff, ``t_start - 2 s``;
* the **audit** collector sizes its tail to the run duration and then
  *verifies* that the tail actually reached back to ``t_start``, re-reading
  with a larger tail when it did not;
* the **Hubble** collector already used the absolute ``--since/--until`` pair;
* the **cAdvisor** collector takes no time window at all (it appends samples).
"""

from __future__ import annotations

import json
import logging
import math
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger("runtimelens.per_run_capture")

DEFAULT_RUNS_DIR = Path("data/raw/runs")
STATIC_TRIVY_REPORT_PATH = Path(
    "data/raw/trivy/docker.io_library_alpine_sha256_6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1.json"
)

#: Margin subtracted from the run start when building an absolute log cutoff.
#: The container runtime stamps each log line with the time it was *written*,
#: which is a few milliseconds after the kernel event it carries, so the
#: cutoff must sit slightly before the run start to stay inclusive.
LOG_WINDOW_MARGIN_SECONDS = 2.0

#: Lower bound for the audit log tail. The measured audit-log growth in this
#: cluster is ~557 bytes/s (~0.75 lines/s), so 4000 lines already cover more
#: than an hour of history; the value is only a floor.
AUDIT_LOG_MIN_TAIL_LINES = 4000

#: Conservative upper bound on the audit-log line rate (lines per second) used
#: to size the tail to the run duration. The measured rate is ~0.75 lines/s,
#: so this bound carries a ~26x margin.
AUDIT_LOG_MAX_LINES_PER_SECOND = 20.0

#: How many times the audit tail may be widened when the first read did not
#: reach back to the run start.
AUDIT_LOG_MAX_WIDEN_ATTEMPTS = 3


def falco_log_since_time(t_start_iso: str) -> str:
    """Return the absolute RFC3339 cutoff for the Falco log read.

    The cutoff is the run start minus :data:`LOG_WINDOW_MARGIN_SECONDS`, so it
    is **independent of the run duration**: a 10 s run and a 10 000 s run are
    both covered in full.
    """
    start = datetime.fromisoformat(t_start_iso.replace("Z", "+00:00"))
    cutoff = start - timedelta(seconds=LOG_WINDOW_MARGIN_SECONDS)
    return cutoff.astimezone(UTC).isoformat().replace("+00:00", "Z")


def audit_log_tail_lines(t_start_iso: str, t_end_iso: str) -> int:
    """Return the number of audit-log tail lines that must cover the run window.

    The tail is taken *after* the run ends, so it has to contain every line
    written between ``t_start`` and ``t_end`` plus a margin for the lines
    written between the end of the run and the moment the tail is taken.
    """
    try:
        start = datetime.fromisoformat(t_start_iso.replace("Z", "+00:00"))
        end = datetime.fromisoformat(t_end_iso.replace("Z", "+00:00"))
        duration = max(0.0, (end - start).total_seconds())
    except Exception:
        duration = 0.0
    scaled = int(math.ceil(duration * AUDIT_LOG_MAX_LINES_PER_SECOND)) + AUDIT_LOG_MIN_TAIL_LINES
    return max(AUDIT_LOG_MIN_TAIL_LINES, scaled)


class PerRunTelemetryCapture:
    """Manages isolated per-run directory captures across all 5 telemetry sources."""

    def __init__(self, base_dir: Path = DEFAULT_RUNS_DIR) -> None:
        self.base_dir = base_dir

    def prepare_run_dir(self, run_id: str) -> Path:
        """Create clean per-run directory structure."""
        run_dir = self.base_dir / run_id
        if run_dir.exists():
            shutil.rmtree(run_dir)
        for src in ["falco", "audit", "hubble", "prometheus", "trivy", "pod"]:
            (run_dir / src).mkdir(parents=True, exist_ok=True)
        return run_dir

    def capture_hubble_flows(
        self,
        namespace: str,
        t_start_iso: str,
        t_end_iso: str,
        run_dir: Path,
    ) -> int:
        """Capture live Cilium network flows from Hubble Relay for the run window."""
        output_file = run_dir / "hubble" / "flows.jsonl"
        cmd = [
            "hubble",
            "--server",
            "localhost:4245",
            "observe",
            "--since",
            t_start_iso,
            "--until",
            t_end_iso,
            "-n",
            namespace,
            "-o",
            "json",
        ]
        count = 0
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            with open(output_file, "w", encoding="utf-8") as f:
                for line in lines:
                    try:
                        # Verify valid JSON
                        json.loads(line)
                        f.write(line + "\n")
                        count += 1
                    except Exception:
                        continue
        except Exception as e:
            logger.warning("Hubble capture exception: %s", e)
        return count

    def capture_cadvisor_metrics(
        self,
        pod_name: str,
        namespace: str,
        run_dir: Path,
    ) -> int:
        """Capture container CPU and memory metrics from kubelet cAdvisor summary API.

        Appends to existing samples in prometheus/metrics.json for time-series tracking.
        """
        output_file = run_dir / "prometheus" / "metrics.json"
        cmd = [
            "kubectl",
            "get",
            "--raw",
            "/api/v1/nodes/runtimelens-control-plane/proxy/stats/summary",
        ]
        samples: list[dict[str, Any]] = []
        if output_file.exists():
            try:
                existing = json.loads(output_file.read_text(encoding="utf-8"))
                samples = existing.get("samples", [])
            except Exception:
                samples = []

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                pods_stats = data.get("pods", [])
                matched_stats = []
                for p in pods_stats:
                    ref = p.get("podRef", {})
                    if ref.get("namespace") == namespace and (
                        ref.get("name") == pod_name or pod_name in ref.get("name", "")
                    ):
                        matched_stats.append(p)

                sample_time = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                raw_summary_time = data.get("node", {}).get("cpu", {}).get("time") or sample_time
                samples.append(
                    {
                        "sample_index": len(samples) + 1,
                        "timestamp": sample_time,
                        "pod_stats": matched_stats,
                    }
                )

                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "samples": samples,
                            "sample_count": len(samples),
                            "pod_stats": matched_stats,
                            "raw_summary_time": raw_summary_time,
                        },
                        f,
                        indent=2,
                    )
        except Exception as e:
            logger.warning("cAdvisor capture exception: %s", e)
        return len(samples)

    def capture_falco_alerts(
        self,
        pod_name: str,
        namespace: str,
        t_start_iso: str,
        run_dir: Path,
    ) -> int:
        """Capture authentic Falco eBPF daemon alerts for the target pod and namespace.

        The log read uses an **absolute** cutoff (``t_start - 2 s``) rather than
        a fixed relative window, so the read always covers the whole run
        however long the run is. See the module docstring for the measurement
        that forced this change.
        """
        output_file = run_dir / "falco" / "events.jsonl"
        since_time = falco_log_since_time(t_start_iso) if t_start_iso else ""
        cmd = [
            "kubectl",
            "logs",
            "-n",
            "falco",
            "ds/falco",
            "-c",
            "falco",
        ]
        if since_time:
            cmd.append(f"--since-time={since_time}")
        count = 0
        t_cmp = t_start_iso[:19] if t_start_iso else ""
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            valid_events = []
            for line in lines:
                if not line.startswith("{"):
                    continue
                try:
                    event = json.loads(line)
                    fields = event.get("output_fields", {})
                    evt_pod = str(fields.get("k8s.pod.name") or "")
                    evt_ns = str(fields.get("k8s.ns.name") or "")
                    evt_time = event.get("time", "")

                    if t_cmp and evt_time and evt_time[:19] < t_cmp:
                        continue

                    # Filter strictly for tenant pod events (excluding host pod=<NA> events)
                    if evt_ns == namespace and (pod_name in evt_pod or evt_pod in pod_name):
                        valid_events.append(line)
                except Exception:
                    continue

            with open(output_file, "w", encoding="utf-8") as f:
                for evt_line in valid_events:
                    f.write(evt_line + "\n")
                    count += 1
        except Exception as e:
            logger.warning("Falco capture exception: %s", e)
        return count

    def capture_k8s_audit_events(
        self,
        pod_name: str,
        namespace: str,
        t_start_iso: str,
        t_end_iso: str,
        run_dir: Path,
    ) -> int:
        """Capture genuine K8s API audit log events for the run namespace and pod.

        The audit log is a plain file, so the read is a ``tail -n N``. That is
        still a *bounded* window: if the log grew by more than ``N`` lines
        during the run, the run's earliest audit events would be missing. The
        tail is therefore sized to the run duration and the collector then
        **verifies** that the tail actually reached back to ``t_start``,
        widening it when it did not.
        """
        output_file = run_dir / "audit" / "events.jsonl"
        audit_log = Path("/var/log/kubernetes/audit/audit.log")
        count = 0
        if not audit_log.exists():
            return 0

        tail_lines = audit_log_tail_lines(t_start_iso, t_end_iso)
        matched_events: list[str] = []
        oldest_seen: str | None = None

        for attempt in range(AUDIT_LOG_MAX_WIDEN_ATTEMPTS):
            cmd = ["sudo", "tail", "-n", str(tail_lines), str(audit_log)]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            matched_events, oldest_seen = self._filter_audit_lines(
                res.stdout,
                pod_name=pod_name,
                namespace=namespace,
                t_start_iso=t_start_iso,
                t_end_iso=t_end_iso,
            )
            reached_start = oldest_seen is None or oldest_seen <= t_start_iso
            if reached_start or attempt == AUDIT_LOG_MAX_WIDEN_ATTEMPTS - 1:
                if not reached_start:
                    logger.warning(
                        "Audit tail of %d lines did not reach back to the run start "
                        "(oldest line %s > %s); the earliest audit events of this run "
                        "may be missing.",
                        tail_lines,
                        oldest_seen,
                        t_start_iso,
                    )
                break
            tail_lines *= 4
            logger.warning(
                "Audit tail of %d lines did not reach back to the run start "
                "(oldest line %s > %s); widening to %d lines.",
                tail_lines // 4,
                oldest_seen,
                t_start_iso,
                tail_lines,
            )

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for line in matched_events:
                    f.write(line + "\n")
                    count += 1
        except Exception as e:
            logger.warning("Audit capture exception: %s", e)
        return count

    @staticmethod
    def _filter_audit_lines(
        raw: str,
        pod_name: str,
        namespace: str,
        t_start_iso: str,
        t_end_iso: str,
    ) -> tuple[list[str], str | None]:
        """Return the matching audit lines and the oldest timestamp seen."""
        target_sa = f"system:serviceaccount:{namespace}:"
        matched_events: list[str] = []
        oldest_seen: str | None = None
        for line in raw.splitlines():
            if not line.strip() or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            ts = item.get("stageTimestamp") or item.get("requestReceivedTimestamp") or ""
            if not ts:
                continue
            if oldest_seen is None or ts < oldest_seen:
                oldest_seen = ts
            if t_start_iso and ts < t_start_iso:
                continue
            if t_end_iso and ts > t_end_iso:
                continue

            obj = item.get("objectRef", {})
            obj_ns = obj.get("namespace", "")
            user_info = item.get("user", {})
            user_name = user_info.get("username", "")
            extra = user_info.get("extra", {})
            extra_pods = extra.get("authentication.kubernetes.io/pod-name", [])

            # Match criteria:
            # 1. Target namespace matches workload pod namespace
            # 2. Originating identity matches workload service account (cross-namespace)
            # 3. Originating identity specifically names this workload pod
            is_ns_match = obj_ns == namespace
            is_sa_match = bool(user_name and user_name.startswith(target_sa))
            is_pod_match = any(p == pod_name or pod_name in p for p in extra_pods)

            if is_ns_match or is_sa_match or is_pod_match:
                matched_events.append(line.strip())
        return matched_events, oldest_seen

    def attach_trivy_report(self, run_dir: Path) -> bool:
        """Attach the static image vulnerability report into the per-run directory."""
        dest = run_dir / "trivy" / "report.json"
        if STATIC_TRIVY_REPORT_PATH.exists():
            shutil.copyfile(STATIC_TRIVY_REPORT_PATH, dest)
            return True

        # Generate minimal static alpine vulnerability report if cache missing
        fallback_data = {
            "SchemaVersion": 2,
            "ArtifactName": "alpine:3.19",
            "ArtifactType": "container_image",
            "Results": [{"Target": "alpine:3.19", "Vulnerabilities": []}],
        }
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(fallback_data, f, indent=2)
        return True

    def attach_pod_spec(self, run_dir: Path, pod_spec: dict[str, Any]) -> bool:
        """Attach sanitized structural pod specification (volumes and securityContext).

        Guarantees zero metadata leakage (zero scenario_id, class, or run_id).
        """
        dest_dir = run_dir / "pod"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "spec.json"

        spec_dict = pod_spec.get("spec", pod_spec)
        sanitized_spec = {
            "volumes": spec_dict.get("volumes", []),
            "containers": [
                {
                    "name": c.get("name", "worker"),
                    "image": c.get("image", "alpine:3.19"),
                    "resources": c.get("resources", {}),
                    "securityContext": c.get("securityContext", {}),
                    "volumeMounts": c.get("volumeMounts", []),
                }
                for c in spec_dict.get("containers", [])
            ],
        }
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(sanitized_spec, f, indent=2)
        return True

    def write_run_index(
        self,
        run_dir: Path,
        run_id: str,
        threat_class: str,
        scenario_id: str,
        namespace: str,
        workload_name: str,
        pod_name: str,
        t_start_iso: str,
        t_end_iso: str,
        clock_offset_ms: float = 0.0,
        expected_cpu_profile: str = "low",
    ) -> Path:
        """Write metadata index file OUTSIDE the telemetry directory."""
        t_start = datetime.fromisoformat(t_start_iso.replace("Z", "+00:00"))
        t_end = datetime.fromisoformat(t_end_iso.replace("Z", "+00:00"))
        duration = round((t_end - t_start).total_seconds(), 2)

        index_data = {
            "run_id": run_id,
            "threat_class": threat_class,
            "scenario_id": scenario_id,
            "expected_cpu_profile": expected_cpu_profile,
            "namespace": namespace,
            "workload_name": workload_name,
            "pod_name": pod_name,
            "t_start": t_start_iso,
            "t_end": t_end_iso,
            "duration_seconds": duration,
            "clock_offset_ms": clock_offset_ms,
        }
        index_file = run_dir / "index.json"
        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2)
        return index_file
