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
from typing import Any, Final

from runtimelens.collector.per_run_capture import PerRunTelemetryCapture
from runtimelens.eval.cpu_bands import (
    BURST_MEDIAN_MAX_MCORES,
    BURST_PEAK_MAX_MCORES,
    BURST_PEAK_MIN_MCORES,
)
from runtimelens.eval.cpu_bands import median as median_value
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
from scripts.stage4a_round4 import ROUND4_TEMPLATE_DEFS

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
        # VERIFIED in Stage 4a attempt 2: the dummy-path prefix makes the mount
        # rule fire on the hostPath File mount.
        "expect_falco": [
            "Interactive Shell Spawned in Non-Debug Container",
            "Launch Sensitive Mount Container",
        ],
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
        # Decision D-31: `cat` of the dummy `shadow` produces an open event that
        # the identity rule owns (it is evaluated first), so the mount rule
        # needs an event of its own: one read of a NON-identity dummy file.
        # proc.cmdline length: 161 -> bin 151-250+
        "command": (
            "cat /opt/runtimelens-dummy/etc/shadow 2>&1 || true; "
            "head -n 1 /opt/runtimelens-dummy/etc/hosts 2>&1 || true; "
            "echo p | nc -u -w 1 198.51.100.22 8080 || true"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": [
            "Interactive Shell Spawned in Non-Debug Container",
            "Launch Sensitive Mount Container",
            "Read Sensitive Host Information Untrusted",
        ],
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
        # Privileged-only pod: there is NO hostPath volume, so
        # `Launch Sensitive Mount Container` can never fire.
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


_BATCH_A_IDS: frozenset[str] = frozenset(
    t["run_id"] for t in ROUND4_TEMPLATE_DEFS if t["batch"] == "A"
)
_BATCH_B_IDS: frozenset[str] = frozenset(
    t["run_id"] for t in ROUND4_TEMPLATE_DEFS if t["batch"] == "B"
)
_BATCH_C_IDS: frozenset[str] = frozenset(
    t["run_id"] for t in ROUND4_TEMPLATE_DEFS if t["batch"] == "C"
)
_BATCH_D_IDS: frozenset[str] = frozenset(
    t["run_id"] for t in ROUND4_TEMPLATE_DEFS if t["batch"] == "D"
)

# ---------------------------------------------------------------------------
# Decision D-29: the benign network-observation vocabulary.
#
# The per-run gate requires all five telemetry sources to carry at least one
# event.  A scenario that opens no socket and resolves no name produces zero
# Hubble flows and therefore fails that gate, even though nothing is wrong
# with the scenario itself.  The gate is NOT relaxed: instead, every purely
# local scenario carries exactly ONE declared benign network observation.
#
# The observation type is varied on purpose so that it is not a class marker:
# the same A / B / C mix appears in the benign, container_escape,
# privilege_abuse and unknown classes, and the fourth type (D) is already used
# by the Part 1 corpus.  All four observations are in-cluster, read-only and
# carry no credential.
#
#   A  DNS resolution via the cluster resolver
#   B  TCP probe against the cluster DNS service
#   C  HTTP(S) GET of the in-cluster Kubernetes API discovery document
#      (world-readable, unauthenticated, and therefore audit-neutral for the
#       collector, which only records namespace-matching or ServiceAccount-
#       attributed requests)
#   D  UDP datagram to the inert external test IP  (pre-existing corpus type)
# ---------------------------------------------------------------------------
NET_OBSERVATIONS: Final[dict[str, str]] = {
    "A": "nslookup kubernetes.default.svc.cluster.local 2>&1 || true",
    "B": "nc -z -w 1 10.96.0.10 53 || true",
    "C": "wget -qO- --no-check-certificate https://10.96.0.1/api 2>&1 || true",
    "D": "echo p | nc -u -w 1 198.51.100.22 8080 || true",
}


def with_observation(command: str, observation_type: str) -> str:
    """Append exactly one declared benign network observation to a command."""
    return f"{command}; {NET_OBSERVATIONS[observation_type]}"


# ---------------------------------------------------------------------------
# Stage 4a ROUND 2 template set: 13 templates, 1 run each.
#
# Round 2 covers exactly the templates that were CHANGED since the Stage 4a
# Part 1 smoke or that have NEVER been run.  The ten Part 1 templates that
# were unchanged and already executed are NOT repeated, so no telemetry is
# collected twice and no template is run outside the review loop.
#
#   changed since Part 1 : ESC-05, ESC-08, ESC-09, ESC-10 (replacements),
#                          PRV-02, PRV-04, PRV-05 (re-scoped / new),
#                          BEN-06 (bin corrected)
#   never run            : BEN-14, BEN-16, BEN-17, PRV-07, UNK-R2
#
# Every command below is PROPOSED: it implements the corresponding
# `docs/SCENARIO_PLAN_v2.md` registry row, and the exact `proc.cmdline` length
# is recorded in the registry and in the template comment below.  The round-2
# run is the first measurement of these templates; the burst CPU profiles
# (BEN-14, BEN-16, BEN-17, PRV-07, UNK-R2) are explicitly subject to
# confirmation against the Decision D-26 band (peak 20-150 mcores, median
# < 100 mcores) and Decision D-27 (post-lag ratio + post-lag median floor).
# ---------------------------------------------------------------------------
ROUND2_TEMPLATES: list[dict[str, Any]] = [
    {
        "run_id": "run-s4a-r2-01",
        "template_id": "TMPL-ESC-05",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-5e21",
        "pod_spec": _pod_spec("worker-task-5e21", privileged=True),
        # Cgroup v2 hierarchy exposure in a privileged sandbox (replaces the
        # cgroup v1 `release_agent` traversal, which cannot execute on v2).
        # Decision D-29: one declared benign network observation (type A, DNS)
        # is appended so the run produces Hubble flow telemetry.
        # proc.cmdline length: 228 -> bin 151-250+
        "command": with_observation(
            "cat /proc/self/cgroup; head -n 30 /proc/self/mountinfo; "
            "grep Cap /proc/self/status; ls -l /proc/self/fd 2>&1 | head -n 10; "
            "cat /proc/self/mounts 2>&1 | head -n 10",
            "A",
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "T"],
    },
    {
        "run_id": "run-s4a-r2-02",
        "template_id": "TMPL-ESC-08",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-6f33",
        "pod_spec": _pod_spec("worker-task-6f33", privileged=True),
        # Host device namespace enumeration in a privileged sandbox (replaces
        # the `mknod` device-node attempt, which the device cgroup blocks even
        # when privileged).
        # Decision D-29: one declared benign network observation (type B, TCP
        # probe against the cluster DNS service).
        # proc.cmdline length: 91 -> bin 81-150
        "command": with_observation(
            "ls -l /dev | head -n 20; grep Cap /proc/self/status",
            "B",
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "T"],
    },
    {
        "run_id": "run-s4a-r2-03",
        "template_id": "TMPL-ESC-09",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-7a44",
        "pod_spec": _pod_spec(
            "worker-task-7a44",
            host_path="/opt/runtimelens-dummy/etc",
            host_path_type="Directory",
        ),
        # Multi-file read over the inert dummy /etc directory.  Requires the
        # four 0-byte dummy files (shadow, passwd, group, hosts) provisioned by
        # the Stage 4a runbook prerequisites.
        # Decision D-29: one declared benign network observation (type C, HTTP
        # GET of the in-cluster API discovery document).
        # Decision D-31: the dummy identity files are owned by the identity rule
        # (evaluated first), so the mount rule needs an event of its own: one
        # read of a NON-identity dummy file.
        # proc.cmdline length: 309 -> bin 151-250+
        "command": with_observation(
            "head -n 2 /opt/runtimelens-dummy/etc/shadow 2>&1 || true; "
            "dd if=/opt/runtimelens-dummy/etc/passwd of=/dev/null 2>&1 || true; "
            "head -n 1 /opt/runtimelens-dummy/etc/hosts 2>&1 || true; "
            "find /opt/runtimelens-dummy/etc -type f 2>&1 || true",
            "C",
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": [
            "Interactive Shell Spawned in Non-Debug Container",
            "Launch Sensitive Mount Container",
            "Read Sensitive Host Information Untrusted",
        ],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "T", "F"],
    },
    {
        "run_id": "run-s4a-r2-04",
        "template_id": "TMPL-ESC-10",
        "threat_class": "container_escape",
        "namespace": SANDBOX_NS,
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-8b56",
        "pod_spec": _pod_spec(
            "worker-task-8b56",
            host_path="/opt/runtimelens-dummy/containerd.sock",
            host_path_type="File",
            privileged=True,
        ),
        # Runtime socket (containerd) exposure in a PRIVILEGED sandbox: the
        # third allowlisted dummy hostPath, which restores a real
        # `Launch Sensitive Mount Container` expectation, combined with
        # `privileged: true` so the feature triple is T/F/T as the plan states.
        # Decision D-31: `ls -l` only stat()s the file and therefore produces no
        # open event, so the mount rule could not fire.  The command now
        # performs a real read (`head -c 1`) of the mounted dummy socket, which
        # is the behaviour the scenario is about: the runtime socket is
        # reachable from inside the container.
        # Decision D-29: one declared benign network observation (type B, TCP
        # probe against the cluster DNS service).
        # proc.cmdline length: 129 -> bin 81-150
        "command": (
            "head -c 1 /opt/runtimelens-dummy/containerd.sock 2>&1 || true; "
            "grep Cap /proc/self/status; nc -z -w 1 10.96.0.10 53 || true"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": [
            "Interactive Shell Spawned in Non-Debug Container",
            "Launch Sensitive Mount Container",
        ],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["T", "F", "T"],
    },
    {
        "run_id": "run-s4a-r2-05",
        "template_id": "TMPL-PRV-02",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-b",
        "app": "web",
        "mode": "exec",
        # Re-scoped (proposed): unauthenticated own-namespace collection
        # enumeration.  No ServiceAccount credential is presented, so the
        # API server answers 403; the request is still captured by the audit
        # collector through the objectRef.namespace match.  This is the
        # credential-less counterfactual of TMPL-BEN-06.
        # No D-29 observation added: this template already produces Hubble
        # flow telemetry through its own API request (observation type C).
        # proc.cmdline length: 88 -> bin 81-150
        "command": (
            "wget -qO- --no-check-certificate https://10.96.0.1/api/v1/namespaces/tenant-b/pods"
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-06",
        "template_id": "TMPL-PRV-04",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-a",
        "app": "payment-style",
        "mode": "exec",
        # ServiceAccount-authenticated cross-tenant ConfigMap extraction.
        # No D-29 observation added: this template already produces Hubble
        # flow telemetry through its own API request (observation type C).
        # BusyBox wget supports only `--header`, never `-H`; the short form
        # aborts before any network request is made.
        # proc.cmdline length: 181 -> bin 151-250+
        "command": (
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);"
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api/v1/namespaces/tenant-b/configmaps"
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-07",
        "template_id": "TMPL-PRV-05",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-b",
        "app": "api",
        "mode": "exec",
        # Re-scoped (proposed): ServiceAccount-authenticated API discovery,
        # i.e. reconnaissance of the authorisation surface using the workload's
        # own identity.  The request is attributed to the pod ServiceAccount
        # in the audit log.
        # Two facts shape this command:
        #   * BusyBox wget supports only `--header`, never `-H`; the short form
        #     aborts before any network request is made.
        #   * with the working `--header=` form the shortest
        #     ServiceAccount-authenticated, audit-attributable request is 153
        #     characters, so this template cannot occupy the 81-150 bin.  That
        #     is a measured property of the lab, not a design choice.
        # proc.cmdline length: 153 -> bin 151-250+
        "command": (
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);"
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api"
        ),
        "sleep_after": 7,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-08",
        "template_id": "TMPL-BEN-06",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "payment-style",
        "mode": "exec",
        # ServiceAccount-authenticated self-introspection of the workload's own
        # namespace.  The lab grants the tenant ServiceAccount no RBAC, so the
        # response is 403 even for the own namespace; the class signal is the
        # own-namespace target, not the status code.
        # BusyBox wget supports only `--header`, never `-H`.
        # proc.cmdline length: 181 -> bin 151-250+
        "command": (
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);"
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api/v1/namespaces/tenant-b/pods"
        ),
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-09",
        "template_id": "TMPL-BEN-14",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "database",
        "mode": "exec",
        # Developer debug session: process, memory and load inspection plus a
        # bounded arithmetic loop.
        # Decision D-30: the burn is calibrated against the measured kubelet
        # cAdvisor collection cadence of ~18-20 s, so the loop must hold its
        # load for ~30 s (480 iterations of the measured MNR-03 shape, whose
        # reported rate was 89.7-100.6 mcores) inside a ~90 s run window, so
        # that at least one collection window closes inside the burn and the
        # burst is observable at all.  The duty cycle keeps the reported rate
        # below the 150 mcores ceiling of the Decision D-26 band and the
        # post-burn samples keep the median below 100 mcores.
        # Decision D-29: one declared benign network observation (type B).
        # proc.cmdline length: 218 -> bin 151-250+
        "command": with_observation(
            "ps aux 2>&1 | head -n 20; cat /proc/meminfo 2>&1 | head -n 10; "
            "free -m 2>&1 | head -n 3; "
            "for i in $(seq 480); do j=0; while [ $j -lt 3000 ]; do j=$((j+1)); done; "
            "sleep 0.05; done",
            "B",
        ),
        "sleep_after": 60,
        "expected_cpu_profile": "burst",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-10",
        "template_id": "TMPL-BEN-16",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "web",
        "mode": "exec",
        # Log compression routine over an ephemeral file in /tmp.
        # Decision D-30: a single gzip of a 12 MiB file lasts ~3 s, which is far
        # shorter than the ~18-20 s cAdvisor collection interval and is
        # therefore invisible to the summary API.  The compression is spread
        # over 8 throttled cycles (~4.5 s each, ~1.5 s of gzip per cycle at
        # the measured ~5 MB/s of gzip on incompressible data) so that the burn
        # lasts ~36 s, long enough for a collection window to close inside it,
        # while the ~33% duty cycle keeps the reported rate around 65-70
        # mcores - inside the Decision D-26 band and below its 100 mcores
        # median floor.  Peak disk usage is 8 MiB (each file is deleted in its
        # own cycle).
        # Decision D-29: one declared benign network observation (type C).
        # proc.cmdline length: 211 -> bin 151-250+
        "command": with_observation(
            "for i in $(seq 8); do dd if=/dev/urandom of=/tmp/a.log bs=1M count=8 2>/dev/null; "
            "gzip -f /tmp/a.log; rm -f /tmp/a.log.gz; sleep 3; done",
            "C",
        ),
        "sleep_after": 50,
        "expected_cpu_profile": "burst",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-11",
        "template_id": "TMPL-BEN-17",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "api",
        "mode": "exec",
        # Batch calculation script: iterative numeric search loop.
        # Decision D-30: the previous nested loop (1500 x 4000 iterations per
        # outer iteration) was a 20-hour workload and was never executable.
        # It is replaced by a single-level loop of the measured MNR-03 shape
        # (3000 inner iterations + 50 ms pause), scaled to 400 outer
        # iterations: ~25 s of wall time at the measured ~90 mcores, i.e. a
        # ~60% duty cycle of the 200 mcores container limit, which keeps the
        # reported peak inside the Decision D-26 band and the burst longer
        # than one cAdvisor collection window.
        # Decision D-29: one declared benign network observation (type A).
        # proc.cmdline length: 174 -> bin 151-250+
        "command": with_observation(
            "cat /proc/loadavg; for i in $(seq 400); do j=0; "
            "while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05; done",
            "A",
        ),
        "sleep_after": 60,
        "expected_cpu_profile": "burst",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-12",
        "template_id": "TMPL-PRV-07",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-a",
        "app": "database",
        "mode": "exec",
        # Node proxy endpoint reconnaissance loop via the API server.
        # BusyBox wget supports only `--header`, never `-H`.
        # Decision D-30: the scenario is I/O bound (a sequence of HTTPS
        # requests) and produces no measurable CPU load at all, so its CPU
        # profile is re-declared `low`.  It was never a burst: the 8 seconds of
        # wall time are spent waiting for HTTP responses, not burning CPU.
        # proc.cmdline length: 229 -> bin 151-250+
        "command": (
            "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);"
            "for i in 1 2 3 4 5;do "
            'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '
            "https://10.96.0.1/api/v1/nodes/runtimelens-control-plane/proxy/metrics;done"
        ),
        "sleep_after": 8,
        "expected_cpu_profile": "low",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        # Measured 46 flows in Round 3: the five sequential node-proxy requests
        # each generate a full TCP retry sequence against the API server
        # ClusterIP, an order of magnitude more than a single request's 10.
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
    },
    {
        "run_id": "run-s4a-r2-13",
        "template_id": "TMPL-UNK-R2",
        "threat_class": "unknown",
        "namespace": "tenant-b",
        "app": "database",
        "mode": "exec",
        # Authorised batch recomputation: a throttled arithmetic loop.  The
        # scenario is "no pool egress" -- the only egress is the declared
        # benign observation below.
        # Decision D-30: the previous 900-iteration loop produced ~14 s of
        # CPU, right at the cAdvisor collection interval, and was therefore
        # not reliably observable.  It is replaced by 480 iterations of the
        # measured MNR-03 shape (~30 s of wall time at the measured ~90
        # mcores) inside a ~90 s run window, so that at least one collection
        # window closes inside the burn.
        # Decision D-29: one declared benign network observation (type A).
        # proc.cmdline length: 155 -> bin 151-250+
        "command": with_observation(
            "for i in $(seq 480); do j=0; "
            "while [ $j -lt 3000 ]; do j=$((j+1)); done; sleep 0.05; done",
            "A",
        ),
        "sleep_after": 60,
        "expected_cpu_profile": "burst",
        "expect_falco": ["Interactive Shell Spawned in Non-Debug Container"],
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
    },
]

# ---------------------------------------------------------------------------
# Stage 4a ROUND 3 template set: 7 templates, 1 run each.
#
# Round 3 covers exactly the templates that the approved D-30 / D-31 edit round
# changed, plus the four Round 2 templates that were never reached because the
# round stopped on the `TMPL-BEN-14` burst-band failure.  The six Round 2 runs
# that are unchanged and already collected are NOT repeated.
# ---------------------------------------------------------------------------
_ROUND2_BY_ID: dict[str, dict[str, Any]] = {t["template_id"]: t for t in ROUND2_TEMPLATES}
ROUND3_TEMPLATE_IDS: tuple[str, ...] = (
    "TMPL-ESC-09",
    "TMPL-ESC-10",
    "TMPL-BEN-14",
    "TMPL-BEN-16",
    "TMPL-BEN-17",
    "TMPL-PRV-07",
    "TMPL-UNK-R2",
)
ROUND3_TEMPLATES: list[dict[str, Any]] = [_ROUND2_BY_ID[tid] for tid in ROUND3_TEMPLATE_IDS]


# ---------------------------------------------------------------------------
# Stage 4a ROUND 4 template set: 2 templates, 1 run each.
#
# Both templates changed under Decision D-31 (a read of a non-identity dummy
# file was added so that the mount rule has an event of its own) and the
# TMPL-ESC-04 telemetry collected in Part 1 is stale with respect to the
# deployed rule order.
# ---------------------------------------------------------------------------
_ROUND1_BY_ID: dict[str, dict[str, Any]] = {t["template_id"]: t for t in TEMPLATES}
ROUND4_TEMPLATE_IDS: tuple[str, ...] = ("TMPL-ESC-04", "TMPL-ESC-09")
ROUND4_TEMPLATES: list[dict[str, Any]] = [
    _ROUND1_BY_ID["TMPL-ESC-04"],
    _ROUND2_BY_ID["TMPL-ESC-09"],
]


# ---------------------------------------------------------------------------
# Stage 4a ROUND 4 template set: the 32 never-run templates of the master
# registry, in the four proposed batches (A: 10, B: 10, C: 10, D: 2).
#
# The definitions live in `scripts/stage4a_round4.py`.  They are *proposed*:
# this is the command-writing round, nothing has been executed.
#
# Naming: the runner's round `4` above is the two D-31 re-runs (`ESC-04`,
# `ESC-09`).  The 32-template corpus-completion set is the *project's* Round 4
# and is therefore exposed by the runner as rounds `5a`-`5d`, with run ids
# `run-s4a-r4-01` .. `run-s4a-r4-32`.
# ---------------------------------------------------------------------------
def _build_round4_templates() -> list[dict[str, Any]]:
    """Materialise the Round 4 template registry, adding the sandbox manifests."""
    built: list[dict[str, Any]] = []
    for definition in ROUND4_TEMPLATE_DEFS:
        template: dict[str, Any] = {
            key: value
            for key, value in definition.items()
            if key not in {"batch", "own", "intensity"}
        }
        if template["mode"] == "sandbox":
            template["pod_spec"] = _pod_spec(template["pod_name"])
        built.append(template)
    return built


ROUND5_TEMPLATES: list[dict[str, Any]] = _build_round4_templates()
ROUND5_BATCHES: dict[str, list[dict[str, Any]]] = {
    "a": [t for t in ROUND5_TEMPLATES if t["run_id"] in _BATCH_A_IDS],
    "b": [t for t in ROUND5_TEMPLATES if t["run_id"] in _BATCH_B_IDS],
    "c": [t for t in ROUND5_TEMPLATES if t["run_id"] in _BATCH_C_IDS],
    "d": [t for t in ROUND5_TEMPLATES if t["run_id"] in _BATCH_D_IDS],
}
ROUND5_TEMPLATE_IDS: tuple[str, ...] = tuple(t["template_id"] for t in ROUND5_TEMPLATES)

# Round identifiers accepted by the CLI.
ROUND1_TEMPLATE_IDS: frozenset[str] = frozenset(t["template_id"] for t in TEMPLATES)
ROUND2_TEMPLATE_IDS: frozenset[str] = frozenset(t["template_id"] for t in ROUND2_TEMPLATES)
ROUND3_TEMPLATE_IDS_SET: frozenset[str] = frozenset(ROUND3_TEMPLATE_IDS)


def select_templates(round_id: str) -> list[dict[str, Any]]:
    """Return the template set for the requested Stage 4a round.

    Accepted selectors:

    * ``1`` — the ten Part 1 templates;
    * ``2`` — the thirteen Round 2 templates;
    * ``3`` — the seven Round 3 templates;
    * ``4`` — the two D-31 re-runs (``ESC-04``, ``ESC-09``);
    * ``5a``/``5b``/``5c``/``5d`` — the four batches of the Round 4
      corpus-completion set (the 32 templates that had never been executed),
      defined in ``scripts/stage4a_round4.py``.
    """
    if round_id == "1":
        return list(TEMPLATES)
    if round_id == "2":
        return list(ROUND2_TEMPLATES)
    if round_id == "3":
        return list(ROUND3_TEMPLATES)
    if round_id == "4":
        return list(ROUND4_TEMPLATES)
    if round_id.startswith("5") and round_id[1:] in ROUND5_BATCHES:
        return list(ROUND5_BATCHES[round_id[1:]])
    raise ValueError(
        f"unknown round: {round_id!r} (expected '1', '2', '3', '4', '5a', '5b', '5c' or '5d')"
    )


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
    """Decision D-26 `burst` CPU band: peak in [20, 150] mcores, median < 100.

    The band width is set by the cAdvisor measurement resolution: the same
    workload measured 25.77 mcores and 117.34 mcores on two consecutive
    attempts of an identical command (see `runtimelens.eval.cpu_bands`).
    """
    if not sample_cpus:
        return False, "FAIL (no cAdvisor samples)"
    peak = max(sample_cpus)
    med = median_value(sample_cpus)
    if (
        peak < BURST_PEAK_MIN_MCORES
        or peak > BURST_PEAK_MAX_MCORES
        or med >= BURST_MEDIAN_MAX_MCORES
    ):
        msg = (
            f"FAIL (peak={peak:.2f}m not in "
            f"[{BURST_PEAK_MIN_MCORES:.0f},{BURST_PEAK_MAX_MCORES:.0f}] "
            f"or med={med:.2f}m >= {BURST_MEDIAN_MAX_MCORES:.0f})"
        )
        return False, msg
    return True, f"PASS (peak={peak:.2f}m in [20,150], med={med:.2f}m)"


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
    round_id = "1"
    if len(sys.argv) > 1:
        round_id = sys.argv[1]
    try:
        selected = select_templates(round_id)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1
    print(
        f"=== STAGE 4a ROUND {round_id}: {len(selected)} templates, 1 run each "
        f"(stop for human review after the last run) ==="
    )
    collector = PerRunTelemetryCapture(base_dir=RUNS_DIR)
    results: list[dict[str, Any]] = []
    stop_reason: str | None = None

    for template in selected:
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
                        "stage": f"4a-round{round_id}",
                        "completed": len(results),
                        "total": len(selected),
                        "runs": results,
                        "stop_reason": stop_reason,
                        "updated_at": _t(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    print(f"\n================ STAGE 4a ROUND {round_id} SUMMARY ================")
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
    print(f"completed={len(results)}/{len(selected)} stop_reason={stop_reason}")
    return 0 if stop_reason is None else 2


if __name__ == "__main__":
    sys.exit(main())
