"""Stage 4a Round 4 corpus-completion template definitions (32 never-run templates).

Every command below was written for this round and is *proposed*: it implements
the corresponding `docs/SCENARIO_PLAN_v2.md` registry row (description, length
bin, duration, tenant/workload, CPU profile, expected signals) under the rules
established by the Stage 4a rounds:

* **D-29** — a scenario with no network activity of its own carries exactly one
  declared benign network observation (type A, B, C or D).
* **BusyBox wget** — the header option is `--header=`, never `-H`.
* **D-22 / D-27** — the mining templates use the verified 3000-iteration inner
  loop of `TMPL-MNR-03`; the `high` ones add the pool-name resolution (type A)
  that a real mining client performs, and the pool probes carry a handshake
  payload.
* **D-30** — a `burst` template holds its load for at least 30 s inside a 90 s
  run window, so that the kubelet's ~18-20 s cAdvisor collection cadence closes
  a collection window inside the burst.
* **No leakage** — no command contains a class name, a scenario/template id or a
  run id.

The observation vocabulary (D-29):

* **A** DNS resolution: `nslookup kubernetes.default.svc.cluster.local 2>&1 || true`
* **B** TCP probe against the cluster DNS service: `nc -z -w 1 10.96.0.10 53 || true`
* **C** HTTP(S) GET of the in-cluster API discovery document:
  `wget -qO- --no-check-certificate https://10.96.0.1/api 2>&1 || true`
* **D** UDP datagram to the inert external test IP:
  `echo p | nc -u -w 1 198.51.100.22 8080 || true`
"""

from __future__ import annotations

from typing import Any, Final

OBS_A: Final[str] = "nslookup kubernetes.default.svc.cluster.local 2>&1 || true"
OBS_B: Final[str] = "nc -z -w 1 10.96.0.10 53 || true"
OBS_C: Final[str] = "wget -qO- --no-check-certificate https://10.96.0.1/api 2>&1 || true"
OBS_D: Final[str] = "echo p | nc -u -w 1 198.51.100.22 8080 || true"

TOKEN_READ: Final[str] = "T=$(cat /run/secrets/kubernetes.io/serviceaccount/token);"
SA_HEADER: Final[str] = 'wget -qO- --no-check-certificate --header="Authorization: Bearer $T" '

# The pool handshake payload a real mining client sends to its pool.
POOL_HANDSHAKE: Final[str] = """printf '{"id":1,"method":"login","params":{"agent":"cpuminer"}}' """

SHELL_ONLY: Final[list[str]] = ["Interactive Shell Spawned in Non-Debug Container"]
SHELL_EGRESS: Final[list[str]] = [
    "Interactive Shell Spawned in Non-Debug Container",
    "Suspicious High Port Egress",
]
SHELL_IDENTITY: Final[list[str]] = [
    "Interactive Shell Spawned in Non-Debug Container",
    "Read Sensitive Host Information Untrusted",
]


def mining_high(port: int, iterations: int, prefix: str = "") -> str:
    """Unthrottled mining loop (D-22): saturates the 200 mcores cgroup cap.

    The loop is bounded so the scenario terminates; the wall time is the CPU
    time divided by the 200 mcores cgroup cap, which is why the iteration
    count (not the command length) sets the duration.
    """
    connect = f"{prefix}nc -u -w 1 198.51.100.22 {port} || true; "
    loop = f"for i in $(seq {iterations}); do j=0; while [ $j -lt 3000 ]; do j=$((j+1)); done; done"
    return connect + loop


def mining_throttled(port: int, iterations: int, pause: str, prefix: str = "") -> str:
    """Throttled mining loop (D-27): a measured duty cycle inside the band."""
    connect = f"{prefix}nc -u -w 1 198.51.100.22 {port} || true; "
    loop = (
        f"for i in $(seq {iterations}); do j=0; "
        f"while [ $j -lt 3000 ]; do j=$((j+1)); done; {pause} done"
    )
    return connect + loop


# ---------------------------------------------------------------------------
# The 32 never-run templates, in the four proposed Round 4 batches.
# `obs` is the declared D-29 observation appended to the command; `own` marks a
# template whose scenario already provides the network activity, so no
# observation is appended and the type is recorded for the mix table only.
# ---------------------------------------------------------------------------
_RAW_DEFS: Final[list[dict[str, Any]]] = [
    # ===================== Batch A: mining, privilege, escape ==================
    {
        "batch": "A",
        "run_id": "run-s4a-r4-01",
        "template_id": "TMPL-MNR-01",
        "threat_class": "cryptomining",
        "namespace": "tenant-a",
        "app": "web",
        "mode": "exec",
        # Pool-name resolution (type A) plus the D-22 125 s busy loop.
        "command": mining_high(3333, 10000),
        "obs": "A",
        "own": "D",
        "sleep_after": 5,
        "expected_cpu_profile": "high",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "200m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-02",
        "template_id": "TMPL-MNR-02",
        "threat_class": "cryptomining",
        "namespace": "tenant-b",
        "app": "database",
        "mode": "exec",
        "command": mining_high(4444, 10000),
        "obs": "A",
        "own": "D",
        "sleep_after": 5,
        "expected_cpu_profile": "high",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "200m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-03",
        "template_id": "TMPL-MNR-04",
        "threat_class": "cryptomining",
        "namespace": "tenant-a",
        "app": "payment-style",
        "mode": "exec",
        "command": mining_throttled(5555, 800, "sleep 0.075;"),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "throttled",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "~70m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-04",
        "template_id": "TMPL-MNR-05",
        "threat_class": "cryptomining",
        "namespace": "tenant-b",
        "app": "api",
        "mode": "exec",
        "command": mining_high(6379, 10000),
        "obs": "A",
        "own": "D",
        "sleep_after": 5,
        "expected_cpu_profile": "high",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "200m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-05",
        "template_id": "TMPL-MNR-06",
        "threat_class": "cryptomining",
        "namespace": "tenant-c",
        "app": "database",
        "mode": "exec",
        "command": mining_throttled(7777, 960, "sleep 0.09;"),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "throttled",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "~58m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-06",
        "template_id": "TMPL-MNR-07",
        "threat_class": "cryptomining",
        "namespace": "tenant-a",
        "app": "web",
        "mode": "exec",
        "command": mining_throttled(
            9999,
            900,
            "sleep 0.075;",
        ).replace(
            "sleep 0.075; done",
            "sleep 0.075; if [ $((i % 50)) -eq 0 ]; then " + OBS_A + "; fi; done",
        ),
        "obs": "",
        "own": "A",
        "sleep_after": 6,
        "expected_cpu_profile": "throttled",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "~70m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-07",
        "template_id": "TMPL-MNR-08",
        "threat_class": "cryptomining",
        "namespace": "tenant-b",
        "app": "web",
        "mode": "exec",
        "command": mining_throttled(8888, 1240, "sleep 0.06;"),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "throttled",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "~85m",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-08",
        "template_id": "TMPL-PRV-06",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-c",
        "app": "payment-style",
        "mode": "exec",
        # Inter-pod `exec` subresource probe against an adjacent namespace.  The
        # authorization filter runs before the storage lookup, so the answer is
        # 403 even for a workload name that is not a live pod.
        "command": (
            TOKEN_READ
            + SA_HEADER
            + "https://10.96.0.1/api/v1/namespaces/tenant-b/pods/payment-style/exec"
        ),
        "obs": "A",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "High",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-09",
        "template_id": "TMPL-PRV-08",
        "threat_class": "privilege_abuse",
        "namespace": "tenant-b",
        "app": "payment-style",
        "mode": "exec",
        # Batch multi-namespace resource scraping with the extracted token.
        "command": (
            TOKEN_READ
            + "for n in tenant-a tenant-b tenant-c;do "
            + SA_HEADER
            + "https://10.96.0.1/api/v1/namespaces/$n/secrets;done"
        ),
        "obs": "D",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
        "intensity": "High",
    },
    {
        "batch": "A",
        "run_id": "run-s4a-r4-10",
        "template_id": "TMPL-ESC-01",
        "threat_class": "container_escape",
        "namespace": "sandbox-workloads",
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-1a01",
        # Read of the container's own identity files.  `cat` is not in the
        # identity rule's exemption list, so the rule fires for both files.
        "command": "cat /etc/shadow /etc/passwd",
        "obs": "A",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_IDENTITY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    # ===================== Batch B: unknown, escape, benign ====================
    {
        "batch": "B",
        "run_id": "run-s4a-r4-11",
        "template_id": "TMPL-UNK-04",
        "threat_class": "unknown",
        "namespace": "tenant-a",
        "app": "payment-style",
        "mode": "exec",
        # Transient execution of a short-lived script from /tmp.
        "command": "printf 'echo x' > /tmp/p.sh; sh /tmp/p.sh",
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-12",
        "template_id": "TMPL-UNK-05",
        "threat_class": "unknown",
        "namespace": "tenant-a",
        "app": "api",
        "mode": "exec",
        # Rapid egress probe across the in-list high ports; every datagram is
        # dropped by the default-deny egress NetworkPolicy.
        "command": (
            "for p in 3333 4444 5555 7777 8888 9999; do "
            "echo p | nc -u -w 1 198.51.100.22 $p || true; done"
        ),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "HIGH",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-13",
        "template_id": "TMPL-UNK-07",
        "threat_class": "unknown",
        "namespace": "tenant-c",
        "app": "payment-style",
        "mode": "exec",
        # Maintenance script whose egress is denied by the default-deny egress
        # NetworkPolicy: a policy trip that is not malicious, and that fires no
        # Falco rule.
        "command": "wget -qO- --no-check-certificate http://10.96.0.10:8080/ 2>&1 || true",
        "obs": "",
        "own": "B",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-14",
        "template_id": "TMPL-UNK-R1",
        "threat_class": "unknown",
        "namespace": "tenant-a",
        "app": "database",
        "mode": "exec",
        # Shared-ServiceAccount contention: the request is authenticated with
        # the namespace ServiceAccount, so the audit record identifies the
        # identity but not which of the workloads that share it issued it.
        "command": TOKEN_READ + SA_HEADER + "https://10.96.0.1/api/v1/namespaces/tenant-a/pods",
        "obs": "",
        "own": "C",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Medium",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-15",
        "template_id": "TMPL-UNK-R3",
        "threat_class": "unknown",
        "namespace": "tenant-b",
        "app": "web",
        "mode": "exec",
        # Health-check liveness probe on an in-list high port.
        "command": "echo p | nc -u -w 1 198.51.100.22 3333 || true",
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-16",
        "template_id": "TMPL-UNK-R4",
        "threat_class": "unknown",
        "namespace": "tenant-b",
        "app": "payment-style",
        "mode": "exec",
        # Rollout-induced exec burst: four short-lived shells in rapid
        # succession, i.e. a burst of spawn events from one workload.
        "command": "for i in 1 2 3 4; do sh -c :; done",
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Medium",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-17",
        "template_id": "TMPL-ESC-02",
        "threat_class": "container_escape",
        "namespace": "sandbox-workloads",
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-2b02",
        # Read-only inspection of the kernel pseudo-filesystems.  Neither path is
        # an identity file, so no identity rule can fire.
        "command": "cat /proc/kcore /proc/sys/kernel/hostname 2>&1 | head -n 2",
        "obs": "C",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-18",
        "template_id": "TMPL-ESC-07",
        "threat_class": "container_escape",
        "namespace": "sandbox-workloads",
        "app": "worker",
        "mode": "sandbox",
        "pod_name": "worker-task-7c07",
        # Symlink traversal check of the container's own /proc/1/root.  No
        # `hostPID`, so the target is the container's own root.
        "command": "readlink /proc/1/root 2>&1 || true",
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "High",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-19",
        "template_id": "TMPL-BEN-02",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "api",
        "mode": "exec",
        "command": "touch /tmp/hc; rm -f /tmp/hc",
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "B",
        "run_id": "run-s4a-r4-20",
        "template_id": "TMPL-BEN-03",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "database",
        "mode": "exec",
        "command": "date -u; hostname",
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    # ===================== Batch C: benign ======================================
    {
        "batch": "C",
        "run_id": "run-s4a-r4-21",
        "template_id": "TMPL-BEN-05",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "web",
        "mode": "exec",
        "command": "echo p | nc -u -w 1 198.51.100.22 6379 || true",
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-22",
        "template_id": "TMPL-BEN-07",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "database",
        "mode": "exec",
        "command": (
            "printf 'GET /metrics HTTP/1.0\\r\\n\\r\\n' | nc -u -w 1 198.51.100.22 9999 || true"
        ),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-23",
        "template_id": "TMPL-BEN-08",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "web",
        "mode": "exec",
        "command": "df -h; du -sk /tmp",
        "obs": "A",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-24",
        "template_id": "TMPL-BEN-09",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "database",
        "mode": "exec",
        "command": "echo p | nc -u -w 1 198.51.100.22 9090 || true",
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-25",
        "template_id": "TMPL-BEN-10",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "web",
        "mode": "exec",
        "command": "ls -l /etc/ssl/certs",
        "obs": "D",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-26",
        "template_id": "TMPL-BEN-12",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "api",
        "mode": "exec",
        "command": (
            "nslookup kubernetes.default.svc.cluster.local 2>&1 || true; "
            "nslookup kube-dns.kube-system.svc.cluster.local 2>&1 || true"
        ),
        "obs": "",
        "own": "A",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-27",
        "template_id": "TMPL-BEN-13",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "payment-style",
        "mode": "exec",
        "command": (
            "for h in 10.96.0.10 10.96.0.11 10.96.0.12; do "
            "printf 'GET /cache/cluster HTTP/1.0\\r\\nHost: cache\\r\\n\\r\\n' | "
            "nc -u -w 1 198.51.100.22 7777 || true; done"
        ),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-28",
        "template_id": "TMPL-BEN-15",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "payment-style",
        "mode": "exec",
        "command": (
            "dd if=/dev/urandom of=/tmp/backup.dat bs=1M count=4 2>/dev/null; "
            "dd if=/dev/urandom of=/tmp/backup.dat.bak bs=1M count=2 2>/dev/null; "
            "md5sum /tmp/backup.dat /tmp/backup.dat.bak 2>&1; "
            "rm -f /tmp/backup.dat /tmp/backup.dat.bak"
        ),
        "obs": "B",
        "own": "",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Medium",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-29",
        "template_id": "TMPL-BEN-18",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "database",
        "mode": "exec",
        # Configuration sync: a ServiceAccount-authenticated ConfigMap read of
        # the workload's OWN namespace.
        "command": (
            TOKEN_READ + SA_HEADER + "https://10.96.0.1/api/v1/namespaces/tenant-b/configmaps"
        ),
        "obs": "",
        "own": "C",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_ONLY,
        "expect_verbs": ["create", "get", "list"],
        "expect_hubble_band": "MID",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "C",
        "run_id": "run-s4a-r4-30",
        "template_id": "TMPL-BEN-19",
        "threat_class": "benign",
        "namespace": "tenant-c",
        "app": "payment-style",
        "mode": "exec",
        "command": (
            "for h in 10.96.0.10 10.96.0.11; do "
            "printf 'GET /edge/health HTTP/1.0\\r\\n\\r\\n' | "
            "nc -u -w 1 198.51.100.22 4444 || true; done"
        ),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    # ===================== Batch D: benign ======================================
    {
        "batch": "D",
        "run_id": "run-s4a-r4-31",
        "template_id": "TMPL-BEN-20",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "web",
        "mode": "exec",
        "command": "echo p | nc -u -w 1 198.51.100.22 5555 || true",
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
    {
        "batch": "D",
        "run_id": "run-s4a-r4-32",
        "template_id": "TMPL-BEN-21",
        "threat_class": "benign",
        "namespace": "tenant-b",
        "app": "web",
        "mode": "exec",
        "command": (
            "dd if=/dev/zero bs=1M count=1 2>/dev/null | "
            "nc -u -w 1 198.51.100.22 8888 || true; "
            "dd if=/dev/zero bs=1M count=1 2>/dev/null | "
            "nc -u -w 1 198.51.100.22 8888 || true; echo transfer-complete"
        ),
        "obs": "",
        "own": "D",
        "sleep_after": 6,
        "expected_cpu_profile": "low",
        "expect_falco": SHELL_EGRESS,
        "expect_verbs": ["create", "get"],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "intensity": "Low",
    },
]


_OBSERVATIONS: Final[dict[str, str]] = {"A": OBS_A, "B": OBS_B, "C": OBS_C, "D": OBS_D}


def _append_observations(defs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Append the declared D-29 observation to every command that needs one."""
    finalised: list[dict[str, Any]] = []
    for definition in defs:
        item = dict(definition)
        observation = item.get("obs", "")
        if observation:
            item["command"] = f"{item['command']}; {_OBSERVATIONS[observation]}"
        finalised.append(item)
    return finalised


ROUND4_TEMPLATE_DEFS: Final[list[dict[str, Any]]] = _append_observations(_RAW_DEFS)
