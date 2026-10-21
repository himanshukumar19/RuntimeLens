"""Feature extraction pipeline deriving ML features strictly from raw telemetry (Stage 1).

Strict Anti-Leakage Guarantee:
Extracts features exclusively from raw per-run telemetry directories:
- falco/events.jsonl
- audit/events.jsonl
- hubble/flows.jsonl
- prometheus/metrics.json
- trivy/report.json
- baselines/<workload>.yaml
Zero access to scenario IDs, ground-truth labels, run IDs, or metadata index files.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Final

import numpy as np

from runtimelens.baseline.loader import BaselineStore
from runtimelens.normalizer.hubble import normalize_hubble_flow
from runtimelens.normalizer.trivy import normalize_trivy_report

logger = logging.getLogger("runtimelens.features.extractor")

SHELL_METACHARACTERS_RE: Final[re.Pattern[str]] = re.compile(r"[&|;$`><(){}\"'*\n\r\\]")

CLASS_LABEL_MAP: Final[dict[str, int]] = {
    "benign": 0,
    "container_escape": 1,
    "privilege_abuse": 2,
    "cryptomining": 3,
    "unknown": 4,
}
INVERSE_CLASS_LABEL_MAP: Final[dict[int, str]] = {v: k for k, v in CLASS_LABEL_MAP.items()}

FEATURE_NAMES: Final[list[str]] = [
    "host_runtime_socket_mounted",
    "sensitive_host_path_mounted",
    "privileged_container",
    "is_root_user",
    "is_shell_process",
    "has_shell_metacharacters",
    "is_cpu_abnormal",
    "cpu_usage_mcores",
    "is_outbound_egress",
    "is_cross_tenant_flow",
    "destination_port_3333",
    "baseline_deviation_detected",
    "shell_expected",
    "deviation_count",
    "is_telemetry_degraded",
    "has_critical_vulnerability",
    "orch_verb_exec",
    "orch_verb_get_secret",
]

# Decision D-28: `command_length` is EXCLUDED from the classifier feature set.
#
# The master template registry (`docs/SCENARIO_PLAN_v2.md` §3.6.3) proves that
# the `privilege_abuse` class physically cannot occupy the `30-80` or `81-150`
# command-length bins: the shortest cross-tenant request that the audit
# collector can attribute to a workload's ServiceAccount costs 120 characters
# of shell overhead before the URL, and no request that produces a captured
# audit event fits inside 80 characters. Every `privilege_abuse` template is
# therefore in the `151-250+` bin and every other class has templates in the
# shorter bins, which makes the raw command length a near-perfect class
# marker. A single feature trained on that value reached Macro-F1 = 1.0000 on
# the Stage 4a Part 1 smoke (ten runs, one per template) purely by memorising
# the non-overlapping length ranges.
#
# `command_length` is therefore retained ONLY as a diagnostic, computed by
# `extract_command_length()` and reported by `scripts/verify_dataset.py`. It
# is never part of the vector consumed by the Random Forest baseline or by the
# ScaleDown state.
EXCLUDED_DIAGNOSTIC_FEATURES: Final[tuple[str, ...]] = ("command_length",)


def extract_features_from_run_dir(
    run_dir: Path,
    baseline_store: BaselineStore | None = None,
) -> np.ndarray:
    """Extract 18 numerical feature values strictly from raw telemetry files in run_dir.

    Guarantees zero access to index.json or ground-truth metadata.

    Decision D-28: the returned vector is the *classifier* feature set. It
    deliberately excludes `command_length`, which is only available as a
    diagnostic through `extract_command_length()`.
    """
    if baseline_store is None:
        baseline_store = BaselineStore(Path("baselines"))

    # 0. Parse Pod Specification Facts (Report Section 5.3, Decision D-07)
    pod_spec_file = run_dir / "pod" / "spec.json"
    if not pod_spec_file.exists():
        pod_spec_file = run_dir / "pod_spec.json"

    host_socket = 0.0
    sensitive_path = 0.0
    privileged = 0.0
    has_pod_spec = False

    if pod_spec_file.exists():
        try:
            pod_spec_data = json.loads(pod_spec_file.read_text(encoding="utf-8"))
            spec = pod_spec_data.get("spec", pod_spec_data)
            volumes = spec.get("volumes", [])
            for vol in volumes:
                hp = vol.get("hostPath", {})
                hp_path = str(hp.get("path", "")).lower()
                if "docker.sock" in hp_path or "containerd.sock" in hp_path:
                    host_socket = 1.0
                if (
                    "/etc/kubernetes" in hp_path
                    or "/opt/runtimelens-dummy/etc" in hp_path
                    or "/etc/shadow" in hp_path
                ):
                    sensitive_path = 1.0
            containers = spec.get("containers", [])
            for c in containers:
                sc = c.get("securityContext", {})
                if sc.get("privileged") is True:
                    privileged = 1.0
            has_pod_spec = True
        except Exception:
            pass

    # 1. Parse Falco Telemetry
    falco_file = run_dir / "falco" / "events.jsonl"
    falco_events: list[dict[str, Any]] = []
    if falco_file.exists():
        with open(falco_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        falco_events.append(json.loads(line))
                    except Exception:
                        continue

    root_user = 0.0
    is_shell = 0.0
    has_meta = 0.0
    workload_candidate = "web"

    for evt in falco_events:
        rule = str(evt.get("rule", "")).lower()
        fields = evt.get("output_fields", {})
        cmd = str(fields.get("proc.cmdline") or "")
        fd_name = str(fields.get("fd.name") or "")
        p_name = str(fields.get("proc.name") or "")
        u_name = str(fields.get("user.name") or "")

        if not has_pod_spec:
            if "docker.sock" in fd_name or "docker.sock" in cmd or "socket" in rule:
                host_socket = 1.0

            if (
                "/etc/shadow" in fd_name
                or "/etc/passwd" in fd_name
                or "read sensitive host" in rule
            ):
                sensitive_path = 1.0

            if "privileged" in rule or fields.get("container.privileged") is True:
                privileged = 1.0

        if u_name == "root" or fields.get("user.uid") == 0:
            root_user = 1.0

        if p_name in {"sh", "bash", "zsh"} or "shell" in rule:
            is_shell = 1.0

        if SHELL_METACHARACTERS_RE.search(cmd):
            has_meta = 1.0

        pod_name = str(fields.get("k8s.pod.name") or "")
        if pod_name:
            for w in ["web", "api", "database", "payment-style", "debug", "analytics"]:
                if pod_name.startswith(w):
                    workload_candidate = w
                    break

    # 2. Parse K8s Audit Telemetry
    audit_file = run_dir / "audit" / "events.jsonl"
    audit_events: list[dict[str, Any]] = []
    if audit_file.exists():
        with open(audit_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        audit_events.append(json.loads(line))
                    except Exception:
                        continue

    orch_exec = 0.0
    orch_secret = 0.0

    for item in audit_events:
        verb = str(item.get("verb", "")).lower()
        obj = item.get("objectRef", {})
        res = str(obj.get("resource", "")).lower()
        sub = str(obj.get("subresource", "")).lower()

        if sub == "exec" or "exec" in verb:
            orch_exec = 1.0
        if res == "secrets" or "secret" in res:
            orch_secret = 1.0

    # 3. Parse Hubble Network Flows
    hubble_file = run_dir / "hubble" / "flows.jsonl"
    hubble_flows: list[dict[str, Any]] = []
    if hubble_file.exists():
        with open(hubble_file, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("{"):
                    try:
                        hubble_flows.append(json.loads(line))
                    except Exception:
                        continue

    is_outbound_egress = 0.0
    is_cross_tenant = 0.0
    dest_port_3333 = 0.0

    for flow in hubble_flows:
        ctx, facts = normalize_hubble_flow(flow)
        if facts.get("is_outbound_egress"):
            is_outbound_egress = 1.0
        if facts.get("is_cross_tenant_flow"):
            is_cross_tenant = 1.0
        if ctx.destination_port == 3333:
            dest_port_3333 = 1.0

    # 4. Parse Prometheus / cAdvisor Metrics
    prom_file = run_dir / "prometheus" / "metrics.json"
    cpu_mcores = 0.0
    is_cpu_abnormal = 0.0
    if prom_file.exists():
        try:
            p_data = json.loads(prom_file.read_text(encoding="utf-8"))
            samples = p_data.get("samples", [])
            stats_list: list[dict[str, Any]] = []
            if samples:
                for s in samples:
                    stats_list.extend(s.get("pod_stats", []))
            else:
                stats_list = p_data.get("pod_stats", [])

            for p in stats_list:
                containers = p.get("containers", [])
                for c in containers:
                    cpu = c.get("cpu", {})
                    nano_cores = float(cpu.get("usageNanoCores", 0.0))
                    c_mcores = nano_cores / 1e6
                    if c_mcores > cpu_mcores:
                        cpu_mcores = c_mcores
            # CPU anomaly threshold: > 75 mcores (3x baseline envelope of 25m)
            if cpu_mcores >= 75.0:
                is_cpu_abnormal = 1.0
        except Exception:
            pass

    # 5. Parse Trivy Static Vulnerability Report
    trivy_file = run_dir / "trivy" / "report.json"
    has_crit_vuln = 0.0
    if trivy_file.exists():
        try:
            t_data = json.loads(trivy_file.read_text(encoding="utf-8"))
            has_crit, _ = normalize_trivy_report(t_data)
            if has_crit:
                has_crit_vuln = 1.0
        except Exception:
            pass

    # 6. Compare with Workload Baseline Profile
    baseline = baseline_store.get_baseline(workload_candidate)
    shell_expected = 0.0
    baseline_dev = 0.0
    dev_count = 0.0

    if baseline:
        shell_expected = 1.0 if baseline.runtime.shell_allowed else 0.0
        # If shell ran but not expected, deviation
        if is_shell == 1.0 and shell_expected == 0.0:
            baseline_dev = 1.0
            dev_count += 1.0
        if host_socket == 1.0 or sensitive_path == 1.0:
            baseline_dev = 1.0
            dev_count += 1.0
        if cpu_mcores > baseline.resources.cpu_max_envelope_mcores:
            baseline_dev = 1.0
            dev_count += 1.0
        if is_cross_tenant == 1.0 or is_outbound_egress == 1.0:
            baseline_dev = 1.0
            dev_count += 1.0

    # 7. Telemetry Degradation Check
    is_degraded = 1.0 if (len(falco_events) == 0 and len(audit_events) == 0) else 0.0

    vector = [
        host_socket,
        sensitive_path,
        privileged,
        root_user,
        is_shell,
        has_meta,
        is_cpu_abnormal,
        cpu_mcores,
        is_outbound_egress,
        is_cross_tenant,
        dest_port_3333,
        baseline_dev,
        shell_expected,
        dev_count,
        is_degraded,
        has_crit_vuln,
        orch_exec,
        orch_secret,
    ]
    assert len(vector) == len(FEATURE_NAMES)
    return np.array(vector, dtype=np.float32)


def extract_command_length(run_dir: Path) -> float:
    """Diagnostic-only helper: the longest observed `proc.cmdline` length in a run.

    Decision D-28: this value is EXCLUDED from the classifier feature set
    (`FEATURE_NAMES`) because the master template registry proves that command
    length is a near-perfect class marker for this dataset. It is retained so
    that `scripts/verify_dataset.py` can keep reporting it as a diagnostic and
    so that the confound stays visible instead of being silently dropped.
    """
    falco_file = run_dir / "falco" / "events.jsonl"
    max_cmd_len = 0.0
    if not falco_file.exists():
        return max_cmd_len
    with open(falco_file, encoding="utf-8") as f:
        for line in f:
            if not line.strip().startswith("{"):
                continue
            try:
                evt = json.loads(line)
            except Exception:
                continue
            cmd = str(evt.get("output_fields", {}).get("proc.cmdline") or "")
            max_cmd_len = max(max_cmd_len, float(len(cmd)))
    return max_cmd_len


def extract_dataset_from_run_dirs(
    run_dirs: list[Path],
    baseline_store: BaselineStore | None = None,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extract feature matrix X, label vector y, and run IDs from per-run directories.

    Labels are read ONLY from index.json for evaluation, NEVER passed to extract_features.
    """
    if baseline_store is None:
        baseline_store = BaselineStore(Path("baselines"))

    features_list: list[np.ndarray] = []
    labels_list: list[int] = []
    ids_list: list[str] = []

    for r_dir in run_dirs:
        # Extract features strictly from telemetry files
        vec = extract_features_from_run_dir(r_dir, baseline_store=baseline_store)

        # Ground truth label read ONLY for target vector y
        index_file = r_dir / "index.json"
        c_name = "benign"
        run_id = r_dir.name
        if index_file.exists():
            try:
                idx_data = json.loads(index_file.read_text(encoding="utf-8"))
                c_name = str(idx_data.get("threat_class", "benign"))
                run_id = str(idx_data.get("run_id", r_dir.name))
            except Exception:
                pass

        label_idx = CLASS_LABEL_MAP.get(c_name, 0)
        features_list.append(vec)
        labels_list.append(label_idx)
        ids_list.append(run_id)

    X = np.vstack(features_list)
    y = np.array(labels_list, dtype=np.int64)
    return X, y, ids_list
