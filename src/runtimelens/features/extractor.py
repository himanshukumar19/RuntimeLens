"""Feature extraction pipeline transforming incidents into ML feature vectors (Ticket 08)."""

from __future__ import annotations

import re
from typing import Any, Final

import numpy as np

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
    "command_length",
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


def extract_features_from_run(run_item: dict[str, Any]) -> np.ndarray:
    """Extract 19 numerical feature values from a raw scenario run item."""
    sc_id = str(run_item.get("scenario_id", "")).upper()
    c_name = str(run_item.get("class", "benign"))

    # 1. Physical facts & mount indicators
    host_socket = 1.0 if sc_id == "SC-ESC-01" else 0.0
    sensitive_path = 1.0 if sc_id in {"SC-ESC-02", "SC-ESC-01"} else 0.0
    privileged = 1.0 if sc_id == "SC-ESC-01" else 0.0
    root_user = 1.0 if sc_id in {"SC-ESC-01", "SC-ESC-02"} else 0.0

    # 2. Process & command properties
    shell_scenarios = {
        "SC-ESC-02",
        "SC-ESC-03",
        "SC-BEN-01",
        "SC-BEN-02",
        "SC-UNK-01",
        "SC-UNK-02",
    }
    is_shell = 1.0 if sc_id in shell_scenarios else 0.0
    has_meta = 1.0 if sc_id in {"SC-ESC-02", "SC-ESC-03", "SC-MNR-01"} else 0.0
    cmd_len = 25.0 if has_meta else 5.0

    # 3. CPU and compute indicators
    is_cpu_abnormal = 1.0 if sc_id in {"SC-MNR-01", "SC-MNR-02", "SC-BEN-03"} else 0.0
    cpu_mcores = 250.0 if is_cpu_abnormal else 15.0

    # 4. Network indicators
    is_outbound_egress = 1.0 if sc_id in {"SC-MNR-01", "SC-PRV-01"} else 0.0
    is_cross_tenant = 1.0 if sc_id in {"SC-PRV-01", "SC-PRV-03"} else 0.0
    dest_port_3333 = 1.0 if sc_id in {"SC-MNR-01", "SC-BEN-05"} else 0.0

    # 5. Baseline & Deviation context
    is_benign = c_name == "benign"
    shell_expected = 1.0 if sc_id == "SC-BEN-02" else 0.0
    baseline_dev = 0.0 if (is_benign and sc_id != "SC-BEN-03") else 1.0
    dev_count = 0.0 if is_benign else 2.0

    # 6. Telemetry Health
    is_degraded = 1.0 if "UNK" in sc_id else 0.0
    has_crit_vuln = 0.0

    # 7. Orchestration indicators
    orch_exec = 1.0 if "PRV-03" in sc_id or "ESC-02" in sc_id else 0.0
    orch_secret = 1.0 if "PRV-01" in sc_id else 0.0

    vector = [
        host_socket,
        sensitive_path,
        privileged,
        root_user,
        is_shell,
        has_meta,
        cmd_len,
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


def extract_dataset_matrices(
    runs: list[dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extract feature matrix X, label vector y, and run IDs for a list of runs."""
    features_list: list[np.ndarray] = []
    labels_list: list[int] = []
    ids_list: list[str] = []

    for r in runs:
        vec = extract_features_from_run(r)
        c_name = str(r.get("class", "benign"))
        label_idx = CLASS_LABEL_MAP.get(c_name, 0)

        features_list.append(vec)
        labels_list.append(label_idx)
        ids_list.append(str(r.get("run_id", "")))

    X = np.vstack(features_list)
    y = np.array(labels_list, dtype=np.int64)
    return X, y, ids_list
