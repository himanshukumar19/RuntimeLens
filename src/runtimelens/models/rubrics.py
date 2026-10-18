"""Versioned rubric definitions for ScaleDown Decisions API (Decision D-04, D-11)."""

from __future__ import annotations

from typing import Any, Final

RUBRIC_VERSION: Final[str] = "v1.0.0"

QUESTION_CHOICE: Final[dict[str, Any]] = {
    "type": "choice",
    "instructions": "Which single category best describes the observed Kubernetes activity?",
    "criteria": {
        "benign": "Expected workload operation, routine maintenance, or normal deployment.",
        "container_escape": "Suspicious interaction with the host kernel or runtime sockets.",
        "privilege_abuse": "Misuse of permissions or unexpected process execution into container.",
        "cryptomining": "Sustained abnormal compute coupled with suspicious mining pool flows.",
        "unknown": "Telemetry is conflicting, truncated, or insufficient.",
    },
}

QUESTION_SCORE: Final[dict[str, Any]] = {
    "type": "score",
    "instructions": "Evaluate the operational and security severity of this runtime event.",
    "criteria": [
        "Informational: Standard expected activity or benign baseline event.",
        "Low: Minor anomaly with high likelihood of benign intent.",
        "Medium: Suspicious policy violation requiring investigation.",
        "High: Clear indicator of compromise or unauthorized privilege access.",
        "Critical: Active confirmed container breakout or cluster-wide compromise.",
    ],
}

QUESTIONS_NOUL: Final[dict[str, Any]] = {
    "baseline_deviation": {
        "type": "noul",
        "instructions": (
            "Is this activity inconsistent with the workload's documented baseline profile?"
        ),
    },
    "shell_unexpected": {
        "type": "noul",
        "instructions": "Is an interactive shell execution unexpected for this workload?",
    },
    "resource_exposure": {
        "type": "noul",
        "instructions": (
            "Does this event grant the container unauthorized access to host resources?"
        ),
    },
    "resource_abuse": {
        "type": "noul",
        "instructions": ("Is the observed compute and network behaviour consistent with mining?"),
    },
}
