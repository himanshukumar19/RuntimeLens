"""Rule-based minimal classifier mapping CanonicalEvent to ClassificationResult."""

from __future__ import annotations

from typing import Literal

from runtimelens.models.decision import ClassificationResult
from runtimelens.models.event import CanonicalEvent


def classify_rules(event: CanonicalEvent) -> ClassificationResult:
    """Classify a CanonicalEvent using deterministic rule heuristics."""
    facts = event.facts
    baseline = event.baseline

    # Compute continuous evidence probabilities
    evidence_flags: dict[str, float] = {
        "baseline_deviation": 1.0 if baseline.baseline_deviation_detected else 0.0,
        "shell_unexpected": (
            1.0 if (facts.is_shell_process and not baseline.shell_expected) else 0.0
        ),
        "resource_exposure": (
            1.0 if (facts.host_runtime_socket_mounted or facts.sensitive_host_path_mounted) else 0.0
        ),
        "resource_abuse": 1.0 if facts.is_cpu_abnormal else 0.0,
    }

    predicted_class: Literal[
        "benign", "container_escape", "privilege_abuse", "cryptomining", "unknown"
    ]
    severity: float
    confidence: float

    # Priority 1: Container Escape indicators (e.g. host socket / sensitive mount)
    if facts.host_runtime_socket_mounted or facts.sensitive_host_path_mounted:
        predicted_class = "container_escape"
        severity = 5.0
        confidence = 0.95
        probs = {"container_escape": 0.95, "privilege_abuse": 0.03, "benign": 0.02}

    # Priority 2: Cryptomining multi-signal
    elif facts.is_cpu_abnormal and facts.is_outbound_egress:
        predicted_class = "cryptomining"
        severity = 4.0
        confidence = 0.90
        probs = {"cryptomining": 0.90, "privilege_abuse": 0.05, "benign": 0.05}

    # Priority 3: Privilege Abuse (Unexpected shell or unauthorized binary)
    elif facts.is_shell_process and not baseline.shell_expected:
        predicted_class = "privilege_abuse"
        severity = 3.8
        confidence = 0.85
        probs = {"privilege_abuse": 0.85, "container_escape": 0.10, "benign": 0.05}

    # Priority 4: General baseline deviation
    elif baseline.baseline_deviation_detected:
        predicted_class = "privilege_abuse"
        severity = 3.2
        confidence = 0.75
        probs = {"privilege_abuse": 0.75, "container_escape": 0.10, "benign": 0.15}

    # Baseline Benign
    else:
        predicted_class = "benign"
        severity = 1.0
        confidence = 0.90
        probs = {"benign": 0.90, "privilege_abuse": 0.05, "unknown": 0.05}

    return ClassificationResult(
        predicted_class=predicted_class,
        class_probabilities=probs,
        severity=severity,
        confidence=confidence,
        evidence_flags=evidence_flags,
        degraded_mode=False,
        classifier_type="rules",
        model_version="v1.0.0",
    )
