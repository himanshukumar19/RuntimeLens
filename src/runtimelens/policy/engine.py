"""Deterministic safety policy engine enforcing SRE containment guardrails."""

from __future__ import annotations

from runtimelens.models.decision import ClassificationResult, PolicyDecision
from runtimelens.models.event import CanonicalEvent

ALLOWED_QUARANTINE_NAMESPACES = frozenset({"tenant-a", "tenant-b", "tenant-c"})
FORBIDDEN_SYSTEM_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "cilium",
        "falco",
        "monitoring",
        "runtimelens",
    }
)


def evaluate_policy(
    classification: ClassificationResult,
    event: CanonicalEvent,
    dry_run: bool = True,
) -> PolicyDecision:
    """Evaluate pure deterministic containment policy for a classified incident."""
    facts = event.facts
    baseline = event.baseline
    health = event.health
    namespace = event.workload.namespace
    reason_codes: list[str] = []

    # 1. Critical Safety Overrides (Highest Precedence)
    if health.is_telemetry_degraded:
        return PolicyDecision(
            action="human_review",
            reason_codes=["ERR_TELEMETRY_DEGRADED"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if classification.degraded_mode:
        return PolicyDecision(
            action="human_review",
            reason_codes=["ERR_MODEL_DEGRADED"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if baseline.is_baseline_stale and classification.predicted_class != "benign":
        return PolicyDecision(
            action="human_review",
            reason_codes=["ERR_BASELINE_STALE"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    # Deterministic physical fact override: host socket / sensitive path mount
    if facts.host_runtime_socket_mounted or facts.sensitive_host_path_mounted:
        reason_codes.append("OVERRIDE_HOST_PATH_MOUNTED")
        if classification.predicted_class == "benign":
            return PolicyDecision(
                action="human_review",
                reason_codes=["OVERRIDE_CRITICAL_FACT_MISMATCH", "OVERRIDE_HOST_PATH_MOUNTED"],
                policy_version="v1.0.0",
                dry_run=dry_run,
            )

    # 2. Table-Driven Choice-Noul Conflict Resolution
    flags = classification.evidence_flags
    c_class = classification.predicted_class

    if c_class == "unknown":
        return PolicyDecision(
            action="human_review",
            reason_codes=["CLASS_UNKNOWN"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if (
        not event.edge_case
        and c_class == "benign"
        and (
            flags.get("baseline_deviation", 0.0) > 0.6 or flags.get("resource_exposure", 0.0) > 0.6
        )
    ):
        return PolicyDecision(
            action="human_review",
            reason_codes=["CONFLICT_BENIGN_WITH_EVIDENCE"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if c_class == "container_escape" and (
        flags.get("resource_exposure", 0.0) < 0.3 and flags.get("shell_unexpected", 0.0) < 0.3
    ):
        return PolicyDecision(
            action="human_review",
            reason_codes=["CONFLICT_ESCAPE_WITHOUT_EVIDENCE"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if c_class == "privilege_abuse" and flags.get("baseline_deviation", 0.0) < 0.3:
        return PolicyDecision(
            action="human_review",
            reason_codes=["CONFLICT_PRIVILEGE_WITHOUT_DEVIATION"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    if c_class == "cryptomining" and flags.get("resource_abuse", 0.0) < 0.3:
        return PolicyDecision(
            action="human_review",
            reason_codes=["CONFLICT_MINING_WITHOUT_RESOURCE_ABUSE"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    # 3. Confidence & Severity Action Tiers
    # Low confidence (< 0.70) routes to human review (applies only to calibrated models;
    # confidence=None for rule baselines bypasses this gate)
    if classification.confidence is not None and classification.confidence < 0.70:
        return PolicyDecision(
            action="human_review",
            reason_codes=["LOW_CONFIDENCE_GATE"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    # Low-priority alert for unconfirmed identity file read (fires BEFORE benign log action)
    if "sensitive_identity_file_access" in baseline.deviations and classification.severity <= 2.5:
        return PolicyDecision(
            action="alert",
            reason_codes=["LOW_SEVERITY_IDENTITY_READ_ALERT"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    # Routine Benign
    if c_class == "benign":
        return PolicyDecision(
            action="log",
            reason_codes=["BENIGN_VERIFIED"],
            policy_version="v1.0.0",
            dry_run=dry_run,
        )

    # Containment Quarantine (Severity >= 4.0, Confidence >= 0.70, Allowlisted namespace)
    if classification.severity >= 4.0:
        is_forbidden = (
            namespace in FORBIDDEN_SYSTEM_NAMESPACES
            or namespace not in ALLOWED_QUARANTINE_NAMESPACES
        )
        if is_forbidden:
            reason_codes.append("QUARANTINE_BLOCKED_SYSTEM_NAMESPACE")
            return PolicyDecision(
                action="alert",
                reason_codes=reason_codes,
                policy_version="v1.0.0",
                dry_run=dry_run,
            )

        reason_codes.append("HIGH_SEVERITY_CONTAINMENT")
        return PolicyDecision(
            action="quarantine",
            reason_codes=reason_codes,
            policy_version="v1.0.0",
            dry_run=dry_run,
            quarantine_labels={"quarantine": "true"},
            auto_rollback_ttl_seconds=900,
        )

    # Medium Severity Alert (Severity >= 3.0)
    reason_codes.append("THREAT_DETECTED")
    return PolicyDecision(
        action="alert",
        reason_codes=reason_codes,
        policy_version="v1.0.0",
        dry_run=dry_run,
    )
