"""Exposure-based continuous risk scoring engine (Ticket 15, Extension 4).

Combines classifier severity score (1.0 - 5.0) with workload exposure metadata:
- Ingress/egress exposure factor (e.g., internet-facing vs internal-only).
- Static image vulnerabilities (critical CVE factor from Trivy).
- Namespace criticality weight (tenant-a/b/c vs sandbox).

Produces a normalized continuous RiskScore (0.0 to 10.0) mapped to risk tiers:
- LOW: [0.0, 4.0)
- MEDIUM: [4.0, 7.0)
- HIGH: [7.0, 9.0)
- CRITICAL: [9.0, 10.0]
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from runtimelens.models.decision import ClassificationResult
from runtimelens.models.event import CanonicalEvent

# Standard multi-tenant namespace criticality weights
DEFAULT_NAMESPACE_WEIGHTS: Final[dict[str, float]] = {
    "tenant-a": 1.00,
    "tenant-b": 1.00,
    "tenant-c": 1.00,
    "production": 1.00,
    "payment": 1.00,
    "default": 0.80,
    "system": 0.80,
    "staging": 0.70,
    "sandbox": 0.50,
    "dev": 0.50,
    "test": 0.50,
}

# Network exposure factors
FACTOR_INTERNET_FACING: Final[float] = 1.25
FACTOR_OUTBOUND_EGRESS: Final[float] = 1.10
FACTOR_INTERNAL_ONLY: Final[float] = 0.90


class RiskTier(StrEnum):
    """Categorical risk tier derived from continuous RiskScore."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ExposureMetadata(BaseModel):
    """Workload exposure and vulnerability metadata."""

    model_config = ConfigDict(extra="forbid")

    is_internet_facing: bool = False
    is_outbound_egress: bool = False
    has_critical_vulnerability: bool = False
    critical_cve_count: int = Field(default=0, ge=0)
    namespace: str = "tenant-a"
    custom_namespace_weight: float | None = Field(default=None, ge=0.0, le=2.0)
    custom_exposure_factor: float | None = Field(default=None, ge=0.0, le=3.0)


class RiskScore(BaseModel):
    """Continuous risk score and environmental factor breakdown."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=10.0, description="Normalized risk score [0.0, 10.0]")
    tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(description="Categorical risk tier")
    severity_score: float = Field(
        ge=1.0, le=5.0, description="Input classifier severity [1.0, 5.0]"
    )
    exposure_factor: float = Field(ge=0.0, description="Network ingress/egress exposure factor")
    cve_factor: float = Field(ge=1.0, description="Static image CVE vulnerability factor")
    namespace_weight: float = Field(ge=0.0, description="Namespace criticality weight")
    details: dict[str, Any] = Field(default_factory=dict, description="Diagnostic breakdown")


def resolve_namespace_weight(namespace: str, custom_weight: float | None = None) -> float:
    """Resolve criticality weight for a given namespace."""
    if custom_weight is not None:
        return custom_weight
    ns_clean = namespace.strip().lower()
    if ns_clean in DEFAULT_NAMESPACE_WEIGHTS:
        return DEFAULT_NAMESPACE_WEIGHTS[ns_clean]
    if ns_clean.startswith("tenant-"):
        return 1.00
    if "sandbox" in ns_clean or "test" in ns_clean or "dev" in ns_clean:
        return 0.50
    return DEFAULT_NAMESPACE_WEIGHTS.get("default", 0.80)


def resolve_exposure_factor(
    is_internet_facing: bool,
    is_outbound_egress: bool,
    custom_factor: float | None = None,
) -> float:
    """Resolve network exposure factor based on ingress/egress posture."""
    if custom_factor is not None:
        return custom_factor
    if is_internet_facing:
        return FACTOR_INTERNET_FACING
    if is_outbound_egress:
        return FACTOR_OUTBOUND_EGRESS
    return FACTOR_INTERNAL_ONLY


def resolve_cve_factor(has_critical_vulnerability: bool, critical_cve_count: int) -> float:
    """Resolve static CVE vulnerability factor from Trivy findings."""
    if not has_critical_vulnerability and critical_cve_count == 0:
        return 1.00
    if critical_cve_count > 0:
        # Scales continuously with CVE count up to a +0.25 ceiling
        return round(1.00 + min(0.25, 0.05 * critical_cve_count), 4)
    # Boolean flag present without explicit count
    return 1.15


def determine_risk_tier(score: float) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    """Map continuous score [0.0, 10.0] to discrete RiskTier."""
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def compute_risk_score(
    severity: float,
    exposure: ExposureMetadata | None = None,
    *,
    is_internet_facing: bool = False,
    is_outbound_egress: bool = False,
    has_critical_vulnerability: bool = False,
    critical_cve_count: int = 0,
    namespace: str = "tenant-a",
    custom_namespace_weight: float | None = None,
    custom_exposure_factor: float | None = None,
) -> RiskScore:
    """Compute exposure-based continuous risk score combining severity and exposure metadata.

    Args:
        severity: Classifier severity in range [1.0, 5.0].
        exposure: Structured ExposureMetadata object (takes precedence over keyword args).
        is_internet_facing: Whether workload is exposed to ingress from internet.
        is_outbound_egress: Whether workload initiates external egress.
        has_critical_vulnerability: Whether Trivy detected critical CVEs.
        critical_cve_count: Count of critical CVEs.
        namespace: Target Kubernetes namespace.
        custom_namespace_weight: Optional explicit override for namespace weight.
        custom_exposure_factor: Optional explicit override for exposure factor.

    Returns:
        RiskScore object with continuous score [0.0, 10.0] and risk tier.
    """
    if severity < 1.0 or severity > 5.0:
        raise ValueError(f"Severity must be in range [1.0, 5.0], got {severity}")

    if exposure is not None:
        exp_meta = exposure
    else:
        exp_meta = ExposureMetadata(
            is_internet_facing=is_internet_facing,
            is_outbound_egress=is_outbound_egress,
            has_critical_vulnerability=has_critical_vulnerability,
            critical_cve_count=critical_cve_count,
            namespace=namespace,
            custom_namespace_weight=custom_namespace_weight,
            custom_exposure_factor=custom_exposure_factor,
        )

    exposure_factor = resolve_exposure_factor(
        exp_meta.is_internet_facing,
        exp_meta.is_outbound_egress,
        exp_meta.custom_exposure_factor,
    )
    cve_factor = resolve_cve_factor(
        exp_meta.has_critical_vulnerability,
        exp_meta.critical_cve_count,
    )
    ns_weight = resolve_namespace_weight(
        exp_meta.namespace,
        exp_meta.custom_namespace_weight,
    )

    # Base severity scaled to [2.0, 10.0]
    base_severity = 2.0 * severity

    # Multiplicative exposure adjustment
    raw_score = base_severity * exposure_factor * cve_factor * ns_weight

    # Strictly normalize and clamp to [0.0, 10.0]
    normalized_score = round(min(10.0, max(0.0, raw_score)), 2)
    tier = determine_risk_tier(normalized_score)

    details = {
        "raw_score": round(raw_score, 4),
        "base_severity": base_severity,
        "exposure_factor": exposure_factor,
        "cve_factor": cve_factor,
        "namespace_weight": ns_weight,
        "namespace": exp_meta.namespace,
        "is_internet_facing": exp_meta.is_internet_facing,
        "is_outbound_egress": exp_meta.is_outbound_egress,
        "has_critical_vulnerability": exp_meta.has_critical_vulnerability,
        "critical_cve_count": exp_meta.critical_cve_count,
    }

    return RiskScore(
        score=normalized_score,
        tier=tier,
        severity_score=severity,
        exposure_factor=exposure_factor,
        cve_factor=cve_factor,
        namespace_weight=ns_weight,
        details=details,
    )


def evaluate_event_risk_score(
    classification: ClassificationResult,
    event: CanonicalEvent,
    *,
    is_internet_facing: bool | None = None,
    critical_cve_count: int | None = None,
    custom_namespace_weight: float | None = None,
    custom_exposure_factor: float | None = None,
) -> RiskScore:
    """Evaluate continuous risk score directly from a CanonicalEvent and ClassificationResult.

    Extracts exposure context from event facts, baseline, and workload identity.
    """
    # Infer internet-facing status from workload identity or override
    if is_internet_facing is not None:
        facing = is_internet_facing
    else:
        facing = event.workload.owner_workload.lower() in {"web", "ingress", "gateway"}

    # Infer critical vulnerability from deterministic facts
    has_crit_vuln = event.facts.has_critical_vulnerability
    cve_cnt = critical_cve_count if critical_cve_count is not None else 0

    # Infer outbound egress from facts or network context
    outbound = event.facts.is_outbound_egress or (
        event.network is not None and event.network.verdict == "FORWARDED"
    )

    metadata = ExposureMetadata(
        is_internet_facing=facing,
        is_outbound_egress=outbound,
        has_critical_vulnerability=has_crit_vuln,
        critical_cve_count=cve_cnt,
        namespace=event.workload.namespace,
        custom_namespace_weight=custom_namespace_weight,
        custom_exposure_factor=custom_exposure_factor,
    )

    return compute_risk_score(severity=classification.severity, exposure=metadata)
