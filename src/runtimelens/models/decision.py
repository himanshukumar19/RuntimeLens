"""Decision, classification, and tamper-evident audit record models."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from runtimelens.models.event import CanonicalEvent


class ClassificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    predicted_class: Literal[
        "benign", "container_escape", "privilege_abuse", "cryptomining", "unknown"
    ]
    class_probabilities: dict[str, float] = Field(default_factory=dict)
    severity: float = Field(ge=1.0, le=5.0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_flags: dict[str, float] = Field(default_factory=dict)
    degraded_mode: bool = False
    classifier_type: Literal["rules", "rf", "scaledown"]
    model_version: str = "v1.0.0"
    rubric_version: str | None = None


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["log", "alert", "human_review", "quarantine"]
    reason_codes: list[str] = Field(default_factory=list)
    policy_version: str = "v1.0.0"
    dry_run: bool = True  # Strict SRE default
    quarantine_labels: dict[str, str] | None = None
    auto_rollback_ttl_seconds: int = 900  # Default 15 minutes


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_id: str
    event: CanonicalEvent
    classification: ClassificationResult
    decision: PolicyDecision
    rubric_version: str | None = None
    prev_record_hash: str
    record_hash: str = ""

    def compute_hash(self) -> str:
        """Compute cryptographic SHA-256 hash of canonical JSON excluding record_hash."""
        exclude_fields: set[str] = {"record_hash"}
        if self.rubric_version is None:
            exclude_fields.add("rubric_version")

        data_to_hash: dict[str, Any] = self.model_dump(exclude=exclude_fields)
        if self.classification.rubric_version is None and "rubric_version" in data_to_hash.get(
            "classification", {}
        ):
            del data_to_hash["classification"]["rubric_version"]

        # Backwards compatibility migration policy for pre-v1.0.1 schema records
        if not self.event.edge_case and "edge_case" in data_to_hash.get("event", {}):
            del data_to_hash["event"]["edge_case"]
        if (
            self.event.telemetry_source.source_rule_name is None
            and "source_rule_name" in data_to_hash.get("event", {}).get("telemetry_source", {})
        ):
            del data_to_hash["event"]["telemetry_source"]["source_rule_name"]

        canonical_bytes = json.dumps(data_to_hash, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(canonical_bytes).hexdigest()
