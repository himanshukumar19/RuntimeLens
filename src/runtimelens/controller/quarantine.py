"""SRE Response Controller: Label-based quarantine and automated TTL rollback (Ticket 13b).

Governed by:
- SRE Containment Specification (docs/RESPONSE_AND_SAFETY.md)
- Decisions D-13, D-19 (Deterministic policy engine & dry-run default)
- Zero Pod Deletion Invariant (Phase 9 & Checkpoint J)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from runtimelens.models.decision import PolicyDecision
from runtimelens.models.event import CanonicalEvent
from runtimelens.policy.engine import ALLOWED_QUARANTINE_NAMESPACES, FORBIDDEN_SYSTEM_NAMESPACES

logger = logging.getLogger("runtimelens.controller.quarantine")

DEFAULT_QUARANTINE_TTL_SECONDS: Final[int] = 900  # 15 minutes
QUARANTINE_LABEL_KEY: Final[str] = "quarantine"
QUARANTINE_LABEL_VALUE: Final[str] = "true"

QuarantineStatus = Literal["active", "rolled_back", "promoted", "failed"]


class QuarantineActionRecord(BaseModel):
    """Tamper-evident record of an automated or dry-run quarantine containment action."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    event_id: str
    namespace: str
    pod_name: str
    pod_uid: str
    quarantine_labels: dict[str, str] = Field(
        default_factory=lambda: {QUARANTINE_LABEL_KEY: QUARANTINE_LABEL_VALUE}
    )
    initiated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    ttl_seconds: int = DEFAULT_QUARANTINE_TTL_SECONDS
    expires_at: str
    status: QuarantineStatus = "active"
    dry_run: bool = True
    diff: dict[str, Any] = Field(default_factory=dict)
    rollback_at: str | None = None
    rollback_reason: str | None = None
    error_message: str | None = None


class KubernetesClientProtocol(Protocol):
    """Protocol for Kubernetes pod label patching without pod deletion capability."""

    def patch_pod_labels(
        self,
        namespace: str,
        pod_name: str,
        labels: dict[str, str | None],
    ) -> bool:
        """Patch pod metadata labels. Setting a label value to None removes the label."""
        ...

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str]:
        """Fetch current pod labels."""
        ...

    def can_delete_pods(self) -> bool:
        """SRE safety assertion: returns whether the client has pod deletion permissions."""
        ...


class MockKubernetesClient:
    """In-memory Kubernetes client for deterministic offline testing and simulation."""

    def __init__(self, initial_pods: dict[str, dict[str, str]] | None = None) -> None:
        # Key format: f"{namespace}/{pod_name}" -> dict of labels
        self.pods: dict[str, dict[str, str]] = initial_pods or {}
        self.patch_log: list[dict[str, Any]] = []

    def _pod_key(self, namespace: str, pod_name: str) -> str:
        return f"{namespace}/{pod_name}"

    def ensure_pod(
        self, namespace: str, pod_name: str, labels: dict[str, str] | None = None
    ) -> None:
        key = self._pod_key(namespace, pod_name)
        if key not in self.pods:
            self.pods[key] = dict(labels or {})

    def patch_pod_labels(
        self,
        namespace: str,
        pod_name: str,
        labels: dict[str, str | None],
    ) -> bool:
        key = self._pod_key(namespace, pod_name)
        current = self.pods.setdefault(key, {})
        for k, v in labels.items():
            if v is None:
                current.pop(k, None)
            else:
                current[k] = v
        self.patch_log.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "namespace": namespace,
                "pod_name": pod_name,
                "patch": labels,
            }
        )
        return True

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str]:
        key = self._pod_key(namespace, pod_name)
        return dict(self.pods.get(key, {}))

    def can_delete_pods(self) -> bool:
        """Safety invariant: Controller client must never possess pod delete permissions."""
        return False


class QuarantineController:
    """Manages label-based pod quarantine, dry-run diffs, and automatic TTL rollback."""

    def __init__(
        self,
        k8s_client: KubernetesClientProtocol | None = None,
        audit_file: Path | None = None,
    ) -> None:
        self.client: KubernetesClientProtocol = k8s_client or MockKubernetesClient()
        self.audit_file: Path | None = audit_file
        self.actions: dict[str, QuarantineActionRecord] = {}

        # SRE Safety Invariant Verification on initialization
        if self.client.can_delete_pods():
            raise PermissionError(
                "CRITICAL SRE SAFETY VIOLATION: QuarantineController detected pod delete "
                "permissions in Kubernetes client. Zero pod delete verbs permitted."
            )

    def _persist_action(self, record: QuarantineActionRecord) -> None:
        self.actions[record.action_id] = record
        if self.audit_file is not None:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.model_dump(), sort_keys=True) + "\n")

    def apply_decision(
        self,
        decision: PolicyDecision,
        event: CanonicalEvent,
        incident_id: str | None = None,
    ) -> QuarantineActionRecord | None:
        """Apply a PolicyDecision if the action indicates quarantine containment."""
        if decision.action != "quarantine":
            return None

        inc_id = incident_id or f"inc-{event.event_id}"
        return self.quarantine_pod(
            namespace=event.workload.namespace,
            pod_name=event.workload.pod_name,
            pod_uid=event.workload.pod_uid,
            incident_id=inc_id,
            event_id=event.event_id,
            ttl_seconds=decision.auto_rollback_ttl_seconds,
            dry_run=decision.dry_run,
        )

    def quarantine_pod(
        self,
        namespace: str,
        pod_name: str,
        pod_uid: str,
        incident_id: str,
        event_id: str,
        ttl_seconds: int = DEFAULT_QUARANTINE_TTL_SECONDS,
        dry_run: bool = True,
    ) -> QuarantineActionRecord:
        """Isolate a pod via metadata label patch, or calculate dry-run diff."""
        # 1. Guard against quarantine in forbidden / system namespaces
        is_disallowed = (
            namespace in FORBIDDEN_SYSTEM_NAMESPACES
            or namespace not in ALLOWED_QUARANTINE_NAMESPACES
        )
        if is_disallowed:
            logger.error(
                "Refusing quarantine for pod %s in non-allowlisted namespace %s",
                pod_name,
                namespace,
            )
            now_iso = datetime.now(UTC).isoformat()
            record = QuarantineActionRecord(
                incident_id=incident_id,
                event_id=event_id,
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                initiated_at=now_iso,
                ttl_seconds=ttl_seconds,
                expires_at=now_iso,
                status="failed",
                dry_run=dry_run,
                error_message=f"Namespace '{namespace}' is not in ALLOWED_QUARANTINE_NAMESPACES",
            )
            self._persist_action(record)
            return record

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        patch_labels = {QUARANTINE_LABEL_KEY: QUARANTINE_LABEL_VALUE}
        diff = {
            "metadata": {
                "labels": patch_labels,
            }
        }

        if dry_run:
            logger.info(
                "[DRY-RUN] Quarantine diff calculated for %s/%s (expires: %s)",
                namespace,
                pod_name,
                expires_at.isoformat(),
            )
            record = QuarantineActionRecord(
                incident_id=incident_id,
                event_id=event_id,
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                quarantine_labels=patch_labels,
                initiated_at=now.isoformat(),
                ttl_seconds=ttl_seconds,
                expires_at=expires_at.isoformat(),
                status="active",
                dry_run=True,
                diff=diff,
            )
            self._persist_action(record)
            return record

        # 2. Live Actuation (dry_run == False)
        try:
            logger.warning(
                "[LIVE ACTUATION] Patching pod %s/%s with quarantine label",
                namespace,
                pod_name,
            )
            success = self.client.patch_pod_labels(
                namespace=namespace,
                pod_name=pod_name,
                labels={QUARANTINE_LABEL_KEY: QUARANTINE_LABEL_VALUE},
            )
            status: QuarantineStatus = "active" if success else "failed"
            record = QuarantineActionRecord(
                incident_id=incident_id,
                event_id=event_id,
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                quarantine_labels=patch_labels,
                initiated_at=now.isoformat(),
                ttl_seconds=ttl_seconds,
                expires_at=expires_at.isoformat(),
                status=status,
                dry_run=False,
                diff=diff,
                error_message=None if success else "Kubernetes label patch failed",
            )
        except Exception as e:
            logger.exception("Failed to patch pod labels for %s/%s", namespace, pod_name)
            record = QuarantineActionRecord(
                incident_id=incident_id,
                event_id=event_id,
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                quarantine_labels=patch_labels,
                initiated_at=now.isoformat(),
                ttl_seconds=ttl_seconds,
                expires_at=expires_at.isoformat(),
                status="failed",
                dry_run=False,
                diff=diff,
                error_message=str(e),
            )

        self._persist_action(record)
        return record

    def rollback_quarantine(
        self,
        action_id: str,
        reason: str = "TTL expired without analyst confirmation",
    ) -> QuarantineActionRecord:
        """Roll back an active quarantine by removing the quarantine label."""
        if action_id not in self.actions:
            raise KeyError(f"Quarantine action {action_id} not found")

        record = self.actions[action_id]
        if record.status != "active":
            logger.info(
                "Action %s already transitioned to status %s; skipping rollback",
                action_id,
                record.status,
            )
            return record

        now_iso = datetime.now(UTC).isoformat()
        if not record.dry_run:
            logger.info("Executing live rollback for pod %s/%s", record.namespace, record.pod_name)
            # Remove quarantine label by patching key with None
            self.client.patch_pod_labels(
                namespace=record.namespace,
                pod_name=record.pod_name,
                labels={QUARANTINE_LABEL_KEY: None},
            )

        updated_record = record.model_copy(
            update={
                "status": "rolled_back",
                "rollback_at": now_iso,
                "rollback_reason": reason,
            }
        )
        self._persist_action(updated_record)
        return updated_record

    def promote_quarantine(
        self,
        action_id: str,
        reason: str = "Analyst confirmed threat incident",
    ) -> QuarantineActionRecord:
        """Promote quarantine: cancel auto-rollback and maintain isolation indefinitely."""
        if action_id not in self.actions:
            raise KeyError(f"Quarantine action {action_id} not found")

        record = self.actions[action_id]
        if record.status != "active":
            logger.info(
                "Action %s already transitioned to status %s; skipping promotion",
                action_id,
                record.status,
            )
            return record

        updated_record = record.model_copy(
            update={
                "status": "promoted",
                "rollback_reason": reason,
            }
        )
        self._persist_action(updated_record)
        return updated_record

    def reconcile_expired(
        self,
        current_time: datetime | None = None,
    ) -> list[QuarantineActionRecord]:
        """Reconciliation loop: auto-rollback all active quarantines past their TTL."""
        now = current_time or datetime.now(UTC)
        rolled_back: list[QuarantineActionRecord] = []

        for action_id, record in list(self.actions.items()):
            if record.status != "active":
                continue

            expiry = datetime.fromisoformat(record.expires_at)
            if now >= expiry:
                logger.info(
                    "Quarantine action %s for %s/%s has reached TTL; triggering auto-rollback",
                    action_id,
                    record.namespace,
                    record.pod_name,
                )
                rb_record = self.rollback_quarantine(
                    action_id=action_id,
                    reason=f"Automated TTL rollback (expired at {record.expires_at})",
                )
                rolled_back.append(rb_record)

        return rolled_back
