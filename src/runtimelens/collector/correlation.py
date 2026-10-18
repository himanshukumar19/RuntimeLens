"""Multi-source temporal correlation engine (+-30s window) for Falco and K8s Audit (Ticket 04)."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Final

from runtimelens.models.event import CanonicalEvent, OrchestrationContext

DEFAULT_WINDOW_SECONDS: Final[float] = 30.0
MAX_BUFFER_PER_KEY: Final[int] = 500

# Redaction patterns for secrets in audit/event streams
SECRET_REDACTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:password|token|secret|key|authorization|bearer)\s*[:=]\s*[\"']?[A-Za-z0-9_\-\.]{8,}[\"']?",
        re.IGNORECASE,
    ),
    re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),  # JWT tokens
)


def redact_secrets_in_text(text: str) -> str:
    """Scrub tokens, passwords, and JWTs from event strings before buffering or persistence."""
    cleaned = text
    for pat in SECRET_REDACTION_PATTERNS:
        cleaned = pat.sub("[REDACTED]", cleaned)
    return cleaned


def parse_timestamp_iso(ts_str: str) -> float:
    """Parse ISO UTC timestamp into epoch seconds."""
    try:
        # Handles Z or +00:00
        clean_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str).timestamp()
    except Exception:
        return 0.0


class CorrelationBuffer:
    """Bounded sliding-window correlation buffer grouping telemetry by pod UID."""

    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        # Map (namespace, pod_uid) -> list of (timestamp, event_or_audit)
        self._falco_events: dict[str, list[CanonicalEvent]] = defaultdict(list)
        self._audit_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.drop_counter = 0

    def _get_key(self, namespace: str, pod_uid: str) -> str:
        return f"{namespace}:{pod_uid}"

    def ingest_falco_event(self, event: CanonicalEvent) -> CanonicalEvent:
        """Ingest a Falco event, prune stale events, and join with correlated audit records."""
        key = self._get_key(event.workload.namespace, event.workload.pod_uid)
        t_event = parse_timestamp_iso(event.event_timestamp)

        # Check for correlated audit events within +- window_seconds
        correlated_audit = None
        retained_audit = []
        for audit_item in self._audit_events[key]:
            t_audit = audit_item.get("timestamp_epoch", 0.0)
            if abs(t_event - t_audit) <= self.window_seconds:
                if correlated_audit is None:
                    correlated_audit = audit_item
            elif t_audit > (t_event - self.window_seconds):
                retained_audit.append(audit_item)

        self._audit_events[key] = retained_audit

        if correlated_audit is not None:
            # Merge orchestration context into canonical event
            event.orchestration = OrchestrationContext(
                verb=str(correlated_audit.get("verb") or ""),
                resource=str(correlated_audit.get("resource") or ""),
                subresource=correlated_audit.get("subresource"),
                request_user=redact_secrets_in_text(str(correlated_audit.get("username") or "")),
            )

        # Append to bounded Falco buffer
        if len(self._falco_events[key]) >= MAX_BUFFER_PER_KEY:
            self._falco_events[key].pop(0)
            self.drop_counter += 1

        self._falco_events[key].append(event)
        return event

    def ingest_audit_event(self, raw_audit: dict[str, Any]) -> None:
        """Ingest raw K8s API audit event into correlation window."""
        obj_ref = raw_audit.get("objectRef", {})
        namespace = obj_ref.get("namespace", "default")
        pod_name = obj_ref.get("name", "")
        pod_uid = obj_ref.get("uid") or f"uid-{pod_name}"

        key = self._get_key(namespace, pod_uid)
        ts_str = raw_audit.get("stageTimestamp") or raw_audit.get("requestReceivedTimestamp") or ""
        t_epoch = parse_timestamp_iso(ts_str)

        user_info = raw_audit.get("user", {})
        audit_record = {
            "timestamp_epoch": t_epoch,
            "verb": raw_audit.get("verb"),
            "resource": obj_ref.get("resource"),
            "subresource": obj_ref.get("subresource"),
            "username": user_info.get("username"),
        }

        # Correlate immediately with pending Falco events if present
        for falco_evt in self._falco_events[key]:
            t_falco = parse_timestamp_iso(falco_evt.event_timestamp)
            if abs(t_falco - t_epoch) <= self.window_seconds and falco_evt.orchestration is None:
                falco_evt.orchestration = OrchestrationContext(
                    verb=str(audit_record["verb"] or ""),
                    resource=str(audit_record["resource"] or ""),
                    subresource=audit_record["subresource"],
                    request_user=redact_secrets_in_text(str(audit_record["username"] or "")),
                )

        if len(self._audit_events[key]) >= MAX_BUFFER_PER_KEY:
            self._audit_events[key].pop(0)
            self.drop_counter += 1

        self._audit_events[key].append(audit_record)
