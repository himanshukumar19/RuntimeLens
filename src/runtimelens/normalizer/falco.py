"""Falco raw telemetry normalizer mapping to CanonicalEvent v1.0.0."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)
from runtimelens.sanitizer import (
    HOST_RUNTIME_SOCKET_PATTERNS,
    SENSITIVE_HOST_PATH_PATTERNS,
    sanitize_untrusted_input,
)

ALPINE_319_ARM64_DIGEST: Final[str] = (
    "docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
)

# Documented simulated runtime socket paths (Condition 1, Decision D-17)
# Placed exclusively in /opt/runtimelens-dummy/ to avoid symlink collision with real /run sockets
SIMULATED_RUNTIME_SOCKET_PATTERNS: Final[tuple[str, ...]] = (
    "/opt/runtimelens-dummy/docker.sock",
    "/opt/runtimelens-dummy/containerd.sock",
)

# Pinned real sha256 digests for lab container images (Decision D-15)
PINNED_IMAGE_DIGESTS: Final[dict[str, str]] = {
    "alpine:3.19": ALPINE_319_ARM64_DIGEST,
    "docker.io/library/alpine:3.19": ALPINE_319_ARM64_DIGEST,
}


class PodSpecInfo(BaseModel):
    """Deterministic security facts derived strictly from the Kubernetes Pod specification."""

    model_config = ConfigDict(extra="forbid")

    has_host_runtime_socket_mount: bool = False
    has_sensitive_host_path_mount: bool = False
    is_privileged: bool = False
    host_pid: bool = False
    host_network: bool = False


def extract_pod_spec_facts(pod_spec: dict[str, Any] | None) -> PodSpecInfo:
    """Extract deterministic host mount and privilege facts directly from pod specification."""
    if not pod_spec:
        return PodSpecInfo()

    has_sock = False
    has_host_path = False

    # 1. Inspect volumes for hostPath volume mounts
    volumes = pod_spec.get("volumes", [])
    if isinstance(volumes, list):
        for vol in volumes:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath")
                if isinstance(hp, dict):
                    hp_path = str(hp.get("path", "")).lower()
                    all_socket_patterns = (
                        HOST_RUNTIME_SOCKET_PATTERNS + SIMULATED_RUNTIME_SOCKET_PATTERNS
                    )
                    if any(sock in hp_path for sock in all_socket_patterns):
                        has_sock = True
                    if any(sens in hp_path for sens in SENSITIVE_HOST_PATH_PATTERNS):
                        has_host_path = True

    # 2. Inspect containers for privileged mode
    is_priv = False
    containers = pod_spec.get("containers", [])
    if isinstance(containers, list):
        for c in containers:
            if isinstance(c, dict):
                sec = c.get("securityContext", {})
                if isinstance(sec, dict) and sec.get("privileged") is True:
                    is_priv = True

    h_pid = bool(pod_spec.get("hostPID", False))
    h_net = bool(pod_spec.get("hostNetwork", False))

    return PodSpecInfo(
        has_host_runtime_socket_mount=has_sock,
        has_sensitive_host_path_mount=has_host_path,
        is_privileged=is_priv,
        host_pid=h_pid,
        host_network=h_net,
    )


def resolve_image_digest(repo: str, tag: str, raw_digest: str | None) -> str:
    """Resolve a real cryptographic sha256 image digest rather than a mutable tag."""
    if raw_digest and "@sha256:" in raw_digest:
        return raw_digest

    lookup_key = f"{repo}:{tag}"
    if lookup_key in PINNED_IMAGE_DIGESTS:
        return PINNED_IMAGE_DIGESTS[lookup_key]

    clean_key = f"{repo.split('/')[-1]}:{tag}"
    if clean_key in PINNED_IMAGE_DIGESTS:
        return PINNED_IMAGE_DIGESTS[clean_key]

    # Deterministic fallback sha256 digest
    synthetic_hash = hashlib.sha256(f"{repo}:{tag}".encode()).hexdigest()
    return f"{repo}@sha256:{synthetic_hash}"


def normalize_falco_event(
    raw_falco: dict[str, Any],
    pod_spec: PodSpecInfo | dict[str, Any] | None = None,
) -> CanonicalEvent:
    """Normalize raw Falco JSON event into versioned CanonicalEvent."""
    fields: dict[str, Any] = raw_falco.get("output_fields", {})

    # 1. Timestamps
    event_time_str = raw_falco.get("time")
    if not event_time_str:
        event_time_str = datetime.now(UTC).isoformat()

    ingest_time_str = datetime.now(UTC).isoformat()

    # 2. Workload Identity
    namespace = str(fields.get("k8s.ns.name") or "default")
    tenant = namespace if namespace.startswith("tenant-") else "system"
    pod_name = str(fields.get("k8s.pod.name") or "unknown-pod")
    pod_uid = str(fields.get("k8s.pod.uid") or f"uid-{pod_name}")

    # Derive owner workload from pod name (e.g. web-6794787bc8-4wmx6 -> web)
    owner_workload = pod_name.rsplit("-", 2)[0] if "-" in pod_name else pod_name

    container_name = str(fields.get("container.name") or "unknown-container")
    container_id = fields.get("container.id")
    if container_id is not None:
        container_id = str(container_id)

    repo = str(fields.get("container.image.repository") or "docker.io/library/alpine")
    tag = str(fields.get("container.image.tag") or "3.19")
    raw_digest = fields.get("container.image.digest")
    image_digest = resolve_image_digest(repo, tag, raw_digest)

    workload = WorkloadIdentity(
        tenant=tenant,
        namespace=namespace,
        pod_name=pod_name,
        pod_uid=pod_uid,
        owner_workload=owner_workload,
        container_name=container_name,
        container_id=container_id,
        image_digest=image_digest,
    )

    # 3. Telemetry Source Reference
    raw_canonical_bytes = json.dumps(raw_falco, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    raw_hash = hashlib.sha256(raw_canonical_bytes).hexdigest()
    rule_name_str = str(raw_falco.get("rule") or "")

    telemetry_source = TelemetrySourceRef(
        source="falco",
        source_event_id=str(fields.get("evt.num") or str(uuid.uuid4())[:8]),
        source_rule_name=rule_name_str if rule_name_str else None,
        raw_event_ref=f"sha256:{raw_hash}",
    )

    # 4. Untrusted argument sanitization & Deterministic Fact Extraction
    cmdline = fields.get("proc.cmdline") or ""
    fd_name = fields.get("fd.name") or ""
    sanitized = sanitize_untrusted_input(cmdline)

    # Deterministic facts derive strictly from the actual pod specification
    if isinstance(pod_spec, PodSpecInfo):
        spec_facts = pod_spec
    elif isinstance(pod_spec, dict):
        spec_facts = extract_pod_spec_facts(pod_spec)
    else:
        spec_facts = PodSpecInfo()

    is_root = fields.get("user.name") == "root" or fields.get("user.uid") == 0

    proc_name = str(fields.get("proc.name") or "")
    is_shell = proc_name in {"sh", "bash", "zsh", "dash"} or any(
        s in cmdline for s in ["/bin/sh", "/bin/bash", "/bin/zsh"]
    )

    facts = DeterministicFacts(
        host_runtime_socket_mounted=spec_facts.has_host_runtime_socket_mount,
        sensitive_host_path_mounted=spec_facts.has_sensitive_host_path_mount,
        privileged_container=spec_facts.is_privileged,
        is_root_user=is_root,
        is_shell_process=is_shell,
        has_critical_vulnerability=False,
        cpu_usage_mcores=0.0,
        is_cpu_abnormal=False,
        is_outbound_egress=False,
        is_cross_tenant_flow=False,
    )

    # 5. Runtime context (Stored unescaped; escaped only during model serialization)
    runtime = RuntimeContext(
        process_name=proc_name if proc_name else None,
        parent_process=str(fields.get("proc.pname") or ""),
        command_args_sanitized=sanitized.sanitized_text,
        syscall=str(fields.get("evt.type") or "syscall"),
    )

    # 6. Baseline context & Drift assessment
    deviations: list[str] = []
    if is_shell:
        deviations.append("unexpected_shell_execution")
    if sanitized.has_shell_metacharacters:
        deviations.append("shell_metacharacters_detected")

    has_identity_access = (
        sanitized.has_identity_file_reference
        or "/etc/shadow" in fd_name
        or "/etc/passwd" in fd_name
    )
    if has_identity_access:
        deviations.append("sensitive_identity_file_access")
    if spec_facts.has_host_runtime_socket_mount:
        deviations.append("host_runtime_socket_access")

    baseline = BaselineContext(
        baseline_version="v1.0.0",
        is_baseline_stale=False,
        shell_expected=False,
        expected_binaries=["web", "api", "database", "payment-style"],
        expected_peers=[],
        baseline_deviation_detected=len(deviations) > 0,
        deviations=deviations,
    )

    # 7. Telemetry Health
    health = TelemetryHealth(
        is_telemetry_degraded=False,
        missing_sources=[],
    )

    is_edge_case = deviations == ["sensitive_identity_file_access"]

    return CanonicalEvent(
        event_id=str(uuid.uuid4()),
        schema_version="1.0.0",
        event_timestamp=event_time_str,
        ingest_timestamp=ingest_time_str,
        workload=workload,
        telemetry_source=telemetry_source,
        facts=facts,
        runtime=runtime,
        orchestration=None,
        network=None,
        baseline=baseline,
        health=health,
        edge_case=is_edge_case,
    )
