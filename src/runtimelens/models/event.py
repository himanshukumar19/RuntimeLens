"""Canonical event model for RuntimeLens telemetry (Schema v1.0.0)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class WorkloadIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant: str
    namespace: str
    pod_name: str
    pod_uid: str
    owner_workload: str
    container_name: str
    container_id: str | None = None
    image_digest: str


class TelemetrySourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["falco", "k8s_audit", "hubble", "trivy", "metrics"]
    source_event_id: str
    source_rule_name: str | None = None
    raw_event_ref: str


class DeterministicFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_runtime_socket_mounted: bool = False
    sensitive_host_path_mounted: bool = False
    privileged_container: bool = False
    is_root_user: bool = False
    is_shell_process: bool = False
    has_critical_vulnerability: bool = False
    cpu_usage_mcores: float = 0.0
    is_cpu_abnormal: bool = False
    is_outbound_egress: bool = False
    is_cross_tenant_flow: bool = False


class RuntimeContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    process_name: str | None = None
    parent_process: str | None = None
    command_args_sanitized: str | None = Field(default=None, max_length=128)
    syscall: str | None = None


class OrchestrationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verb: str | None = None
    resource: str | None = None
    subresource: str | None = None
    request_user: str | None = None


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    verdict: Literal["FORWARDED", "DROPPED"] | None = None
    dns_query: str | None = None


class BaselineContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_version: str = "v1.0.0"
    is_baseline_stale: bool = False
    shell_expected: bool = False
    expected_binaries: list[str] = Field(default_factory=list)
    expected_peers: list[str] = Field(default_factory=list)
    baseline_deviation_detected: bool = False
    deviations: list[str] = Field(default_factory=list)


class TelemetryHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_telemetry_degraded: bool = False
    missing_sources: list[str] = Field(default_factory=list)


class CanonicalEvent(BaseModel):
    """Single source of truth Pydantic model for RuntimeLens CanonicalEvent v1.0.0."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    ingest_timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    workload: WorkloadIdentity
    telemetry_source: TelemetrySourceRef
    facts: DeterministicFacts
    runtime: RuntimeContext | None = None
    orchestration: OrchestrationContext | None = None
    network: NetworkContext | None = None
    baseline: BaselineContext
    health: TelemetryHealth
    edge_case: bool = False
