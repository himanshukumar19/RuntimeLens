"""Pydantic schema definitions for declarative workload baselines."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class BaselineMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workload: str
    created_at: str
    approved_by: str = "security-admin"
    description: str = ""
    observation_period_minutes: int = 60
    observation_run_ids: list[str] = Field(default_factory=list)


class BaselineRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shell_allowed: bool = False
    allowed_binaries: list[str] = Field(default_factory=list)
    allowed_parent_processes: list[str] = Field(default_factory=list)
    permitted_capabilities: list[str] = Field(default_factory=list)
    allowed_volume_mounts: list[str] = Field(default_factory=list)
    disallowed_mount_patterns: list[str] = Field(default_factory=list)


class BaselineNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_inbound_ports: list[int] = Field(default_factory=list)
    allowed_peers: list[str] = Field(default_factory=list)
    allow_external_egress: bool = False
    allowed_dns_domains: list[str] = Field(default_factory=list)


class BaselineResources(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu_baseline_mcores: float = 25.0
    cpu_max_envelope_mcores: float = 150.0
    memory_baseline_mb: float = 64.0
    memory_max_envelope_mb: float = 256.0


class WorkloadBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "v1.0.0"
    metadata: BaselineMetadata
    runtime: BaselineRuntime
    network: BaselineNetwork
    resources: BaselineResources
