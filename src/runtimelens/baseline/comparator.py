"""Deterministic baseline drift comparator (Decision D-08, Ticket 05)."""

from __future__ import annotations

from runtimelens.baseline.models import WorkloadBaseline
from runtimelens.models.event import BaselineContext, CanonicalEvent


def compare_against_baseline(
    event: CanonicalEvent,
    baseline: WorkloadBaseline | None,
    is_stale: bool = False,
) -> BaselineContext:
    """Compare an observed event against declarative workload baseline to detect drift."""
    if baseline is None:
        return BaselineContext(
            baseline_version="unconfigured",
            is_baseline_stale=False,
            shell_expected=False,
            expected_binaries=[],
            expected_peers=[],
            baseline_deviation_detected=True,
            deviations=["workload_baseline_missing"],
        )

    deviations: list[str] = []
    facts = event.facts
    runtime = event.runtime

    # 1. Shell execution check
    shell_expected = baseline.runtime.shell_allowed
    if facts.is_shell_process and not shell_expected:
        deviations.append("unexpected_shell_execution")

    # 2. Binary execution check
    if runtime and runtime.process_name:
        proc = runtime.process_name
        allowed = baseline.runtime.allowed_binaries
        is_allowed = any(proc == b or b.endswith(f"/{proc}") for b in allowed)
        if not is_allowed and proc not in {"init", "containerd-shim"}:
            deviations.append(f"unauthorized_binary:{proc}")

    # 3. Network egress check
    if facts.is_outbound_egress and not baseline.network.allow_external_egress:
        deviations.append("unauthorized_external_egress")

    if facts.is_cross_tenant_flow:
        deviations.append("cross_tenant_flow_violation")

    # 4. CPU usage envelope check
    if facts.cpu_usage_mcores > baseline.resources.cpu_max_envelope_mcores:
        deviations.append("cpu_envelope_exceeded")

    # 5. Preserve pre-extracted identity file access deviations
    if "sensitive_identity_file_access" in event.baseline.deviations:
        deviations.append("sensitive_identity_file_access")

    # 6. Host runtime socket deviation
    if facts.host_runtime_socket_mounted:
        deviations.append("host_runtime_socket_access")

    # Deduplicate deviations while preserving order
    unique_deviations = list(dict.fromkeys(deviations))

    return BaselineContext(
        baseline_version=baseline.version,
        is_baseline_stale=is_stale,
        shell_expected=shell_expected,
        expected_binaries=baseline.runtime.allowed_binaries,
        expected_peers=baseline.network.allowed_peers,
        baseline_deviation_detected=len(unique_deviations) > 0,
        deviations=unique_deviations,
    )
