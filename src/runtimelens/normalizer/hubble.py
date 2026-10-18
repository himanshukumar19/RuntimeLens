"""Cilium / Hubble network flow normalizer mapping to NetworkContext (Ticket 09b)."""

from __future__ import annotations

from typing import Any, Literal

from runtimelens.models.event import NetworkContext


def normalize_hubble_flow(raw_event: dict[str, Any]) -> tuple[NetworkContext, dict[str, bool]]:
    """Normalize raw Hubble JSON flow event into NetworkContext and flow facts.

    Returns:
        tuple of (NetworkContext, facts_dict) where facts_dict includes
        'is_cross_tenant_flow' and 'is_outbound_egress'.
    """
    flow = raw_event.get("flow", raw_event)

    # 1. IP & Transport layer extraction
    ip_info = flow.get("IP", {})
    dest_ip = ip_info.get("destination")

    l4_info = flow.get("l4", {})
    dest_port: int | None = None
    protocol: str | None = None

    if "TCP" in l4_info:
        dest_port = l4_info["TCP"].get("destination_port")
        protocol = "TCP"
    elif "UDP" in l4_info:
        dest_port = l4_info["UDP"].get("destination_port")
        protocol = "UDP"

    # 2. Verdict extraction
    raw_verdict = str(flow.get("verdict", "")).upper()
    verdict: Literal["FORWARDED", "DROPPED"] | None = None
    if raw_verdict == "FORWARDED":
        verdict = "FORWARDED"
    elif raw_verdict == "DROPPED":
        verdict = "DROPPED"

    # 3. DNS query if present (L7)
    dns_query = flow.get("DNS", {}).get("query")

    network_ctx = NetworkContext(
        destination_ip=dest_ip,
        destination_port=dest_port,
        protocol=protocol,
        verdict=verdict,
        dns_query=dns_query,
    )

    # 4. Derive flow facts
    src_ns = flow.get("source", {}).get("namespace", "")
    dst_ns = flow.get("destination", {}).get("namespace", "")

    is_cross_tenant = False
    if src_ns.startswith("tenant-") and dst_ns.startswith("tenant-"):
        is_cross_tenant = src_ns != dst_ns

    # Check for external outbound egress (non-cluster IP)
    is_egress = False
    if dest_ip:
        # Cluster pod CIDR: 10.244.0.0/16, Service CIDR: 10.96.0.0/12, Node IP: 172.18.0.0/16
        is_cluster_internal = (
            dest_ip.startswith("10.244.")
            or dest_ip.startswith("10.96.")
            or dest_ip.startswith("172.18.")
            or dest_ip == "127.0.0.1"
        )
        is_egress = not is_cluster_internal

    facts = {
        "is_cross_tenant_flow": is_cross_tenant,
        "is_outbound_egress": is_egress,
    }
    return network_ctx, facts
