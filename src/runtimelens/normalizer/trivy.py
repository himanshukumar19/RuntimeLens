"""Trivy static image vulnerability report normalizer (Ticket 09b)."""

from __future__ import annotations

from typing import Any


def normalize_trivy_report(raw_report: dict[str, Any]) -> tuple[bool, list[str]]:
    """Normalize Trivy static vulnerability scan report.

    Returns:
        tuple of (has_critical_vulnerability, list_of_critical_cves).
    """
    has_critical = False
    critical_cves: list[str] = []

    results = raw_report.get("Results", [])
    if isinstance(results, list):
        for res in results:
            if isinstance(res, dict):
                vulns = res.get("Vulnerabilities", [])
                if isinstance(vulns, list):
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            sev = str(vuln.get("Severity", "")).upper()
                            cve_id = str(vuln.get("VulnerabilityID", ""))
                            if sev == "CRITICAL":
                                has_critical = True
                                if cve_id:
                                    critical_cves.append(cve_id)

    return has_critical, critical_cves
