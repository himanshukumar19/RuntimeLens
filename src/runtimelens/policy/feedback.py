"""Human feedback diff loop for baseline tuning (Ticket 15, Extension 5).

When an analyst reviews an incident in the review queue and confirms activity
was benign (e.g., an authorized maintenance script, new peer, or batch burst),
this module generates a unified git diff proposal against the target workload
baseline YAML in baselines/.

Strictly validates all proposals against the WorkloadBaseline Pydantic schema
prior to returning or formatting diffs.
"""

from __future__ import annotations

import difflib
import logging
import re
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from runtimelens.baseline.models import WorkloadBaseline
from runtimelens.models.event import CanonicalEvent

logger = logging.getLogger("runtimelens.policy.feedback")

DEFAULT_BASELINES_DIR: Final[Path] = Path("baselines")


class IndentedYamlDumper(yaml.SafeDumper):
    """YAML safe dumper preserving proper sequence indentation."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        return super().increase_indent(flow, False)


class BaselineProposal(BaseModel):
    """Structured proposal for modifying a workload baseline profile."""

    model_config = ConfigDict(extra="forbid")

    workload: str = Field(description="Target workload identifier (e.g. web, api, database)")
    add_allowed_binaries: list[str] = Field(
        default_factory=list,
        description="List of executable binary paths to add to runtime.allowed_binaries",
    )
    add_allowed_peers: list[str] = Field(
        default_factory=list,
        description="List of cluster DNS/IP peers to add to network.allowed_peers",
    )
    cpu_max_envelope_mcores: float | None = Field(
        default=None,
        gt=0.0,
        description="Updated ceiling for cpu_max_envelope_mcores",
    )
    analyst_id: str = Field(default="security-analyst", description="Reviewer identifier")
    incident_id: str | None = Field(default=None, description="Triggering review incident ID")
    justification: str = Field(
        default="", description="Operational justification for the baseline change"
    )

    @field_validator("workload")
    @classmethod
    def validate_workload(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Workload name cannot be empty")
        return clean


class FeedbackDiffResult(BaseModel):
    """Result of baseline diff proposal generation."""

    model_config = ConfigDict(extra="forbid")

    workload: str
    baseline_path: str
    unified_diff: str
    original_yaml: str
    proposed_yaml: str
    is_modified: bool
    proposal: BaselineProposal


def _insert_list_items(content: str, section: str, key: str, items: list[str]) -> str:
    """Insert list items into a YAML section while preserving exact existing formatting."""
    if not items:
        return content

    lines = content.splitlines()
    in_section = False
    in_key = False
    last_item_idx = -1
    key_idx = -1
    item_indent = "    "
    existing_items: set[str] = set()

    for i, line in enumerate(lines):
        trimmed = line.strip()
        if trimmed.startswith(f"{section}:"):
            in_section = True
            continue
        if in_section and not line.startswith(" ") and trimmed:
            # Exited top-level section
            break
        if in_section:
            match = re.match(r"^(\s*)" + re.escape(key) + r":(\s*\[\])?", line)
            if match:
                key_idx = i
                in_key = True
                if match.group(2):
                    # Handle empty list declaration like `key: []`
                    lines[i] = f"{match.group(1)}{key}:"
                    for offset, item in enumerate(items):
                        lines.insert(i + 1 + offset, f'{match.group(1)}  - "{item}"')
                    return "\n".join(lines) + "\n"
                continue

            if in_key:
                item_match = re.match(r"^(\s+)-\s+[\"']?(.*?)[\"']?\s*$", line)
                if item_match:
                    item_indent = item_match.group(1)
                    last_item_idx = i
                    existing_items.add(item_match.group(2))
                elif trimmed and not trimmed.startswith("#"):
                    # End of the current key list
                    break

    # Filter out items already present
    to_add = [item for item in items if item not in existing_items]
    if not to_add:
        return content

    insert_idx = last_item_idx if last_item_idx != -1 else key_idx
    if insert_idx != -1:
        for offset, item in enumerate(to_add):
            lines.insert(insert_idx + 1 + offset, f'{item_indent}- "{item}"')
        return "\n".join(lines) + "\n"

    return content


def _update_scalar(content: str, section: str, key: str, value: float | int | str) -> str:
    """Update a scalar value in a YAML section while preserving indentation."""
    lines = content.splitlines()
    in_section = False
    for i, line in enumerate(lines):
        trimmed = line.strip()
        if trimmed.startswith(f"{section}:"):
            in_section = True
            continue
        if in_section and not line.startswith(" ") and trimmed:
            break
        if in_section:
            match = re.match(r"^(\s*)" + re.escape(key) + r":\s*.*$", line)
            if match:
                lines[i] = f"{match.group(1)}{key}: {value}"
                return "\n".join(lines) + "\n"
    return content


def generate_baseline_diff(
    proposal: BaselineProposal,
    baselines_dir: Path = DEFAULT_BASELINES_DIR,
) -> FeedbackDiffResult:
    """Generate a validated unified git diff for a proposed baseline adjustment.

    Args:
        proposal: BaselineProposal detailing workload changes.
        baselines_dir: Directory holding declarative workload YAML baselines.

    Returns:
        FeedbackDiffResult containing the unified git diff and validated schema.

    Raises:
        FileNotFoundError: If the workload YAML baseline file does not exist.
        ValueError / ValidationError: If proposed changes violate WorkloadBaseline schema.
    """
    baseline_file = baselines_dir / f"{proposal.workload}.yaml"
    if not baseline_file.is_file():
        raise FileNotFoundError(
            f"Baseline file for workload '{proposal.workload}' not found at {baseline_file}"
        )

    original_yaml = baseline_file.read_text(encoding="utf-8")

    # Verify original baseline parses against canonical schema
    orig_dict = yaml.safe_load(original_yaml)
    WorkloadBaseline.model_validate(orig_dict)

    updated_yaml = original_yaml

    # 1. Propose additions to allowed_binaries
    if proposal.add_allowed_binaries:
        updated_yaml = _insert_list_items(
            updated_yaml,
            section="runtime",
            key="allowed_binaries",
            items=proposal.add_allowed_binaries,
        )

    # 2. Propose additions to allowed_peers
    if proposal.add_allowed_peers:
        updated_yaml = _insert_list_items(
            updated_yaml,
            section="network",
            key="allowed_peers",
            items=proposal.add_allowed_peers,
        )

    # 3. Propose updates to cpu_max_envelope_mcores
    if proposal.cpu_max_envelope_mcores is not None:
        updated_yaml = _update_scalar(
            updated_yaml,
            section="resources",
            key="cpu_max_envelope_mcores",
            value=proposal.cpu_max_envelope_mcores,
        )

    # Validate updated YAML against WorkloadBaseline schema
    proposed_dict = yaml.safe_load(updated_yaml)
    WorkloadBaseline.model_validate(proposed_dict)

    # Compute unified git diff
    rel_path = f"baselines/{proposal.workload}.yaml"
    orig_lines = original_yaml.splitlines(keepends=True)
    prop_lines = updated_yaml.splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            prop_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )
    unified_diff = "".join(diff_lines)
    is_modified = len(diff_lines) > 0

    return FeedbackDiffResult(
        workload=proposal.workload,
        baseline_path=str(baseline_file),
        unified_diff=unified_diff,
        original_yaml=original_yaml,
        proposed_yaml=updated_yaml,
        is_modified=is_modified,
        proposal=proposal,
    )


def propose_from_incident(
    incident: CanonicalEvent | dict[str, Any],
    *,
    modification_type: str,
    explicit_value: str | float | None = None,
    analyst_id: str = "security-analyst",
    justification: str = "Approved during analyst human review",
) -> BaselineProposal:
    """Construct a BaselineProposal directly from an incident under analyst review.

    Args:
        incident: CanonicalEvent or incident dictionary from review queue.
        modification_type: One of 'binary', 'peer', 'cpu'.
        explicit_value: Optional manual override for proposed value.
        analyst_id: Reviewer name or ID.
        justification: Operational rationale for approval.

    Returns:
        Structured BaselineProposal ready for diff generation.
    """
    if isinstance(incident, dict):
        workload = str(incident.get("workload", {}).get("owner_workload", "web"))
        incident_id = str(incident.get("event_id", ""))
    else:
        workload = incident.workload.owner_workload
        incident_id = incident.event_id

    add_binaries: list[str] = []
    add_peers: list[str] = []
    cpu_envelope: float | None = None

    if modification_type == "binary":
        if explicit_value is not None:
            add_binaries.append(str(explicit_value))
        elif isinstance(incident, CanonicalEvent):
            proc = incident.runtime.process_name if incident.runtime else None
            if proc:
                add_binaries.append(proc)
        elif isinstance(incident, dict):
            proc = incident.get("runtime", {}).get("process_name")
            if proc:
                add_binaries.append(str(proc))

    elif modification_type == "peer":
        if explicit_value is not None:
            add_peers.append(str(explicit_value))
        elif isinstance(incident, CanonicalEvent):
            dest = (
                incident.network.dns_query
                if incident.network and incident.network.dns_query
                else (incident.network.destination_ip if incident.network else None)
            )
            if dest:
                add_peers.append(dest)
        elif isinstance(incident, dict):
            dest = incident.get("network", {}).get("dns_query") or incident.get("network", {}).get(
                "destination_ip"
            )
            if dest:
                add_peers.append(str(dest))

    elif modification_type == "cpu":
        if explicit_value is not None:
            cpu_envelope = float(explicit_value)
        elif isinstance(incident, CanonicalEvent):
            used = incident.facts.cpu_usage_mcores
            if used > 0:
                cpu_envelope = round(used * 1.25, 1)  # 25% safety margin
        elif isinstance(incident, dict):
            used = float(incident.get("facts", {}).get("cpu_usage_mcores", 0.0))
            if used > 0:
                cpu_envelope = round(used * 1.25, 1)

    return BaselineProposal(
        workload=workload,
        add_allowed_binaries=add_binaries,
        add_allowed_peers=add_peers,
        cpu_max_envelope_mcores=cpu_envelope,
        analyst_id=analyst_id,
        incident_id=incident_id,
        justification=justification,
    )
