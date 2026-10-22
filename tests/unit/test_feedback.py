"""Exhaustive unit test suite for human feedback baseline diff loop (Ticket 15)."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from runtimelens.baseline.models import WorkloadBaseline
from runtimelens.models.event import (
    BaselineContext,
    CanonicalEvent,
    DeterministicFacts,
    NetworkContext,
    RuntimeContext,
    TelemetryHealth,
    TelemetrySourceRef,
    WorkloadIdentity,
)
from runtimelens.policy.feedback import (
    BaselineProposal,
    generate_baseline_diff,
    propose_from_incident,
)
from runtimelens.review import main as review_main


def _make_dummy_event(
    workload: str = "web",
    process: str = "/usr/bin/maintenance.sh",
    peer: str = "backup.tenant-a.svc.cluster.local",
    cpu: float = 180.0,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-feedback-001",
        workload=WorkloadIdentity(
            tenant="tenant-a",
            namespace="tenant-a",
            pod_name=f"{workload}-pod-1",
            pod_uid="uid-fb-1",
            owner_workload=workload,
            container_name="app",
            image_digest="docker.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
        ),
        telemetry_source=TelemetrySourceRef(
            source="falco",
            source_event_id="src-fb-1",
            source_rule_name="Maintenance Script Run",
            raw_event_ref="sha256:dummy",
        ),
        facts=DeterministicFacts(
            cpu_usage_mcores=cpu,
            is_cpu_abnormal=True,
        ),
        runtime=RuntimeContext(
            process_name=process,
            parent_process="init",
            command_args_sanitized=f"{process} --run",
            syscall="execve",
        ),
        network=NetworkContext(
            destination_ip="10.96.0.50",
            destination_port=53,
            dns_query=peer,
            verdict="FORWARDED",
        ),
        baseline=BaselineContext(
            baseline_version="v1.0.0",
            expected_binaries=["nginx"],
            expected_peers=[],
            baseline_deviation_detected=True,
            deviations=["unexpected_binary"],
        ),
        health=TelemetryHealth(
            is_telemetry_degraded=False,
            missing_sources=[],
        ),
    )


class TestBaselineDiffGeneration:
    def test_propose_add_allowed_binary(self) -> None:
        proposal = BaselineProposal(
            workload="web",
            add_allowed_binaries=["/usr/bin/maintenance.sh"],
            justification="Authorized scheduled maintenance script",
        )
        result = generate_baseline_diff(proposal)

        assert result.is_modified is True
        assert result.workload == "web"
        assert "--- a/baselines/web.yaml" in result.unified_diff
        assert "+++ b/baselines/web.yaml" in result.unified_diff
        assert '+    - "/usr/bin/maintenance.sh"' in result.unified_diff

        # Validate that proposed YAML validates against schema
        data = yaml.safe_load(result.proposed_yaml)
        model = WorkloadBaseline.model_validate(data)
        assert "/usr/bin/maintenance.sh" in model.runtime.allowed_binaries

    def test_propose_add_allowed_peer(self) -> None:
        proposal = BaselineProposal(
            workload="api",
            add_allowed_peers=["backup.tenant-a.svc.cluster.local"],
            justification="New internal backup service peer",
        )
        result = generate_baseline_diff(proposal)

        assert result.is_modified is True
        assert '+    - "backup.tenant-a.svc.cluster.local"' in result.unified_diff

        data = yaml.safe_load(result.proposed_yaml)
        model = WorkloadBaseline.model_validate(data)
        assert "backup.tenant-a.svc.cluster.local" in model.network.allowed_peers

    def test_propose_cpu_max_envelope_update(self) -> None:
        proposal = BaselineProposal(
            workload="database",
            cpu_max_envelope_mcores=350.0,
            justification="Increased workload database queries during batch sync",
        )
        result = generate_baseline_diff(proposal)

        assert result.is_modified is True
        assert "-  cpu_max_envelope_mcores:" in result.unified_diff
        assert "+  cpu_max_envelope_mcores: 350.0" in result.unified_diff

        data = yaml.safe_load(result.proposed_yaml)
        model = WorkloadBaseline.model_validate(data)
        assert model.resources.cpu_max_envelope_mcores == 350.0

    def test_propose_combined_modifications(self) -> None:
        proposal = BaselineProposal(
            workload="payment-style",
            add_allowed_binaries=["/usr/local/bin/audit-helper"],
            add_allowed_peers=["audit.tenant-c.svc.cluster.local"],
            cpu_max_envelope_mcores=280.0,
            justification="Quarterly compliance agent deployment",
        )
        result = generate_baseline_diff(proposal)

        assert result.is_modified is True
        assert '+    - "/usr/local/bin/audit-helper"' in result.unified_diff
        assert '+    - "audit.tenant-c.svc.cluster.local"' in result.unified_diff
        assert "+  cpu_max_envelope_mcores: 280.0" in result.unified_diff

        data = yaml.safe_load(result.proposed_yaml)
        model = WorkloadBaseline.model_validate(data)
        assert "/usr/local/bin/audit-helper" in model.runtime.allowed_binaries
        assert "audit.tenant-c.svc.cluster.local" in model.network.allowed_peers
        assert model.resources.cpu_max_envelope_mcores == 280.0

    def test_duplicate_items_result_in_no_modifications(self) -> None:
        # /usr/sbin/nginx is already in baselines/web.yaml
        proposal = BaselineProposal(
            workload="web",
            add_allowed_binaries=["/usr/sbin/nginx"],
            justification="Duplicate proposal",
        )
        result = generate_baseline_diff(proposal)

        assert result.is_modified is False
        assert result.unified_diff == ""

    def test_nonexistent_workload_raises_error(self) -> None:
        proposal = BaselineProposal(
            workload="nonexistent-svc",
            add_allowed_binaries=["/bin/sh"],
        )
        with pytest.raises(
            FileNotFoundError, match="Baseline file for workload 'nonexistent-svc' not found"
        ):
            generate_baseline_diff(proposal)

    def test_empty_workload_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            BaselineProposal(workload="   ")

    def test_negative_cpu_envelope_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            BaselineProposal(workload="web", cpu_max_envelope_mcores=-50.0)


class TestProposeFromIncident:
    def test_propose_from_canonical_event_binary(self) -> None:
        event = _make_dummy_event(workload="web", process="/usr/bin/maintenance.sh")
        proposal = propose_from_incident(event, modification_type="binary")

        assert proposal.workload == "web"
        assert proposal.incident_id == "evt-feedback-001"
        assert proposal.add_allowed_binaries == ["/usr/bin/maintenance.sh"]
        assert proposal.add_allowed_peers == []
        assert proposal.cpu_max_envelope_mcores is None

    def test_propose_from_canonical_event_peer(self) -> None:
        event = _make_dummy_event(workload="api", peer="redis.tenant-a.svc.cluster.local")
        proposal = propose_from_incident(event, modification_type="peer")

        assert proposal.workload == "api"
        assert proposal.add_allowed_peers == ["redis.tenant-a.svc.cluster.local"]

    def test_propose_from_canonical_event_cpu(self) -> None:
        event = _make_dummy_event(workload="database", cpu=200.0)
        proposal = propose_from_incident(event, modification_type="cpu")

        # 200.0 * 1.25 margin = 250.0
        assert proposal.workload == "database"
        assert proposal.cpu_max_envelope_mcores == 250.0

    def test_propose_from_dict_incident(self) -> None:
        raw_dict: dict[str, Any] = {
            "event_id": "evt-dict-999",
            "workload": {"owner_workload": "payment-style"},
            "runtime": {"process_name": "/opt/custom/agent"},
            "network": {"dns_query": "billing.tenant-c.svc.cluster.local"},
            "facts": {"cpu_usage_mcores": 160.0},
        }

        prop_bin = propose_from_incident(raw_dict, modification_type="binary")
        assert prop_bin.workload == "payment-style"
        assert prop_bin.add_allowed_binaries == ["/opt/custom/agent"]

        prop_peer = propose_from_incident(raw_dict, modification_type="peer")
        assert prop_peer.add_allowed_peers == ["billing.tenant-c.svc.cluster.local"]

        prop_cpu = propose_from_incident(raw_dict, modification_type="cpu")
        # 160.0 * 1.25 = 200.0
        assert prop_cpu.cpu_max_envelope_mcores == 200.0

    def test_propose_with_explicit_value_override(self) -> None:
        event = _make_dummy_event(workload="web")
        prop = propose_from_incident(
            event,
            modification_type="binary",
            explicit_value="/usr/local/bin/custom-run",
            justification="Explicit override from analyst GUI",
        )
        assert prop.add_allowed_binaries == ["/usr/local/bin/custom-run"]
        assert prop.justification == "Explicit override from analyst GUI"


class TestReviewCli:
    def test_cli_generate_diff_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        cmd = ["--generate-diff", "--workload", "web", "--add-binary", "/usr/bin/newtool"]
        ret = review_main(cmd)
        assert ret == 0
        captured = capsys.readouterr()
        assert "--- a/baselines/web.yaml" in captured.out
        assert "+++ b/baselines/web.yaml" in captured.out
        assert '+    - "/usr/bin/newtool"' in captured.out

    def test_cli_generate_diff_nonexistent_workload(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = review_main(["--generate-diff", "--workload", "unknown-workload"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error generating baseline diff:" in captured.err

    def test_cli_no_args_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        ret = review_main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "RuntimeLens Analyst Review Queue and Baseline Diff Tool" in captured.out
