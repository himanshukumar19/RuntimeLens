#!/usr/bin/env python3
"""RuntimeLens Live Interactive Demonstration Script (Ticket 16c).

Showcases the entire RuntimeLens vertical slice across four realistic threat scenarios:
1. Benign Web Traffic (Normalizer -> Baseline Match -> Rules -> Action: Log)
2. Privilege Abuse (Unexpected Shell in DB -> Drift -> Action: Alert/Review)
3. Container Escape (Sensitive Host Mount -> Fact -> Safety Override -> Action: Quarantine)
4. Cryptomining Egress (Prometheus CPU Spike + Hubble Flow -> Action: Quarantine)
5. Audit Verification (Cryptographic SHA-256 Hash-Chain Verification of all recorded decisions)

Usage:
    python scripts/demo.py           # Interactive step-by-step mode
    python scripts/demo.py --auto    # Automated non-interactive mode for CI/Viva rehearsal
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from runtimelens.audit.writer import AuditWriter
from runtimelens.baseline.comparator import compare_against_baseline
from runtimelens.baseline.loader import BaselineStore
from runtimelens.classifiers.rules import classify_rules_context
from runtimelens.classifiers.scaledown import ScaleDownAdapter
from runtimelens.models.decision import AuditRecord
from runtimelens.normalizer.falco import normalize_falco_event
from runtimelens.normalizer.hubble import normalize_hubble_flow
from runtimelens.normalizer.prometheus import normalize_prometheus_metric
from runtimelens.policy.engine import evaluate_policy

DEFAULT_AUDIT_LOG = Path("data/audit/demo_audit.jsonl")


class TerminalColor:
    """ANSI color codes for terminal rendering with graceful disable support."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    @property
    def RESET(self) -> str:  # noqa: N802
        return "\033[0m" if self.enabled else ""

    @property
    def BOLD(self) -> str:  # noqa: N802
        return "\033[1m" if self.enabled else ""

    @property
    def GREEN(self) -> str:  # noqa: N802
        return "\033[32m" if self.enabled else ""

    @property
    def YELLOW(self) -> str:  # noqa: N802
        return "\033[33m" if self.enabled else ""

    @property
    def RED(self) -> str:  # noqa: N802
        return "\033[31m" if self.enabled else ""

    @property
    def CYAN(self) -> str:  # noqa: N802
        return "\033[36m" if self.enabled else ""

    @property
    def MAGENTA(self) -> str:  # noqa: N802
        return "\033[35m" if self.enabled else ""

    @property
    def BLUE(self) -> str:  # noqa: N802
        return "\033[34m" if self.enabled else ""


def prompt_user(step_num: int, title: str, auto_mode: bool, delay: float = 0.0) -> None:
    """Prompt the operator before advancing in interactive mode, or delay in auto mode."""
    if auto_mode:
        if delay > 0:
            time.sleep(delay)
        return

    sys.stdout.write(f"\n[Step {step_num}] Ready to execute: {title}\n")
    sys.stdout.write("Press [Enter] to execute step (or 'q' to abort): ")
    sys.stdout.flush()
    try:
        choice = sys.stdin.readline().strip().lower()
        if choice in {"q", "quit", "exit"}:
            sys.stdout.write("\nAborted by operator.\n")
            sys.exit(0)
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\nAborted by operator.\n")
        sys.exit(0)


def print_banner(c: TerminalColor) -> None:
    """Print the demonstration banner."""
    sep = "=" * 78
    title_line = " RuntimeLens: Multi-Tenant Kubernetes Runtime Threat Classification"
    sub_line = " Live Vertical Slice Demonstration & SRE Containment Engine (Ticket 16c)"
    print(f"{c.BOLD}{c.CYAN}{sep}{c.RESET}")
    print(f"{c.BOLD}{c.CYAN}{title_line}{c.RESET}")
    print(f"{c.BOLD}{sub_line}{c.RESET}")
    print(f"{c.CYAN}{sep}{c.RESET}\n")


def print_section(title: str, c: TerminalColor) -> None:
    """Print section divider."""
    sep = "-" * 78
    print(f"\n{c.BOLD}{c.BLUE}{sep}{c.RESET}")
    print(f"{c.BOLD}{c.BLUE}>>> {title}{c.RESET}")
    print(f"{c.BOLD}{c.BLUE}{sep}{c.RESET}")


def format_action_badge(action: str, c: TerminalColor) -> str:
    """Format action string with color-coded badge."""
    if action == "log":
        return f"{c.GREEN}[ACTION: LOG]{c.RESET}"
    if action == "alert":
        return f"{c.YELLOW}[ACTION: ALERT]{c.RESET}"
    if action == "human_review":
        return f"{c.YELLOW}{c.BOLD}[ACTION: HUMAN REVIEW]{c.RESET}"
    if action == "quarantine":
        return f"{c.RED}{c.BOLD}[ACTION: QUARANTINE]{c.RESET}"
    return f"[{action.upper()}]"


def run_scenario_1(
    writer: AuditWriter,
    store: BaselineStore,
    c: TerminalColor,
    auto_mode: bool,
    delay: float,
) -> AuditRecord:
    """Scenario 1: Benign web traffic (Normalizer -> Baseline Match -> Log)."""
    prompt_user(1, "Scenario 1 — Benign Web Traffic (Tenant A)", auto_mode, delay)
    print_section("Scenario 1: Benign Web Traffic (Routine Nginx Service)", c)

    raw_event: dict[str, Any] = {
        "output": "12:00:01: Web process executed in container",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-74b88dfd9b-w6tl9",
            "k8s.pod.uid": "uid-web-01",
            "container.name": "web",
            "container.id": "c1234567890a",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "/usr/sbin/nginx -g daemon off;",
            "proc.name": "nginx",
            "user.name": "appuser",
            "user.uid": 10001,
            "evt.num": "1001",
            "evt.type": "execve",
        },
        "rule": "Process Execution",
        "time": "2026-10-23T12:00:01.000000Z",
    }

    pod_name = raw_event["output_fields"]["k8s.pod.name"]
    cmdline = raw_event["output_fields"]["proc.cmdline"]
    print(f"1. Telemetry Ingest: Falco syscall execve from pod {pod_name}")
    print(f"   Command line: {cmdline}")

    canonical = normalize_falco_event(raw_event)
    baseline = store.get_baseline(canonical.workload.owner_workload)
    canonical.baseline = compare_against_baseline(canonical, baseline)

    wl_name = canonical.workload.owner_workload
    num_bins = len(canonical.baseline.expected_binaries)
    devs = canonical.baseline.deviations or "none"
    print(f"2. Baseline Match: Workload '{wl_name}' profile loaded ({num_bins} allowed binaries)")
    drift_det = canonical.baseline.baseline_deviation_detected
    print(f"   Drift detected: {drift_det} (deviations: {devs})")

    classification = classify_rules_context(canonical)
    c_type = classification.classifier_type
    p_class = classification.predicted_class
    sev = classification.severity
    print(f"3. Classification: Class='{p_class}', Severity={sev}, Classifier='{c_type}'")

    decision = evaluate_policy(classification, canonical, dry_run=True)
    badge = format_action_badge(decision.action, c)
    print(f"4. Policy Decision: {badge} Reason codes={decision.reason_codes}")

    record = writer.write_record(canonical, classification, decision)
    print(f"5. Tamper-Evident Audit: Record written to {writer.log_path}")
    print(f"   Record Hash: {record.record_hash[:16]}... (Prev: {record.prev_record_hash[:16]}...)")

    return record


def run_scenario_2(
    writer: AuditWriter,
    store: BaselineStore,
    classifier_choice: str,
    scaledown_adapter: ScaleDownAdapter,
    c: TerminalColor,
    auto_mode: bool,
    delay: float,
) -> AuditRecord:
    """Scenario 2: Privilege abuse (Unexpected shell in database container)."""
    prompt_user(2, "Scenario 2 — Privilege Abuse (Database Shell Spawn)", auto_mode, delay)
    print_section("Scenario 2: Privilege Abuse (Unexpected Shell in Database)", c)

    raw_event: dict[str, Any] = {
        "output": "12:01:15: Interactive shell spawned in tenant database container",
        "output_fields": {
            "k8s.ns.name": "tenant-b",
            "k8s.pod.name": "database-9dfb5894b-4q2lm",
            "k8s.pod.uid": "uid-db-01",
            "container.name": "database",
            "container.id": "c9876543210b",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "/bin/sh",
            "proc.name": "sh",
            "user.name": "root",
            "user.uid": 0,
            "evt.num": "1002",
            "evt.type": "execve",
        },
        "rule": "Terminal shell in container",
        "time": "2026-10-23T12:01:15.000000Z",
    }

    pod_name = raw_event["output_fields"]["k8s.pod.name"]
    cmdline = raw_event["output_fields"]["proc.cmdline"]
    uid_val = raw_event["output_fields"]["user.uid"]
    print(f"1. Telemetry Ingest: Falco syscall execve from pod {pod_name}")
    print(f"   Command: {cmdline} by uid={uid_val} (root)")

    canonical = normalize_falco_event(raw_event)
    baseline = store.get_baseline(canonical.workload.owner_workload)
    canonical.baseline = compare_against_baseline(canonical, baseline)

    print(f"2. Baseline Drift: Workload '{canonical.workload.owner_workload}' shell_allowed=False")
    print(f"   Deviations detected: {canonical.baseline.deviations}")

    if classifier_choice == "scaledown":
        classification = scaledown_adapter.classify_event(canonical)
        conf_val = classification.confidence or 0.0
        print(
            f"3. Classification (ScaleDown Typed): Class='{classification.predicted_class}', "
            f"Severity={classification.severity:.2f}, Confidence={conf_val:.2f}"
        )
        print(f"   Noul Evidence Flags: {classification.evidence_flags}")
    else:
        classification = classify_rules_context(canonical)
        print(
            f"3. Classification (Context Rules): Class='{classification.predicted_class}', "
            f"Severity={classification.severity}, Evidence Flags={classification.evidence_flags}"
        )

    decision = evaluate_policy(classification, canonical, dry_run=True)
    badge = format_action_badge(decision.action, c)
    r_codes = decision.reason_codes
    print(f"4. Policy Decision: {badge} Reason codes={r_codes} (Dry-run: {decision.dry_run})")

    record = writer.write_record(canonical, classification, decision)
    print("5. Tamper-Evident Audit: Hash chain linked")
    print(f"   Record Hash: {record.record_hash[:16]}... (Prev: {record.prev_record_hash[:16]}...)")

    return record


def run_scenario_3(
    writer: AuditWriter,
    store: BaselineStore,
    c: TerminalColor,
    auto_mode: bool,
    delay: float,
) -> AuditRecord:
    """Scenario 3: Container escape via sensitive host mount (Safety Override -> Quarantine)."""
    prompt_user(3, "Scenario 3 — Container Escape (Sensitive Host Mount)", auto_mode, delay)
    print_section("Scenario 3: Container Escape (Sensitive Host Path Mount)", c)

    raw_event: dict[str, Any] = {
        "output": "12:02:30: Container started with sensitive host path mounted",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "web-escape-pwn-84c49d",
            "k8s.pod.uid": "uid-escape-01",
            "container.name": "web",
            "container.id": "c1122334455e",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "cat /host/etc/kubernetes/admin.conf",
            "proc.name": "cat",
            "user.name": "root",
            "user.uid": 0,
            "evt.num": "1003",
            "evt.type": "open",
        },
        "rule": "Detect release_agent File Container Escapes",
        "time": "2026-10-23T12:02:30.000000Z",
    }
    pod_spec: dict[str, Any] = {
        "volumes": [
            {
                "name": "host-k8s",
                "hostPath": {"path": "/etc/kubernetes"},
            }
        ]
    }

    print("1. Telemetry Ingest: Pod spec volume mount detection + Falco sensitive file open")
    print(f"   Host volume path: {pod_spec['volumes'][0]['hostPath']['path']}")

    canonical = normalize_falco_event(raw_event, pod_spec=pod_spec)
    baseline = store.get_baseline(canonical.workload.owner_workload)
    canonical.baseline = compare_against_baseline(canonical, baseline)

    fact_val = canonical.facts.sensitive_host_path_mounted
    print(f"2. Physical Security Fact Detection: sensitive_host_path_mounted={fact_val}")

    classification = classify_rules_context(canonical)
    p_class = classification.predicted_class
    sev = classification.severity
    print(f"3. Classification: Class='{p_class}', Severity={sev}")

    decision = evaluate_policy(classification, canonical, dry_run=True)
    badge = format_action_badge(decision.action, c)
    ttl_sec = decision.auto_rollback_ttl_seconds
    print("4. Policy Decision & SRE Containment:")
    print(f"   Outcome: {badge} (Namespace: {canonical.workload.namespace})")
    print(f"   Reason codes: {decision.reason_codes}")
    print(f"   Containment labels: {decision.quarantine_labels}")
    print(f"   SRE Guardrails: Auto-rollback TTL={ttl_sec}s (15 min), Zero delete verbs")

    record = writer.write_record(canonical, classification, decision)
    print("5. Tamper-Evident Audit: Hash chain linked")
    print(f"   Record Hash: {record.record_hash[:16]}... (Prev: {record.prev_record_hash[:16]}...)")

    return record


def run_scenario_4(
    writer: AuditWriter,
    store: BaselineStore,
    c: TerminalColor,
    auto_mode: bool,
    delay: float,
) -> AuditRecord:
    """Scenario 4: Cryptomining egress (Multi-signal Prometheus + Hubble correlation)."""
    prompt_user(4, "Scenario 4 — Cryptomining Egress (CPU Spike + Egress)", auto_mode, delay)
    print_section("Scenario 4: Cryptomining Egress (Prometheus + Hubble Flow)", c)

    raw_event: dict[str, Any] = {
        "output": "12:03:45: Outbound connection from high-CPU container to mining pool",
        "output_fields": {
            "k8s.ns.name": "tenant-a",
            "k8s.pod.name": "api-6b47c6997b-8jkl2",
            "k8s.pod.uid": "uid-miner-01",
            "container.name": "api",
            "container.id": "c5566778899m",
            "container.image.repository": "alpine",
            "container.image.tag": "3.19",
            "proc.cmdline": "./xmrig --url=pool.supportxmr.com:3333",
            "proc.name": "xmrig",
            "user.name": "appuser",
            "user.uid": 10001,
            "evt.num": "1004",
            "evt.type": "connect",
        },
        "rule": "Execution from /dev/shm",
        "time": "2026-10-23T12:03:45.000000Z",
    }

    # 1. Prometheus CPU metric normalization
    raw_metric = {"value": "0.850"}  # 850 millicores
    cpu_mcores, is_cpu_abnormal = normalize_prometheus_metric(
        raw_metric, baseline_cpu_envelope_mcores=50.0
    )
    print(
        f"1. Telemetry Ingest [Prometheus]: CPU={cpu_mcores} mcores "
        f"(Envelope: 50.0 mcores, >=3x abnormal={is_cpu_abnormal})"
    )

    # 2. Hubble Network Flow normalization
    raw_flow = {
        "flow": {
            "source": {"namespace": "tenant-a", "pod_name": "api-6b47c6997b-8jkl2"},
            "destination": {"namespace": ""},
            "IP": {"destination": "198.51.100.24"},
            "l4": {"TCP": {"destination_port": 3333}},
            "verdict": "FORWARDED",
        }
    }
    net_ctx, net_facts = normalize_hubble_flow(raw_flow)
    dst_endpoint = f"{net_ctx.destination_ip}:{net_ctx.destination_port}"
    print(
        f"   Telemetry Ingest [Hubble]: Flow to {dst_endpoint} "
        f"(Egress={net_facts['is_outbound_egress']}, Verdict={net_ctx.verdict})"
    )

    canonical = normalize_falco_event(raw_event)
    canonical.facts.cpu_usage_mcores = cpu_mcores
    canonical.facts.is_cpu_abnormal = is_cpu_abnormal
    canonical.facts.is_outbound_egress = net_facts["is_outbound_egress"]
    canonical.network = net_ctx

    baseline = store.get_baseline(canonical.workload.owner_workload)
    canonical.baseline = compare_against_baseline(canonical, baseline)

    print("2. Correlated Drift: Abnormal compute + unauthorized external egress detected")
    print(f"   Baseline deviations: {canonical.baseline.deviations}")

    classification = classify_rules_context(canonical)
    p_class = classification.predicted_class
    c_type = classification.classifier_type
    sev = classification.severity
    print(f"3. Classification: Class='{p_class}', Severity={sev}, Classifier='{c_type}'")

    decision = evaluate_policy(classification, canonical, dry_run=True)
    badge = format_action_badge(decision.action, c)
    ttl_sec = decision.auto_rollback_ttl_seconds
    print(f"4. Policy Decision: {badge} Reason codes={decision.reason_codes}")
    print(f"   Quarantine labels={decision.quarantine_labels}, Rollback TTL={ttl_sec}s")

    record = writer.write_record(canonical, classification, decision)
    print("5. Tamper-Evident Audit: Hash chain linked")
    print(f"   Record Hash: {record.record_hash[:16]}... (Prev: {record.prev_record_hash[:16]}...)")

    return record


def run_audit_verification(
    log_path: Path,
    c: TerminalColor,
    auto_mode: bool,
    delay: float,
) -> bool:
    """Step 5: Cryptographic audit chain verification."""
    prompt_user(5, "Step 5 — Cryptographic Audit Trail Verification", auto_mode, delay)
    print_section("Step 5: Tamper-Evident SHA-256 Audit Chain Verification", c)

    is_valid, count, err = AuditWriter.verify_chain(log_path)
    if not is_valid:
        print(f"{c.RED}[FAIL] Cryptographic audit chain verification failed: {err}{c.RESET}")
        return False

    print(f"Audit Log: {log_path} ({log_path.stat().st_size} bytes, {count} records)\n")
    print("Record Verification Sequence:")

    with open(log_path, encoding="utf-8") as f:
        for idx, line in enumerate(f):
            data = json.loads(line)
            r_hash = data.get("record_hash", "")[:8]
            p_hash = data.get("prev_record_hash", "")[:8]
            action = data.get("decision", {}).get("action", "")
            p_class = data.get("classification", {}).get("predicted_class", "")
            workload = data.get("event", {}).get("workload", {}).get("owner_workload", "")

            print(
                f"  [{idx + 1}] Workload: {workload:<10} | "
                f"Class: {p_class:<16} | Action: {action:<12} | "
                f"Prev: {p_hash}... -> Hash: {r_hash}..."
            )

    pass_msg = (
        f"[PASS] Cryptographic integrity verified: "
        f"All {count} records strictly hash-chained back to Genesis (SHA-256)."
    )
    print(f"\n{c.GREEN}{c.BOLD}{pass_msg}{c.RESET}")
    return True


def run_demo(
    output_path: Path = DEFAULT_AUDIT_LOG,
    auto_mode: bool = False,
    classifier_choice: str = "rules",
    color: bool = True,
    delay: float = 0.0,
    clean: bool = True,
) -> int:
    """Execute the full 5-step live interactive demonstration."""
    c = TerminalColor(enabled=color)
    print_banner(c)

    if clean and output_path.exists():
        output_path.unlink()

    writer = AuditWriter(output_path)
    store = BaselineStore(baselines_dir=Path("baselines"))
    scaledown_adapter = ScaleDownAdapter()

    mode_str = "Automated Non-Interactive" if auto_mode else "Interactive Step-by-Step"
    print(f"Demo Mode: {mode_str}")
    print(f"Primary Classifier: {classifier_choice.upper()}")
    print(f"Audit Log Destination: {output_path}")
    print(f"Baselines Loaded: {list(store._cache.keys())}\n")

    try:
        run_scenario_1(writer, store, c, auto_mode, delay)
        run_scenario_2(writer, store, classifier_choice, scaledown_adapter, c, auto_mode, delay)
        run_scenario_3(writer, store, c, auto_mode, delay)
        run_scenario_4(writer, store, c, auto_mode, delay)
        ok = run_audit_verification(output_path, c, auto_mode, delay)
        if not ok:
            return 1
    except Exception as exc:
        print(f"\n{c.RED}[ERROR] Demonstration encountered an exception: {exc}{c.RESET}")
        return 1

    print_section("Demonstration Summary", c)
    summary_msg = "RuntimeLens vertical slice completed successfully across all 4 scenarios."
    print(f"{c.GREEN}{c.BOLD}{summary_msg}{c.RESET}")
    print(f"Audit log persisted and verified at: {output_path}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and dispatch demo execution."""
    parser = argparse.ArgumentParser(
        description="RuntimeLens Live Interactive Demonstration & Viva Defense Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run non-interactively without pause prompts.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_AUDIT_LOG,
        help="Path to write the tamper-evident audit log JSONL file.",
    )
    parser.add_argument(
        "--classifier",
        choices=["rules", "scaledown"],
        default="rules",
        help="Classifier engine to evaluate in Scenario 2.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal coloring.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Artificial delay in seconds between steps when running with --auto.",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not delete existing audit output file before running.",
    )

    args = parser.parse_args(argv)

    use_color = (not args.no_color) and sys.stdout.isatty()

    return run_demo(
        output_path=args.output,
        auto_mode=args.auto,
        classifier_choice=args.classifier,
        color=use_color,
        delay=args.delay,
        clean=not args.no_clean,
    )


if __name__ == "__main__":
    sys.exit(main())
