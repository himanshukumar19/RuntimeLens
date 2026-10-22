"""Human analyst review queue and baseline diff generator CLI (Ticket 15).

Supports:
- Generating baseline diff proposals for Dev split baselines (`--generate-diff`).
- Reviewing incidents from the human review queue.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runtimelens.policy.feedback import (
    DEFAULT_BASELINES_DIR,
    BaselineProposal,
    generate_baseline_diff,
)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for analyst review and diff generation."""
    parser = argparse.ArgumentParser(
        description="RuntimeLens Analyst Review Queue and Baseline Diff Tool"
    )
    parser.add_argument(
        "--generate-diff",
        action="store_true",
        help="Generate a unified Git diff proposal for a workload baseline",
    )
    parser.add_argument(
        "--workload",
        type=str,
        default="web",
        help="Target workload baseline (default: web)",
    )
    parser.add_argument(
        "--add-binary",
        type=str,
        action="append",
        dest="add_binaries",
        help="Propose adding an executable binary path to allowed_binaries",
    )
    parser.add_argument(
        "--add-peer",
        type=str,
        action="append",
        dest="add_peers",
        help="Propose adding a network peer to allowed_peers",
    )
    parser.add_argument(
        "--cpu-max-envelope",
        type=float,
        dest="cpu_max_envelope",
        help="Propose an updated ceiling for cpu_max_envelope_mcores",
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        default=None,
        help="Optional incident ID associating the change with a review ticket",
    )
    parser.add_argument(
        "--baselines-dir",
        type=Path,
        default=DEFAULT_BASELINES_DIR,
        help="Directory containing declarative baseline YAML files",
    )

    args = parser.parse_args(argv)

    if args.generate_diff:
        # If no explicit modifications were provided, generate a sample maintenance addition
        has_other_mods = bool(args.add_peers or args.cpu_max_envelope)
        default_bins = [] if has_other_mods else ["/usr/bin/maintenance.sh"]
        binaries = args.add_binaries or default_bins
        peers = args.add_peers or []
        cpu = args.cpu_max_envelope

        proposal = BaselineProposal(
            workload=args.workload,
            add_allowed_binaries=binaries,
            add_allowed_peers=peers,
            cpu_max_envelope_mcores=cpu,
            incident_id=args.incident_id,
            justification="Analyst confirmed benign activity in review queue",
        )

        try:
            result = generate_baseline_diff(proposal, baselines_dir=args.baselines_dir)
            if result.is_modified:
                sys.stdout.write(result.unified_diff)
            else:
                sys.stdout.write(f"# No modifications proposed for {args.workload}.yaml\n")
            return 0
        except Exception as e:
            sys.stderr.write(f"Error generating baseline diff: {e}\n")
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
