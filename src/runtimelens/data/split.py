"""Dataset partitioning (72/28), air-gap locking, and manifest (Decision D-05, Ticket 07)."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger("runtimelens.data.split")

DEFAULT_CHECKPOINT_PATH: Final[Path] = Path("data/scenarios/run_checkpoint.json")
DEFAULT_MANIFEST_PATH: Final[Path] = Path("datasets/splits/manifest_v1.json")
DEFAULT_AUDIT_ACCESS_LOG: Final[Path] = Path("data/audit/test_eval_access.log")

# Exact pre-registered split sizes matching Section 4.1 in docs/SCENARIOS.md:
# Dev: 288 runs (43 esc, 43 prv, 43 cry, 29 unk, 130 ben)
# Test: 112 runs (17 esc, 17 prv, 17 cry, 11 unk, 50 ben)
TARGET_SPLIT_COUNTS: Final[dict[str, dict[str, int]]] = {
    "dev": {
        "container_escape": 43,
        "privilege_abuse": 43,
        "cryptomining": 43,
        "unknown": 29,
        "benign": 130,
        "total": 288,
    },
    "test": {
        "container_escape": 17,
        "privilege_abuse": 17,
        "cryptomining": 17,
        "unknown": 11,
        "benign": 50,
        "total": 112,
    },
}


def partition_runs(
    runs: list[dict[str, Any]],
    random_seed: int = 1337,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Group and partition runs into stratified 72% Dev and 28% Held-out Test splits."""
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in runs:
        by_class[r["class"]].append(r)

    rng = random.Random(random_seed)
    dev_split: list[dict[str, Any]] = []
    test_split: list[dict[str, Any]] = []

    for c_name, c_runs in by_class.items():
        # Deterministic shuffle within class
        shuffled = list(c_runs)
        rng.shuffle(shuffled)

        test_target = TARGET_SPLIT_COUNTS["test"][c_name]
        test_items = shuffled[:test_target]
        dev_items = shuffled[test_target:]

        test_split.extend(test_items)
        dev_split.extend(dev_items)

    assert len(dev_split) == TARGET_SPLIT_COUNTS["dev"]["total"], (
        f"Dev split count mismatch: {len(dev_split)} != {TARGET_SPLIT_COUNTS['dev']['total']}"
    )
    assert len(test_split) == TARGET_SPLIT_COUNTS["test"]["total"], (
        f"Test split count mismatch: {len(test_split)} != {TARGET_SPLIT_COUNTS['test']['total']}"
    )

    # Sort deterministically by run_id
    dev_split.sort(key=lambda x: str(x.get("run_id", "")))
    test_split.sort(key=lambda x: str(x.get("run_id", "")))

    return dev_split, test_split


def build_and_lock_manifest(
    checkpoint_path: Path = DEFAULT_CHECKPOINT_PATH,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    random_seed: int = 1337,
) -> dict[str, Any]:
    """Build, serialize, and cryptographically lock manifest_v1.json with SHA-256."""
    if not checkpoint_path.exists():
        raise FileNotFoundError(f"Checkpoint file missing: {checkpoint_path}")

    raw_data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    runs_dict = raw_data.get("runs", raw_data)
    runs_list = list(runs_dict.values()) if isinstance(runs_dict, dict) else runs_dict

    dev_runs, test_runs = partition_runs(runs_list, random_seed=random_seed)

    manifest_payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "created_at": datetime.now(UTC).isoformat(),
        "total_runs": len(runs_list),
        "split_ratio": {"dev": 0.72, "test": 0.28},
        "target_counts": TARGET_SPLIT_COUNTS,
        "dev_split": dev_runs,
        "test_split": test_runs,
        "sha256_lock": "",
    }

    # Compute canonical SHA-256 excluding sha256_lock field
    canonical_json = json.dumps(
        {k: v for k, v in manifest_payload.items() if k != "sha256_lock"},
        sort_keys=True,
        separators=(",", ":"),
    )
    content_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    manifest_payload["sha256_lock"] = content_hash

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")
    logger.info("Saved locked dataset manifest to %s (SHA-256: %s)", manifest_path, content_hash)
    return manifest_payload


def log_test_eval_access(
    caller_info: str, purpose: str, access_log: Path = DEFAULT_AUDIT_ACCESS_LOG
) -> None:
    """Log any reading or evaluation access to the held-out test split."""
    access_log.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "caller": caller_info,
        "purpose": purpose,
    }
    with open(access_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Dataset Partitioning and Air-Gap Lock")
    parser.add_argument(
        "--checkpoint", default=str(DEFAULT_CHECKPOINT_PATH), help="Path to run checkpoint"
    )
    parser.add_argument(
        "--manifest", default=str(DEFAULT_MANIFEST_PATH), help="Destination manifest path"
    )
    args = parser.parse_args()

    print("=== RuntimeLens Dataset Partitioning & Manifest Air-Gap Lock (Ticket 07) ===")
    manifest = build_and_lock_manifest(Path(args.checkpoint), Path(args.manifest))

    print(f"Total Runs Partitioned: {manifest['total_runs']}")
    print(f"Dev Split Runs: {len(manifest['dev_split'])} (Target: 288)")
    print(f"Test Split Runs: {len(manifest['test_split'])} (Target: 112)")
    print(f"Air-Gap Cryptographic SHA-256 Lock: {manifest['sha256_lock']}")
    print(f"Manifest written to: {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
