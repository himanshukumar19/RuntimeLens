"""Automated CI leakage tests for dataset split manifest (Ticket 07)."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from runtimelens.data.split import (
    DEFAULT_MANIFEST_PATH,
    TARGET_SPLIT_COUNTS,
    log_test_eval_access,
)


def _load_manifest() -> dict[str, Any]:
    assert DEFAULT_MANIFEST_PATH.exists(), f"Manifest missing at {DEFAULT_MANIFEST_PATH}"
    result: dict[str, Any] = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
    return result


def test_zero_leakage_between_dev_and_test_splits() -> None:
    manifest = _load_manifest()
    dev_runs = manifest["dev_split"]
    test_runs = manifest["test_split"]

    dev_ids = {r["run_id"] for r in dev_runs}
    test_ids = {r["run_id"] for r in test_runs}

    # Strict disjointness assertion: zero overlapping run IDs
    intersection = dev_ids & test_ids
    assert len(intersection) == 0, f"DATA LEAKAGE DETECTED! Overlapping runs: {intersection}"


def test_exact_split_counts_and_stratification() -> None:
    manifest = _load_manifest()
    dev_runs = manifest["dev_split"]
    test_runs = manifest["test_split"]

    assert len(dev_runs) == 288, f"Expected 288 Dev runs, got {len(dev_runs)}"
    assert len(test_runs) == 112, f"Expected 112 Test runs, got {len(test_runs)}"
    assert len(dev_runs) + len(test_runs) == 400

    dev_counts = Counter(r["class"] for r in dev_runs)
    test_counts = Counter(r["class"] for r in test_runs)

    for c_name, expected_dev_count in TARGET_SPLIT_COUNTS["dev"].items():
        if c_name != "total":
            assert dev_counts[c_name] == expected_dev_count, (
                f"Dev count mismatch for {c_name}: {dev_counts[c_name]} != {expected_dev_count}"
            )

    for c_name, expected_test_count in TARGET_SPLIT_COUNTS["test"].items():
        if c_name != "total":
            assert test_counts[c_name] == expected_test_count, (
                f"Test count mismatch for {c_name}: {test_counts[c_name]} != {expected_test_count}"
            )


def test_manifest_sha256_cryptographic_lock_valid() -> None:
    manifest = _load_manifest()
    recorded_hash = manifest["sha256_lock"]

    canonical_json = json.dumps(
        {k: v for k, v in manifest.items() if k != "sha256_lock"},
        sort_keys=True,
        separators=(",", ":"),
    )
    computed_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    assert recorded_hash == computed_hash, "Manifest SHA-256 lock mismatch! Manifest was modified."


def test_zero_test_split_leakage_in_baselines() -> None:
    manifest = _load_manifest()
    test_ids = {r["run_id"] for r in manifest["test_split"]}

    # Inspect all YAML baselines under baselines/
    baselines_dir = Path("baselines")
    for b_file in baselines_dir.glob("*.yaml"):
        content = b_file.read_text(encoding="utf-8")
        for tid in test_ids:
            assert tid not in content, f"LEAKAGE: Test {tid} referenced in baseline {b_file.name}!"


def test_audit_logging_tracks_test_eval_access(tmp_path: Path) -> None:
    test_log = tmp_path / "test_access.log"
    log_test_eval_access("eval_harness", "unit_test_verification", access_log=test_log)

    assert test_log.exists()
    lines = test_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["caller"] == "eval_harness"
    assert record["purpose"] == "unit_test_verification"
