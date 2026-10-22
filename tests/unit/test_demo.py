"""Unit tests for Live Interactive Demonstration Script (Ticket 16c)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from runtimelens.audit.writer import GENESIS_HASH, AuditWriter
from scripts.demo import main


def test_demo_auto_rules_execution(tmp_path: Path) -> None:
    """Test demo script running in automated rules mode end-to-end."""
    out_file = tmp_path / "demo_rules_audit.jsonl"
    rc = main(["--auto", "--output", str(out_file), "--classifier", "rules", "--no-color"])
    assert rc == 0
    assert out_file.exists()

    # Verify cryptographic integrity
    is_valid, count, err = AuditWriter.verify_chain(out_file)
    assert is_valid, f"Verification failed: {err}"
    assert count == 4

    # Inspect the four records
    records: list[dict[str, object]] = []
    with open(out_file, encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))

    assert len(records) == 4

    # Scenario 1: Benign
    r1 = records[0]
    assert isinstance(r1, dict)
    cl1 = r1.get("classification")
    dec1 = r1.get("decision")
    assert isinstance(cl1, dict) and cl1.get("predicted_class") == "benign"
    assert isinstance(dec1, dict) and dec1.get("action") == "log"
    assert r1.get("prev_record_hash") == GENESIS_HASH

    # Scenario 2: Privilege Abuse
    r2 = records[1]
    assert isinstance(r2, dict)
    cl2 = r2.get("classification")
    dec2 = r2.get("decision")
    assert isinstance(cl2, dict) and cl2.get("predicted_class") == "privilege_abuse"
    assert isinstance(dec2, dict) and dec2.get("action") == "alert"
    assert r2.get("prev_record_hash") == r1.get("record_hash")

    # Scenario 3: Container Escape
    r3 = records[2]
    assert isinstance(r3, dict)
    cl3 = r3.get("classification")
    dec3 = r3.get("decision")
    assert isinstance(cl3, dict) and cl3.get("predicted_class") == "container_escape"
    assert isinstance(dec3, dict) and dec3.get("action") == "quarantine"
    assert isinstance(dec3, dict) and dec3.get("auto_rollback_ttl_seconds") == 900
    assert r3.get("prev_record_hash") == r2.get("record_hash")

    # Scenario 4: Cryptomining
    r4 = records[3]
    assert isinstance(r4, dict)
    cl4 = r4.get("classification")
    dec4 = r4.get("decision")
    assert isinstance(cl4, dict) and cl4.get("predicted_class") == "cryptomining"
    assert isinstance(dec4, dict) and dec4.get("action") == "quarantine"
    assert isinstance(dec4, dict) and dec4.get("auto_rollback_ttl_seconds") == 900
    assert r4.get("prev_record_hash") == r3.get("record_hash")


def test_demo_auto_scaledown_execution(tmp_path: Path) -> None:
    """Test demo script running in automated ScaleDown mode."""
    out_file = tmp_path / "demo_scaledown_audit.jsonl"
    rc = main(["--auto", "--output", str(out_file), "--classifier", "scaledown", "--no-color"])
    assert rc == 0
    assert out_file.exists()

    is_valid, count, err = AuditWriter.verify_chain(out_file)
    assert is_valid, f"Verification failed: {err}"
    assert count == 4

    records: list[dict[str, object]] = []
    with open(out_file, encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))

    # In ScaleDown mode, Scenario 2 routes to human_review (confidence < 0.70 threshold)
    r2 = records[1]
    assert isinstance(r2, dict)
    cl2 = r2.get("classification")
    dec2 = r2.get("decision")
    assert isinstance(cl2, dict) and cl2.get("predicted_class") == "privilege_abuse"
    assert isinstance(cl2, dict) and cl2.get("classifier_type") == "scaledown"
    assert isinstance(dec2, dict) and dec2.get("action") == "human_review"
    assert isinstance(dec2, dict) and "LOW_CONFIDENCE_GATE" in (dec2.get("reason_codes") or [])


def test_demo_cli_subprocess(tmp_path: Path) -> None:
    """Test executing demo script via external subprocess CLI command."""
    out_file = tmp_path / "subprocess_demo_audit.jsonl"
    cmd = [
        sys.executable,
        "scripts/demo.py",
        "--auto",
        "--output",
        str(out_file),
        "--no-color",
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Process stderr: {proc.stderr}"
    assert "[PASS] Cryptographic integrity verified" in proc.stdout
    assert "RuntimeLens vertical slice completed successfully" in proc.stdout

    is_valid, count, _ = AuditWriter.verify_chain(out_file)
    assert is_valid
    assert count == 4


def test_demo_tamper_detection(tmp_path: Path) -> None:
    """Test that tampering with any record in the demo log is detected immediately."""
    out_file = tmp_path / "tamper_demo_audit.jsonl"
    rc = main(["--auto", "--output", str(out_file), "--no-color"])
    assert rc == 0

    # Tamper with the second line
    lines = out_file.read_text(encoding="utf-8").splitlines()
    tampered_record = json.loads(lines[1])
    # Alter the action from alert to log
    tampered_record["decision"]["action"] = "log"
    lines[1] = json.dumps(tampered_record)
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    is_valid, _, err = AuditWriter.verify_chain(out_file)
    assert is_valid is False
    assert err is not None
    assert "Hash mismatch at record 1" in err or "Hash chain broken" in err
