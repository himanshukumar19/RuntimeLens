"""Tamper-evident, hash-chained audit log writer (Decision D-13)."""

from __future__ import annotations

import json
from pathlib import Path

from runtimelens.models.decision import AuditRecord, ClassificationResult, PolicyDecision
from runtimelens.models.event import CanonicalEvent

GENESIS_HASH = "0" * 64


class AuditWriter:
    """Appends decisions to an atomic, hash-chained tamper-evident audit JSONL log."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_hash = self._get_tail_hash()

    @staticmethod
    def _get_tail_hash_from_path(path: Path) -> str:
        if not path.exists() or path.stat().st_size == 0:
            return GENESIS_HASH

        try:
            with open(path, encoding="utf-8") as f:
                last_line = ""
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
                if last_line:
                    data = json.loads(last_line)
                    return str(data.get("record_hash") or GENESIS_HASH)
        except Exception:
            return GENESIS_HASH
        return GENESIS_HASH

    def _get_tail_hash(self) -> str:
        """Find the record_hash of the most recent record or return GENESIS_HASH."""
        return self._get_tail_hash_from_path(self.log_path)

    def write_record(
        self,
        event: CanonicalEvent,
        classification: ClassificationResult,
        decision: PolicyDecision,
    ) -> AuditRecord:
        """Construct, cryptographically hash, and append an AuditRecord."""
        record = AuditRecord(
            event_id=event.event_id,
            event=event,
            classification=classification,
            decision=decision,
            prev_record_hash=self.last_hash,
        )

        record.record_hash = record.compute_hash()
        self.last_hash = record.record_hash

        # Atomic append to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    @staticmethod
    def verify_chain(log_path: Path) -> tuple[bool, int, str | None]:
        """Verify the cryptographic hash integrity of the entire audit chain.

        Returns (is_valid, record_count, error_message).
        """
        if not log_path.exists() or log_path.stat().st_size == 0:
            return True, 0, None

        expected_prev = GENESIS_HASH
        count = 0

        with open(log_path, encoding="utf-8") as f:
            for idx, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record_dict = json.loads(stripped)
                    record = AuditRecord.model_validate(record_dict)
                except Exception as e:
                    return False, count, f"Record {idx} malformed: {e}"

                if record.prev_record_hash != expected_prev:
                    msg = (
                        f"Hash chain broken at record {idx}: "
                        f"prev_hash {record.prev_record_hash} != expected {expected_prev}"
                    )
                    return False, count, msg

                calculated = record.compute_hash()
                if record.record_hash != calculated:
                    msg = (
                        f"Hash mismatch at record {idx}: "
                        f"recorded {record.record_hash} != calculated {calculated}"
                    )
                    return False, count, msg

                expected_prev = record.record_hash
                count += 1

        return True, count, None

    @staticmethod
    def verify_chain_against_head(
        log_path: Path, expected_head_hash: str
    ) -> tuple[bool, int, str | None]:
        """Verify the hash integrity and assert that the head matches the anchored hash.

        Detects tail truncation (where an adversary drops the last N records).
        """
        is_valid, count, error = AuditWriter.verify_chain(log_path)
        if not is_valid:
            return False, count, error

        tail_hash = AuditWriter._get_tail_hash_from_path(log_path)
        if tail_hash != expected_head_hash:
            msg = (
                f"Truncation detected: log tail hash {tail_hash} != "
                f"anchored head hash {expected_head_hash}"
            )
            return False, count, msg

        return True, count, None
