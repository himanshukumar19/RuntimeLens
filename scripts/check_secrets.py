#!/usr/bin/env python3
"""Pre-commit hook and CI script to prevent committing secrets, tokens, or forbidden files."""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN_FILE_PATTERNS = [
    r"^\.env(\..+)?$",
    r".*\.key$",
    r".*\.pem$",
    r".*\.token$",
    r".*secret.*",
    r".*credential.*",
]

SECRET_CONTENT_PATTERNS = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private cryptographic key",
    ),
    (
        re.compile(r"SCALEDOWN_API_KEY\s*=\s*[\"'][a-zA-Z0-9_\-]{8,}[\"']"),
        "ScaleDown API key assignment",
    ),
    (
        re.compile(
            r"(?:api[_-]?key|auth[_-]?token|secret[_-]?token)\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{16,}[\"']",
            re.IGNORECASE,
        ),
        "Generic API/Auth token",
    ),
    (
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),
        "GitHub Personal Access Token",
    ),
]

# Paths allowed to contain references (e.g. documentation or tests checking redaction)
EXCLUDED_PATHS = {
    Path("scripts/check_secrets.py"),
    Path("tests/unit/test_secrets_guard.py"),
}


def check_file(path_str: str) -> list[str]:
    path = Path(path_str)
    violations: list[str] = []

    # Exclude files specifically designed to implement or test secret checks
    normalized_path = path.as_posix()
    if any(str(excluded) in normalized_path for excluded in EXCLUDED_PATHS):
        return violations

    # 1. Check filename patterns
    filename = path.name
    for pattern in FORBIDDEN_FILE_PATTERNS:
        if re.match(pattern, filename, re.IGNORECASE):
            violations.append(f"Forbidden secret file name detected: {path}")

    if not path.is_file():
        return violations

    # 2. Check file contents
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        violations.append(f"Could not read {path}: {e}")
        return violations

    for regex, desc in SECRET_CONTENT_PATTERNS:
        matches = regex.findall(content)
        if matches:
            violations.append(f"Secret detected in {path} ({desc})")

    return violations


def main() -> int:
    files_to_check = sys.argv[1:]
    if not files_to_check:
        return 0

    all_violations: list[str] = []
    for f in files_to_check:
        violations = check_file(f)
        all_violations.extend(violations)

    if all_violations:
        print("\n[BLOCKED] Secret verification failed! Unsafe files or credentials detected:\n")
        for v in all_violations:
            print(f"  - {v}")
        print("\nPlease remove all credentials, .env files, or keys before committing.\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
