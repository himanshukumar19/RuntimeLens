"""Tests for repository secrets prevention guard."""

from pathlib import Path
from tempfile import NamedTemporaryFile

from scripts.check_secrets import check_file


def test_rejects_env_file() -> None:
    violations = check_file(".env")
    assert any("Forbidden secret file name detected" in v for v in violations)


def test_rejects_env_local_file() -> None:
    violations = check_file(".env.production")
    assert any("Forbidden secret file name detected" in v for v in violations)


def test_rejects_key_file() -> None:
    violations = check_file("server.key")
    assert any("Forbidden secret file name detected" in v for v in violations)


def test_rejects_token_file() -> None:
    violations = check_file("auth.token")
    assert any("Forbidden secret file name detected" in v for v in violations)


def test_rejects_private_key_content() -> None:
    with NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        )
        temp_path = f.name
    try:
        violations = check_file(temp_path)
        assert any("Private cryptographic key" in v for v in violations)
    finally:
        Path(temp_path).unlink()


def test_rejects_scaledown_api_key_assignment() -> None:
    with NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write('SCALEDOWN_API_KEY = "sk-live-1234567890abcdef"')
        temp_path = f.name
    try:
        violations = check_file(temp_path)
        assert any("ScaleDown API key assignment" in v for v in violations)
    finally:
        Path(temp_path).unlink()


def test_accepts_clean_file() -> None:
    with NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write("import os\napi_key = os.getenv('SCALEDOWN_API_KEY')\n")
        temp_path = f.name
    try:
        violations = check_file(temp_path)
        assert violations == []
    finally:
        Path(temp_path).unlink()
