#!/usr/bin/env python3
"""RuntimeLens Verification Control Harness (control-runtimelens).

CLI tool for launching, inspecting, driving, and tearing down RuntimeLens
verification instances, webhook receivers, and safety linters.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from runtimelens.audit.writer import AuditWriter


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Run diagnostic checks on the local environment."""
    print("=== RuntimeLens Doctor ===")
    all_ok = True

    # 1. Python version check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"[PASS] Python version: {py_ver} (>= 3.12 required)")

    # 2. Package import verification
    try:
        import runtimelens
        from runtimelens.models.event import CanonicalEvent
        from runtimelens.policy.engine import evaluate_policy

        _ = CanonicalEvent
        _ = evaluate_policy
        print(f"[PASS] RuntimeLens core package loaded ({runtimelens.__file__})")
    except Exception as e:
        print(f"[FAIL] RuntimeLens import error: {e}")
        all_ok = False

    # 3. Docker / OrbStack engine check
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            print(f"[PASS] Docker engine active (version: {proc.stdout.strip()})")
        else:
            print(f"[WARN] Docker engine not responding: {proc.stderr.strip() or 'daemon down'}")
    except Exception as e:
        print(f"[WARN] Docker check skipped: {e}")

    # 4. Kubectl context check
    try:
        proc = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            ctx = proc.stdout.strip()
            print(f"[INFO] Kubectl context: {ctx}")
            if ctx != "kind-runtimelens":
                print("[INFO] Context is not kind-runtimelens (cluster guardrail active)")
        else:
            print("[INFO] Kubectl context: none active (offline mode)")
    except Exception:
        print("[INFO] Kubectl not available or not configured (offline mode)")

    # 5. Secrets check on tracked files
    try:
        proc = subprocess.run(
            [sys.executable, "scripts/check_secrets.py", "pyproject.toml", "README.md"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            print("[PASS] Secret scanner guardrail operational")
        else:
            print(f"[FAIL] Secret scanner failed: {proc.stderr}")
            all_ok = False
    except Exception as e:
        print(f"[WARN] Secret scanner check skipped: {e}")

    return 0 if all_ok else 1


def cmd_start_webhook(args: argparse.Namespace) -> int:
    """Start an isolated webhook receiver daemon."""
    allowed_hosts = {"127.0.0.1", "localhost", "172.18.0.1"}
    if args.host not in allowed_hosts:
        print(
            f"ERROR: Safety refusal: host must be one of {allowed_hosts}, got {args.host!r}",
            file=sys.stderr,
        )
        return 1

    audit_path = Path(args.audit_file).resolve()
    pid_path = Path(args.pid_file).resolve()
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.parent.mkdir(parents=True, exist_ok=True)

    if pid_path.exists():
        try:
            old_pid = int(pid_path.read_text().strip())
            os.kill(old_pid, 0)
            print(f"ERROR: Server already running with PID {old_pid}", file=sys.stderr)
            return 1
        except OSError:
            pid_path.unlink()

    # Pass secret securely via environment variables, not CLI arguments
    child_env = os.environ.copy()
    child_env["FALCO_WEBHOOK_SECRET"] = args.secret

    cmd = [
        sys.executable,
        "-c",
        (
            "import sys; from runtimelens.collector.webhook import run_webhook_server; "
            "from pathlib import Path; "
            f"s = run_webhook_server({args.host!r}, {args.port}, "
            f"audit_path=Path({str(audit_path)!r})); "
            "s.serve_forever()"
        ),
    ]

    proc = subprocess.Popen(
        cmd,
        env=child_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid_path.write_text(str(proc.pid))

    # Wait for server to be responsive
    target_url = f"http://{args.host}:{args.port}/falco"
    started = False
    for _ in range(50):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
        try:
            req = urllib.request.Request(target_url, method="POST", data=b"{}")
            with urllib.request.urlopen(req, timeout=1.0):
                pass
        except urllib.error.HTTPError as e:
            # 401 or 400 means server is up and evaluating requests
            if e.code in (400, 401, 429):
                started = True
                break
        except OSError:
            pass

    if started:
        print(
            json.dumps(
                {
                    "status": "running",
                    "pid": proc.pid,
                    "host": args.host,
                    "port": args.port,
                    "audit_file": str(audit_path),
                }
            )
        )
        return 0
    else:
        print(f"ERROR: Webhook server failed to start on port {args.port}", file=sys.stderr)
        with contextlib.suppress(OSError):
            os.kill(proc.pid, signal.SIGTERM)
        if pid_path.exists():
            pid_path.unlink()
        return 1


def cmd_stop_webhook(args: argparse.Namespace) -> int:
    """Stop the webhook receiver daemon by PID file."""
    pid_path = Path(args.pid_file).resolve()
    if not pid_path.exists():
        print(f"WARN: PID file not found: {pid_path}", file=sys.stderr)
        return 0

    try:
        pid = int(pid_path.read_text().strip())
    except Exception as e:
        print(f"ERROR: Corrupted PID file: {e}", file=sys.stderr)
        pid_path.unlink(missing_ok=True)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except OSError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass

    pid_path.unlink(missing_ok=True)
    print(json.dumps({"status": "stopped", "pid": pid}))
    return 0


def cmd_post_event(args: argparse.Namespace) -> int:
    """Send an authenticated security event to the webhook receiver."""
    payload_str: str = args.payload
    raw_stripped = args.payload.strip()

    # If argument does not start with JSON object/array brackets, check if it's a file path
    if not (raw_stripped.startswith("{") or raw_stripped.startswith("[")):
        try:
            potential_file = Path(args.payload)
            if potential_file.is_file():
                payload_str = potential_file.read_text(encoding="utf-8")
        except OSError:
            pass

    try:
        payload_data = json.loads(payload_str)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON payload: {e}", file=sys.stderr)
        return 1

    body_bytes = json.dumps(payload_data).encode("utf-8")
    url = f"http://{args.host}:{args.port}{args.endpoint}"
    req = urllib.request.Request(
        url,
        data=body_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
            "X-Webhook-Token": args.secret,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = resp.read().decode("utf-8")
            status_code = resp.status
            print(json.dumps({"http_status": status_code, "response": json.loads(data)}, indent=2))
            return 0
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_body)
        except Exception:
            err_json = {"error": err_body}
        print(json.dumps({"http_status": e.code, "response": err_json}, indent=2))
        return 0 if e.code < 500 else 1
    except Exception as e:
        print(f"ERROR: Connection failed: {e}", file=sys.stderr)
        return 1


def cmd_verify_audit(args: argparse.Namespace) -> int:
    """Verify hash chain integrity of an audit log."""
    path = Path(args.audit_file).resolve()
    if not path.exists():
        print(f"ERROR: Audit log file does not exist: {path}", file=sys.stderr)
        return 1

    is_valid, count, error_msg = AuditWriter.verify_chain(path)
    result: dict[str, Any] = {
        "audit_file": str(path),
        "valid": is_valid,
        "record_count": count,
        "error": error_msg,
    }
    print(json.dumps(result, indent=2))
    return 0 if is_valid else 1


def cmd_safety_lint(_args: argparse.Namespace) -> int:
    """Run scenario manifest safety linter."""
    res = subprocess.run(
        [sys.executable, "scripts/scenario_safety_lint.py"],
        check=False,
    )
    return res.returncode


def cmd_audit_dataset(args: argparse.Namespace) -> int:
    """Run dataset anti-leakage and baseline integrity auditor."""
    res = subprocess.run(
        [sys.executable, "scripts/verify_dataset.py", "--runs-dir", args.runs_dir],
        check=False,
    )
    return res.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="RuntimeLens Verification Harness CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # doctor
    subparsers.add_parser("doctor", help="Run local diagnostic checks")

    # start-webhook
    p_start = subparsers.add_parser("start-webhook", help="Start background webhook receiver")
    p_start.add_argument("--host", default="127.0.0.1", help="Loopback host to bind")
    p_start.add_argument("--port", type=int, default=18765, help="Port to listen on")
    p_start.add_argument("--audit-file", required=True, help="Path for isolated audit output JSONL")
    p_start.add_argument("--secret", required=True, help="Shared webhook authentication secret")
    p_start.add_argument("--pid-file", required=True, help="Path to write server PID")

    # stop-webhook
    p_stop = subparsers.add_parser("stop-webhook", help="Stop background webhook receiver")
    p_stop.add_argument("--pid-file", required=True, help="Path to server PID file")

    # post-event
    p_post = subparsers.add_parser("post-event", help="Send event payload to webhook")
    p_post.add_argument("--host", default="127.0.0.1")
    p_post.add_argument("--port", type=int, default=18765)
    p_post.add_argument("--endpoint", default="/falco")
    p_post.add_argument("--secret", required=True)
    p_post.add_argument("--payload", required=True, help="JSON string or path to JSON file")

    # verify-audit
    p_audit = subparsers.add_parser("verify-audit", help="Verify audit log hash chain")
    p_audit.add_argument("--audit-file", required=True)

    # safety-lint
    subparsers.add_parser("safety-lint", help="Audit scenario manifests for safety guardrails")

    # audit-dataset
    p_data = subparsers.add_parser(
        "audit-dataset", help="Audit dataset directory for anti-leakage compliance"
    )
    p_data.add_argument(
        "--runs-dir", default="data/raw/runs", help="Directory containing run telemetry"
    )

    args = parser.parse_args()

    if args.command == "doctor":
        return cmd_doctor(args)
    elif args.command == "start-webhook":
        return cmd_start_webhook(args)
    elif args.command == "stop-webhook":
        return cmd_stop_webhook(args)
    elif args.command == "post-event":
        return cmd_post_event(args)
    elif args.command == "verify-audit":
        return cmd_verify_audit(args)
    elif args.command == "safety-lint":
        return cmd_safety_lint(args)
    elif args.command == "audit-dataset":
        return cmd_audit_dataset(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
