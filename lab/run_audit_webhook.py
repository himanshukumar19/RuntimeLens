"""Audit Webhook runner script for live cluster ingestion."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from runtimelens.collector.audit_webhook import run_audit_webhook_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if __name__ == "__main__":
    raw_file = Path("/home/ubuntu/vm_outputs/audit/live_audit_webhook_events.jsonl")
    host = "172.18.0.1"
    port = 8766
    cert = Path("/etc/kubernetes/policies/audit.crt")
    key = Path("/etc/kubernetes/policies/audit.key")

    if len(sys.argv) > 1:
        raw_file = Path(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]
    if len(sys.argv) > 3:
        port = int(sys.argv[3])

    raw_file.parent.mkdir(parents=True, exist_ok=True)
    server = run_audit_webhook_server(
        host=host,
        port=port,
        raw_path=raw_file,
        cert_file=cert if cert.exists() else None,
        key_file=key if key.exists() else None,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
