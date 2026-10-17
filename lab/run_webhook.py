"""Webhook runner script for live cluster ingestion."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from runtimelens.collector.webhook import run_webhook_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if __name__ == "__main__":
    audit_file = Path("/home/ubuntu/vm_outputs/audit/decisions.jsonl")
    if len(sys.argv) > 1:
        audit_file = Path(sys.argv[1])

    audit_file.parent.mkdir(parents=True, exist_ok=True)
    server = run_webhook_server(host="127.0.0.1", port=8765, audit_path=audit_file)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
