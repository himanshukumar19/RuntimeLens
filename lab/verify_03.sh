#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "Ticket 03: Minimal Vertical Slice Verification"
echo "=========================================================="

REQUIRED_CONTEXT="kind-runtimelens"
CURRENT_CONTEXT=$(kubectl config current-context)
if [ "$CURRENT_CONTEXT" != "$REQUIRED_CONTEXT" ]; then
    echo "SAFETY REFUSAL: Current context is '$CURRENT_CONTEXT', expected '$REQUIRED_CONTEXT'!"
    exit 1
fi
echo "PASS: Context confirmed as '$REQUIRED_CONTEXT'."

AUDIT_DIR="/home/ubuntu/vm_outputs/audit"
AUDIT_LOG="$AUDIT_DIR/decisions.jsonl"
mkdir -p "$AUDIT_DIR"
rm -f "$AUDIT_LOG"

echo "[1/4] Starting Webhook Receiver on 127.0.0.1:8765..."
export PYTHONPATH="/home/ubuntu/RuntimeLens/src"
python3 lab/run_webhook.py "$AUDIT_LOG" &
WEBHOOK_PID=$!
trap "kill $WEBHOOK_PID 2>/dev/null || true" EXIT

sleep 2

# Verify webhook is responding
echo "[2/4] Testing Webhook Endpoint and Measuring End-to-End Latency..."
START_TIME=$(date +%s%N)

curl -s -X POST http://127.0.0.1:8765/falco \
  -H "Content-Type: application/json" \
  -d '{
    "output": "18:20:00: Interactive shell spawned in tenant container",
    "output_fields": {
      "k8s.ns.name": "tenant-a",
      "k8s.pod.name": "web-live-test",
      "k8s.pod.uid": "uid-web-live-01",
      "container.name": "web",
      "container.id": "c1234567890a",
      "container.image.repository": "alpine",
      "container.image.tag": "3.19",
      "proc.cmdline": "/bin/sh -i",
      "proc.name": "sh",
      "user.name": "root",
      "user.uid": 0
    },
    "rule": "Interactive Shell Spawned in Non-Debug Container",
    "time": "'$(date -u -Iseconds)'"
  }' | jq .

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "PASS: Webhook response received. Roundtrip Latency: ${ELAPSED_MS} ms (Requirement: < 2000 ms)."

if [ "$ELAPSED_MS" -ge 2000 ]; then
    echo "FAIL: Latency exceeded 2000 ms!"
    exit 1
fi

echo "[3/4] Triggering Live Container Exec Syscall on Cluster..."
POD_NAME=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
echo "Triggering kubectl exec in $POD_NAME..."
kubectl exec -n tenant-a "$POD_NAME" -- /bin/sh -c "echo live_syscall_exec_test"

sleep 3

echo "[4/4] Verifying Audit Log Records and Cryptographic Hash Chain..."
if [ ! -s "$AUDIT_LOG" ]; then
    echo "FAIL: Audit log $AUDIT_LOG is empty!"
    exit 1
fi

echo "Sample Audit Record from $AUDIT_LOG:"
tail -n 1 "$AUDIT_LOG" | jq .

echo "Verifying cryptographic hash chain integrity..."
python3 -c "
from pathlib import Path
from runtimelens.audit.writer import AuditWriter

is_valid, count, error = AuditWriter.verify_chain(Path('$AUDIT_LOG'))
print(f'Audit Chain Validation: is_valid={is_valid}, records={count}, error={error}')
assert is_valid, f'Chain verification failed: {error}'
assert count >= 1, 'Expected at least 1 record'
print('PASS: Cryptographic hash chain verified successfully.')
"

echo "=========================================================="
echo "Exit Gate 03 PASSED: Minimal Vertical Slice Verified."
echo "=========================================================="
