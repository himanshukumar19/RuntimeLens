#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "Ticket 02a: Lab VM & eBPF Feasibility Gate Verification"
echo "=========================================================="

REQUIRED_CONTEXT="kind-runtimelens"

# 1. BTF Check
echo "[Check 1/4] Verifying /sys/kernel/btf/vmlinux..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "FAIL: /sys/kernel/btf/vmlinux is missing!"
    exit 1
fi
ls -lh /sys/kernel/btf/vmlinux
echo "PASS: Kernel BTF is present and accessible."

# 2. kind cluster creation
echo "[Check 2/4] Initializing kind cluster (kind-runtimelens)..."
if ! kind get clusters | grep -q "^runtimelens$"; then
    kind create cluster --config lab/kind/kind-config.yaml
else
    echo "kind cluster 'runtimelens' already exists."
fi

# 3. Context Verification Guard
echo "[Check 3/4] Verifying kubectl context..."
CURRENT_CONTEXT=$(kubectl config current-context)
if [ "$CURRENT_CONTEXT" != "$REQUIRED_CONTEXT" ]; then
    echo "SAFETY REFUSAL: Current context is '$CURRENT_CONTEXT', expected '$REQUIRED_CONTEXT'!"
    exit 1
fi
echo "PASS: kubectl context confirmed as '$REQUIRED_CONTEXT'."

# 4. Cilium CNI Installation with kube-proxy replacement and Hubble
echo "[Check 4/4] Installing and verifying Cilium CNI with Hubble..."
if ! cilium status --brief 2>/dev/null | grep -q "OK"; then
    echo "Installing Cilium..."
    cilium install \
        --set kubeProxyReplacement=true \
        --set hubble.enabled=true \
        --set hubble.relay.enabled=true \
        --set hubble.ui.enabled=true
fi

echo "Waiting for Cilium to reach healthy status..."
cilium status --wait

echo "=========================================================="
echo "Feasibility Gate 02a PASSED: BTF, kind, Cilium & Hubble OK."
echo "=========================================================="
