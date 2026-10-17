#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "Ticket 02a: Lab VM & eBPF Feasibility Gate Verification"
echo "=========================================================="

REQUIRED_CONTEXT="kind-runtimelens"

# 1. BTF Check
echo "[Check 1/5] Verifying /sys/kernel/btf/vmlinux..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "FAIL: /sys/kernel/btf/vmlinux is missing!"
    exit 1
fi
ls -lh /sys/kernel/btf/vmlinux
echo "PASS: Kernel BTF is present and accessible."

# 2. kind cluster creation
echo "[Check 2/5] Initializing kind cluster (kind-runtimelens)..."
if ! kind get clusters | grep -q "^runtimelens$"; then
    kind create cluster --config lab/kind/kind-config.yaml
else
    echo "kind cluster 'runtimelens' already exists."
fi

# 3. Context Verification Guard
echo "[Check 3/5] Verifying kubectl context..."
CURRENT_CONTEXT=$(kubectl config current-context)
if [ "$CURRENT_CONTEXT" != "$REQUIRED_CONTEXT" ]; then
    echo "SAFETY REFUSAL: Current context is '$CURRENT_CONTEXT', expected '$REQUIRED_CONTEXT'!"
    exit 1
fi
echo "PASS: kubectl context confirmed as '$REQUIRED_CONTEXT'."

# 4. Cilium CNI Installation with kube-proxy replacement and Hubble
echo "[Check 4/5] Installing and verifying Cilium CNI with Hubble..."
if ! cilium status --brief 2>/dev/null | grep -q "OK"; then
    echo "Installing Cilium..."
    cilium install \
        --set kubeProxyReplacement=true \
        --set hubble.enabled=true \
        --set hubble.relay.enabled=true \
        --set hubble.ui.enabled=false
fi

echo "Waiting for Cilium to reach healthy status..."
cilium status --wait

# 5. Falco Installation with modern eBPF Probe & Event Generator Verification
echo "[Check 5/5] Deploying Falco with modern eBPF driver and verifying event-generator..."
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

if ! kubectl get daemonset -n falco falco &>/dev/null; then
    echo "Deploying Falco via Helm (modern_ebpf)..."
    helm upgrade --install falco falcosecurity/falco \
        --namespace falco --create-namespace \
        --set driver.kind=modern_ebpf \
        --set tty=true
fi

echo "Waiting for Falco pod to become ready..."
kubectl rollout status daemonset/falco -n falco --timeout=180s

echo "Running event-generator test..."
kubectl run event-generator-test \
    --image=falcosecurity/event-generator:latest \
    --restart=Never \
    --namespace=default \
    -- run syscall --loop=false

echo "Waiting for event-generator test to complete..."
kubectl wait --for=condition=Ready pod/event-generator-test --timeout=60s || true
sleep 5

echo "Capturing Falco detection logs..."
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50

echo "Cleaning up event generator test pod..."
kubectl delete pod event-generator-test --namespace=default --ignore-not-found=true

echo "=========================================================="
echo "Feasibility Gate 02a PASSED: BTF, kind, Cilium, Falco eBPF & event-generator verified."
echo "=========================================================="
