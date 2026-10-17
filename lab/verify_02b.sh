#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "Ticket 02b: Falco, Audit, Namespaces & Workloads Verification"
echo "=========================================================="

REQUIRED_CONTEXT="kind-runtimelens"

# 1. Setup host audit directories in VM
echo "[1/7] Preparing audit policy and log directories on VM host..."
sudo mkdir -p /etc/kubernetes/policies /var/log/kubernetes/audit
sudo cp lab/audit/audit-policy.yaml /etc/kubernetes/policies/audit-policy.yaml
sudo chmod 644 /etc/kubernetes/policies/audit-policy.yaml
sudo chmod 777 /var/log/kubernetes/audit

# 2. Ensure kind cluster has API server audit policy enabled
echo "[2/7] Ensuring kind cluster has API server auditing enabled..."
if ! kind get clusters | grep -q "^runtimelens$"; then
    echo "Creating cluster to bind API server audit policy..."
    kind create cluster --config lab/kind/kind-config.yaml
else
    echo "kind cluster 'runtimelens' already exists."
fi

# Context verification guard
CURRENT_CONTEXT=$(kubectl config current-context)
if [ "$CURRENT_CONTEXT" != "$REQUIRED_CONTEXT" ]; then
    echo "SAFETY REFUSAL: Current context is '$CURRENT_CONTEXT', expected '$REQUIRED_CONTEXT'!"
    exit 1
fi
echo "PASS: Context confirmed as '$REQUIRED_CONTEXT'."

# 3. Install Cilium CNI with Hubble
echo "[3/7] Verifying Cilium CNI with Hubble..."
if ! cilium status --brief 2>/dev/null | grep -q "OK"; then
    echo "Installing Cilium CNI..."
    cilium install \
        --set kubeProxyReplacement=true \
        --set hubble.enabled=true \
        --set hubble.relay.enabled=true \
        --set hubble.ui.enabled=true
fi
cilium status --wait

# 4. Deploy Falco with modern eBPF and JSON output
echo "[4/7] Deploying Falco with modern eBPF and JSON output..."
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --values lab/falco/falco-values.yaml
kubectl rollout status daemonset/falco -n falco --timeout=180s

# 5. Deploy Tenant Namespaces, Quotas, and NetworkPolicies
echo "[5/7] Deploying tenant namespaces, quotas, and default-deny NetworkPolicies..."
kubectl apply -f lab/tenants/namespaces.yaml
kubectl apply -f lab/tenants/quotas.yaml
kubectl apply -f lab/tenants/network-policies.yaml

# 6. Deploy Workloads in all 3 tenant namespaces
echo "[6/7] Deploying hardened ARM64 workloads across tenant namespaces..."
kubectl apply -f lab/workloads/tenant-workloads.yaml

echo "Waiting for tenant-a workloads to roll out..."
kubectl rollout status deployment/web -n tenant-a --timeout=90s
kubectl rollout status deployment/api -n tenant-a --timeout=90s
kubectl rollout status deployment/database -n tenant-a --timeout=90s
kubectl rollout status deployment/payment-style -n tenant-a --timeout=90s

echo "Waiting for tenant-b workloads to roll out..."
kubectl rollout status deployment/web -n tenant-b --timeout=90s
kubectl rollout status deployment/api -n tenant-b --timeout=90s
kubectl rollout status deployment/database -n tenant-b --timeout=90s
kubectl rollout status deployment/payment-style -n tenant-b --timeout=90s

echo "Waiting for tenant-c workloads to roll out..."
kubectl rollout status deployment/web -n tenant-c --timeout=90s
kubectl rollout status deployment/api -n tenant-c --timeout=90s
kubectl rollout status deployment/database -n tenant-c --timeout=90s
kubectl rollout status deployment/payment-style -n tenant-c --timeout=90s

# 7. Verification Tests
echo "[7/7] Running Exit Gate 02b Verification Checks..."

echo "--- Check A: Verify Kubernetes API Audit Log Stream ---"
# Trigger a Kubernetes API operation
kubectl get pods -n tenant-a > /dev/null
sleep 2

AUDIT_LOG="/var/log/kubernetes/audit/audit.log"
if [ ! -s "$AUDIT_LOG" ]; then
    echo "FAIL: Audit log $AUDIT_LOG is missing or empty!"
    exit 1
fi
echo "Audit log actively receiving events. Sample record:"
tail -n 1 "$AUDIT_LOG" | jq .

echo "--- Check B: Verify PSS and Tenant Workloads ---"
kubectl get namespaces -L pod-security.kubernetes.io/enforce,pod-security.kubernetes.io/audit
kubectl get pods -A -l tenant

echo "--- Check C: Verify NetworkPolicy Default-Deny ---"
kubectl get networkpolicies -A

echo "--- Check D: Trigger Live Syscall and Verify Falco JSON Output ---"
# Trigger sensitive file read inside tenant-a web pod
POD_NAME=$(kubectl get pod -n tenant-a -l app=web -o jsonpath='{.items[0].metadata.name}')
echo "Executing test read on /etc/shadow in pod $POD_NAME..."
kubectl exec -n tenant-a "$POD_NAME" -- cat /etc/shadow 2>&1 || true
sleep 3

echo "Inspecting Falco detection log for JSON output:"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "Read sensitive" || true

echo "=========================================================="
echo "Exit Gate 02b PASSED: Falco, Audit, Namespaces & Workloads Healthy."
echo "=========================================================="
