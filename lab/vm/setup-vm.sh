#!/usr/bin/env bash
set -euo pipefail

echo "======================================================"
echo "RuntimeLens VM Provisioning: Ubuntu 24.04 ARM64"
echo "======================================================"

# 1. Verify Kernel BTF support (CRITICAL FEASIBILITY REQUIREMENT)
echo "[1/6] Verifying Linux Kernel BTF (/sys/kernel/btf/vmlinux)..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found! eBPF CO-RE is unavailable."
    echo "Feasibility Gate 02a FAILED."
    exit 1
fi
echo "SUCCESS: Kernel BTF verified at /sys/kernel/btf/vmlinux."

# 2. Update apt and install basic utilities
echo "[2/6] Installing base prerequisites..."
sudo apt-get update -y
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    make \
    jq

# 3. Install Docker Engine
echo "[3/6] Installing Docker..."
if ! command -v docker &>/dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER"
fi
echo "SUCCESS: Docker installed."

# 4. Install kubectl
echo "[4/6] Installing kubectl..."
if ! command -v kubectl &>/dev/null; then
    KUBECTL_VERSION="v1.30.0"
    ARCH=$(dpkg --print-architecture)
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    rm -f kubectl
fi
echo "SUCCESS: kubectl installed."

# 5. Install kind
echo "[5/6] Installing kind..."
if ! command -v kind &>/dev/null; then
    KIND_VERSION="v0.22.0"
    ARCH=$(dpkg --print-architecture)
    curl -Lo ./kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${ARCH}"
    chmod +x ./kind
    sudo mv ./kind /usr/local/bin/kind
fi
echo "SUCCESS: kind installed."

# 6. Install Cilium CLI
echo "[6/7] Installing Cilium CLI..."
if ! command -v cilium &>/dev/null; then
    CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
    ARCH=$(dpkg --print-architecture)
    curl -L --fail --remote-name-all "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${ARCH}.tar.gz"
    sudo tar xzvfC "cilium-linux-${ARCH}.tar.gz" /usr/local/bin
    rm -f "cilium-linux-${ARCH}.tar.gz"
fi
echo "SUCCESS: Cilium CLI installed."

# 7. Install Helm
echo "[7/7] Installing Helm..."
if ! command -v helm &>/dev/null; then
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi
echo "SUCCESS: Helm installed."

echo "======================================================"
echo "VM Provisioning Complete. Ready for kind cluster creation."
echo "======================================================"
