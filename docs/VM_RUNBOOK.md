# VM & Cluster Execution Runbook: `runtimelens-vm`

## 1. Overview & Isolation Principles
The RuntimeLens laboratory cluster operates inside an Ubuntu 24.04 ARM64 Linux VM named `runtimelens-vm` (4 vCPUs, 6 GB RAM, 40 GB disk).

To prevent data contamination, protect secrets, and maintain strict host isolation:
- **No Shared Folder Mounting:** `multipass mount` is strictly forbidden.
- **Air-Gapped Ingestion:** Only Git-tracked repository files are transferred into the VM. Untracked files, `.env`, credentials, local tokens, and Mac kubeconfigs never enter the VM.
- **Zero Credentials in VM:** Git operations inside the VM never store or use personal access tokens or credentials.
- **Isolated Outputs:** VM-generated outputs (telemetry captures, test logs, evidence files) are written to a dedicated directory in the VM (`/home/ubuntu/vm_outputs/`) and copied back explicitly to the Mac via `multipass transfer`.

---

## 2. Inbound Code Transfer: Mac $\rightarrow$ VM

To sync the latest verified codebase into the VM without exposing untracked secrets:

```bash
# 1. On Mac: Generate a clean tar archive of Git-tracked HEAD
git archive --format=tar HEAD | gzip > /private/var/folders/3f/1mwww4fs68dbtv8qq7q5sjkc0000gn/T/opencode/runtimelens-repo.tar.gz

# 2. Transfer archive into VM
multipass transfer /private/var/folders/3f/1mwww4fs68dbtv8qq7q5sjkc0000gn/T/opencode/runtimelens-repo.tar.gz runtimelens-vm:/home/ubuntu/runtimelens-repo.tar.gz

# 3. Inside VM: Unpack into project workspace
multipass exec runtimelens-vm -- bash -c "mkdir -p /home/ubuntu/RuntimeLens && tar -xzf /home/ubuntu/runtimelens-repo.tar.gz -C /home/ubuntu/RuntimeLens"

# 4. On Mac: Clean up temporary transfer artifact
rm -f /private/var/folders/3f/1mwww4fs68dbtv8qq7q5sjkc0000gn/T/opencode/runtimelens-repo.tar.gz
```

---

## 3. Outbound Evidence Transfer: VM $\rightarrow$ Mac

All cluster scenario captures, evidence outputs, and logs generated inside the VM reside under `/home/ubuntu/vm_outputs/`:

```bash
# Example: Copying Gate 02a verification evidence back to Mac
multipass transfer runtimelens-vm:/home/ubuntu/vm_outputs/gate_02a_evidence.log ./docs/evidence/gate_02a_evidence.log
```

---

## 4. VM Lifecycle Rules & Health Checks

- **VM Name:** `runtimelens-vm`
- **Prohibited Operations:** Never execute `multipass delete`, `multipass purge`, or `multipass stop --all` without explicit user sign-off.
- **Stop / Restart Protocol:** Never restart or stop the VM without prior notification.
- **Post-Restart Verification:** If the VM is stopped and restarted, the following health commands must run and be reported before executing further workloads:
  ```bash
  multipass exec runtimelens-vm -- bash -c "cd /home/ubuntu/RuntimeLens && make lab-up && make lab-verify"
  ```
