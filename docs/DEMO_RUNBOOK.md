# RuntimeLens Live Demonstration & Viva Defense Runbook

## Overview
This runbook guides operators and student researchers through the 5-minute live demonstration of RuntimeLens for viva defense and technical review. It details the demonstration script execution, step-by-step talk track, expected outputs, examiner FAQs, and contingency fallbacks.

The demonstration tool is located at `scripts/demo.py`. It exercises the full vertical slice across four realistic scenarios and concludes with cryptographic audit verification.

## Demonstration Execution Commands
The demonstration runs either interactively (step-by-step with pause prompts) or automated (non-interactive):

- Interactive demonstration:
  ```bash
  make demo
  # or directly:
  uv run python scripts/demo.py
  ```
- Automated non-interactive demonstration:
  ```bash
  make demo-auto
  # or directly:
  uv run python scripts/demo.py --auto
  ```
- ScaleDown typed decision mode:
  ```bash
  uv run python scripts/demo.py --auto --classifier scaledown
  ```

---

## 5-Minute Viva Defense Talk Track

### Introduction (30 seconds)
"RuntimeLens classifies runtime and orchestration threats in multi-tenant Kubernetes clusters. Traditional runtime tools like raw Falco generate excessive alerts because they lack workload context. RuntimeLens combines Falco system call telemetry, Hubble eBPF network flows, Prometheus container resource metrics, and pod specifications against declarative workload baselines. Deterministic policy gates enforce SRE safety guardrails, including zero pod deletion and automatic quarantine rollbacks."

### Step 1: Benign Web Traffic (45 seconds)
**Operator action:** Run step 1 in `scripts/demo.py`.

**Viva talk track:**
"In Scenario 1, an Nginx container in tenant-a starts a worker process. The Falco normalizer converts the raw event into a CanonicalEvent. RuntimeLens evaluates the event against the declarative baseline in baselines/web.yaml. The baseline allows nginx and specifies that shells are not permitted. Because the executed binary matches the allowed set and resource usage is nominal, zero drift is detected. The classifier assigns a benign class with severity 1.0. The policy engine evaluates this as safe and issues a log action. The decision is appended to a tamper-evident, hash-chained audit record with a genesis backlink."

**Expected output excerpt:**
```text
>>> Scenario 1: Benign Web Traffic (Routine Nginx Service)
1. Telemetry Ingest: Falco syscall execve from pod web-74b88dfd9b-w6tl9
   Command line: /usr/sbin/nginx -g daemon off;
2. Baseline Match: Workload 'web' profile loaded (3 allowed binaries)
   Drift detected: False (deviations: none)
3. Classification: Class='benign', Severity=1.0, Classifier='rules'
4. Policy Decision: [ACTION: LOG] Reason codes=['BENIGN_VERIFIED']
5. Tamper-Evident Audit: Record written to data/audit/demo_audit.jsonl
   Record Hash: fbae87589cd3f149... (Prev: 0000000000000000...)
```

### Step 2: Privilege Abuse (Unexpected Shell in Database) (45 seconds)
**Operator action:** Advance to step 2.

**Viva talk track:**
"In Scenario 2, an attacker spawns an interactive shell inside a tenant database container. The database baseline explicitly sets shell_allowed to false and restricts allowed binaries to redis-server, redis-cli, and busybox. The comparator flags two deviations: unexpected_shell_execution and unauthorized_binary:sh. The context-aware classifier identifies privilege abuse at severity 3.8. Because severity is below 4.0, the policy engine produces an alert rather than an automated containment action. Under our ScaleDown typed rubric model, where confidence is 0.64, the policy engine routes the incident to human review because confidence is below our 0.70 threshold."

**Expected output excerpt:**
```text
>>> Scenario 2: Privilege Abuse (Unexpected Shell in Database)
1. Telemetry Ingest: Falco syscall execve from pod database-9dfb5894b-4q2lm
   Command: /bin/sh by uid=0 (root)
2. Baseline Drift: Workload 'database' shell_allowed=False
   Deviations detected: ['unexpected_shell_execution', 'unauthorized_binary:sh']
3. Classification (Context-Aware Rules): Class='privilege_abuse', Severity=3.8
4. Policy Decision: [ACTION: ALERT] Reason codes=['THREAT_DETECTED'] (Dry-run: True)
5. Tamper-Evident Audit: Hash chain linked
```

### Step 3: Container Escape (Sensitive Host Mount) (45 seconds)
**Operator action:** Advance to step 3.

**Viva talk track:**
"Scenario 3 demonstrates deterministic SRE safety overrides. An attacker mounts a sensitive host path (/etc/kubernetes) into a tenant container. RuntimeLens inspects actual pod specifications during normalization. Even if an LLM or heuristic model produced an ambiguous result, our policy engine checks physical facts. The physical fact sensitive_host_path_mounted triggers the OVERRIDE_HOST_PATH_MOUNTED safety override. With severity 5.0 in an allowlisted tenant namespace, the policy engine issues a quarantine action. Following SRE principles, RuntimeLens never deletes pods. Instead, it proposes patching the label quarantine=true, triggering pre-installed Cilium network isolation with a 900-second automatic rollback TTL."

**Expected output excerpt:**
```text
>>> Scenario 3: Container Escape (Sensitive Host Path Mount)
1. Telemetry Ingest: Pod spec volume mount detection + Falco sensitive file open
   Host volume path: /etc/kubernetes
2. Physical Security Fact Detection: sensitive_host_path_mounted=True
3. Classification: Class='container_escape', Severity=5.0
4. Policy Decision & SRE Containment:
   Outcome: [ACTION: QUARANTINE] (Namespace: tenant-a)
   Reason codes: ['OVERRIDE_HOST_PATH_MOUNTED', 'HIGH_SEVERITY_CONTAINMENT']
   Containment labels: {'quarantine': 'true'}
   SRE Guardrails: Auto-rollback TTL=900s (15 min), Zero delete verbs
5. Tamper-Evident Audit: Hash chain linked
```

### Step 4: Cryptomining Egress (Correlated Signals) (45 seconds)
**Operator action:** Advance to step 4.

**Viva talk track:**
"Scenario 4 highlights cross-source correlation. Single-source detection is often noisy. Here, Prometheus cAdvisor reports 850 millicores of CPU consumption against a 50 millicore baseline envelope, exceeding our 3x anomaly threshold. Simultaneously, Hubble eBPF flow capture reveals outbound TCP traffic to an external mining pool on port 3333. Neither metric alone proves cryptomining, but correlated together against the workload baseline, the classifier identifies cryptomining at severity 4.0. The policy engine issues quarantine isolation."

**Expected output excerpt:**
```text
>>> Scenario 4: Cryptomining Egress (Prometheus + Hubble Flow)
1. Telemetry Ingest [Prometheus]: CPU usage=850.0 mcores (Baseline envelope: 50.0 mcores, >=3x abnormal=True)
   Telemetry Ingest [Hubble]: Flow to 198.51.100.24:3333 (Outbound egress=True, Verdict=FORWARDED)
2. Multi-Signal Correlated Drift: Abnormal compute + unauthorized external egress detected
   Baseline deviations: ['unauthorized_binary:xmrig', 'unauthorized_external_egress', 'cpu_envelope_exceeded']
3. Classification: Class='cryptomining', Severity=4.0, Classifier='rules'
4. Policy Decision: [ACTION: QUARANTINE] Reason codes=['HIGH_SEVERITY_CONTAINMENT']
5. Tamper-Evident Audit: Hash chain linked
```

### Step 5: Cryptographic Audit Verification (30 seconds)
**Operator action:** Advance to step 5.

**Viva talk track:**
"Finally, Step 5 verifies the cryptographic integrity of all decisions made during the run. Every AuditRecord includes the SHA-256 digest of the previous record, starting from a 64-character zero genesis hash. RuntimeLens recalculates the hash of every record and confirms the chain is unbroken. If an adversary or compromised operator modifies any byte in the audit log, chain verification fails instantly."

**Expected output excerpt:**
```text
>>> Step 5: Tamper-Evident SHA-256 Audit Chain Verification
Audit Log File: data/audit/demo_audit.jsonl (9899 bytes, 4 decision records)

Record Verification Sequence:
  [1] Workload: web        | Class: benign           | Action: log          | Prev: 00000000... -> Hash: fbae8758...
  [2] Workload: database   | Class: privilege_abuse  | Action: alert        | Prev: fbae8758... -> Hash: 73ebdd08...
  [3] Workload: web-escape | Class: container_escape | Action: quarantine   | Prev: 73ebdd08... -> Hash: b72bc5c5...
  [4] Workload: api        | Class: cryptomining     | Action: quarantine   | Prev: b72bc5c5... -> Hash: 71496e54...

[PASS] Cryptographic integrity verified: All 4 records strictly hash-chained back to Genesis (SHA-256).
```

---

## Reviewer & Examiner FAQs

### 1. Why not just use Falco default rules without RuntimeLens?
Default Falco rules lack workload context. For example, Falco flags any shell spawned in a container or sensitive file read, generating high false positive rates in workloads where administrative or developer utilities run. RuntimeLens uses declarative baselines to distinguish expected activity from anomalous drift. In our paired experiments, baseline context reduced the false positive rate on benign activity while maintaining high recall on true threats.

### 2. Why does RuntimeLens use label-based quarantine instead of deleting pods?
In Site Reliability Engineering, an automated false positive that deletes a production service causes an availability outage. Pod deletion also destroys forensic evidence in container memory. RuntimeLens applies `quarantine: "true"` labels matching pre-installed NetworkPolicies. This cuts ingress and egress traffic immediately while preserving container state for forensic analysis. A 900-second automatic rollback TTL restores connectivity if an operator does not confirm containment.

### 3. What happens if telemetry is delayed or the classifier goes offline?
RuntimeLens implements strict fail-safe defaults. If telemetry health reports missing sources, or if the model call times out, the policy engine forces an action of `human_review` with reason code `ERR_TELEMETRY_DEGRADED` or `ERR_MODEL_DEGRADED`. Automated quarantine is never permitted on degraded telemetry.

### 4. What prevents prompt injection if untrusted inputs reach the classifier?
RuntimeLens sanitizes untrusted process arguments before serialization. It strips known prompt injection keywords and caps command argument length at 128 characters. Critical security decisions like host runtime socket mounts rely on deterministic pod-spec facts that override model outputs directly.

### 5. Why is dry-run the default mode in the policy engine?
Containment operations carry operational risk. RuntimeLens sets `dry_run: true` on every PolicyDecision by default. Live mutation requires an explicit operator flag and allowlisted tenant namespaces (`tenant-a`, `tenant-b`, `tenant-c`). System namespaces like `kube-system` and `falco` are strictly forbidden from quarantine actions.

### 6. Can an attacker alter past audit records to hide their actions?
No. Every audit record contains `prev_record_hash`. Modifying an earlier record changes its SHA-256 hash, which invalidates all subsequent hashes in the chain. Verification via `AuditWriter.verify_chain()` scans from genesis and detects tampering at the exact index of modification.

---

## Emergency Contingency Runbook

### If running offline without cluster access:
`scripts/demo.py` is self-contained. It uses local declarative baseline files in `baselines/` and normalizes raw telemetry structures in memory. It does not require a live Kind cluster or internet connectivity to execute.

### If running with ScaleDown when the API key is unavailable:
The ScaleDown adapter defaults to local recorded fixtures (`tests/fixtures/scaledown/live_smoke_responses.json`). Passing `--classifier scaledown` uses these offline fixtures without external network requests or spend.

### Quick Verification Check:
Before presenting, run:
```bash
make lint
make typecheck
make test
uv run python scripts/demo.py --auto
```
Confirm all exit codes are 0.
