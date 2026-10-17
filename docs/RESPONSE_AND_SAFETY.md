# RESPONSE POLICY & SRE SAFETY SPECIFICATION

## 1. SRE Perspective on Automated Security Response
In Site Reliability Engineering (SRE), security response is treated as an availability problem:
- **A false positive that terminates an essential payment pod is an availability outage.**
- Containment must be **predictable, least-disruptive, reversible, and auditable**.
- The model provides probabilistic evidence; deterministic code enforces policy.

## 2. Policy Function & Precedence Rules
The policy engine is implemented as a pure, versioned function:
```python
def evaluate_policy(
    classification: ClassificationResult,
    facts: ExtractedFacts,
    telemetry_health: TelemetryHealth,
    baseline_status: BaselineStatus,
) -> PolicyDecision:
    ...
```

### Precedence Hierarchy (Highest to Lowest)
1. **Critical Safety Overrides:**
   - If `facts.host_runtime_socket_mounted` or `facts.sensitive_host_path_mounted` is True $\rightarrow$ Action is immediately upgraded to at least `alert + human_review`, even if model outputs `benign`.
   - If `telemetry_health.is_telemetry_degraded` is True $\rightarrow$ Action routes to `human_review` with reason code `ERR_TELEMETRY_DEGRADED`.
   - If `classification.degraded_mode` is True (API timeout / failure) $\rightarrow$ Action routes to `human_review` with reason code `ERR_MODEL_DEGRADED`.
   - If `baseline_status.is_baseline_stale` is True and classification is non-benign $\rightarrow$ Action routes to `human_review`.
2. **Choice-Noul Conflict Matrix:**
   - Table-driven verification of consistency between discrete Choice class and binary Noul flags.
   - Any detected contradiction immediately overrides automated action and routes to `human_review`.
3. **Calibrated Confidence & Severity Gating:**
   - Evaluates numeric severity (1–5) and model confidence against calibrated dev-set thresholds.

## 3. Table-Driven Choice-Noul Conflict Resolution

| Predicted Class | Corroborating Noul Flags (Expected $> 0.5$) | Contradicting Condition (Forces `human_review`) |
|:---|:---|:---|
| `benign` | None (expected $\le 0.5$ across all flags) | `baseline_deviation > 0.6` OR `resource_exposure > 0.6` |
| `container_escape` | `resource_exposure`, `shell_unexpected` | `resource_exposure < 0.3` AND `shell_unexpected < 0.3` |
| `privilege_abuse` | `baseline_deviation`, `resource_exposure` | `baseline_deviation < 0.3` |
| `cryptomining` | `resource_abuse`, `baseline_deviation` | `resource_abuse < 0.3` |
| `unknown` | Any | Routes to `human_review` unconditionally |

## 4. Response Action Tiers & Threshold Matrix

| Action | Condition | Guardrails & SRE Checks |
|:---|:---|:---|
| **`log`** | `class == benign` AND `confidence >= 0.70` AND zero contradictions. | Written to tamper-evident audit log; zero cluster change. |
| **`alert` (Low Priority)** | Threat class with Severity $< 3.0$, or degraded model fallback. | Rate-limited webhook/JSONL; alerts grouped by `incident_id`. |
| **`human_review`** | `class == unknown` OR `confidence < 0.70` OR contradiction detected OR degraded telemetry. | Enqueued to persistent review JSONL; zero workload disruption. |
| **`quarantine`** | Severity $\ge 4.0$ AND `confidence >= 0.70` AND corroborating Noul flags AND allowlisted namespace. | **Dry-Run default.** In live mode: label patched (`quarantine=true`), TTL rollback timer started (default 15m). |
| **`terminate`** | **Not implemented; design and future work only.** | **Zero pod delete permissions exist in RBAC, controller code, or manifests.** |

## 5. Label-Based Quarantine Mechanics & Auto-Rollback

### 5.1 Pre-Installed Isolation NetworkPolicy
Rather than dynamically generating CRDs or policies during an incident, each tenant namespace features a pre-installed `NetworkPolicy`:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-quarantined-pods
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
    - Ingress
    - Egress
  egress:
    - to:
      - namespaceSelector: {}
        podSelector:
          matchLabels:
            k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```
- **Execution:** The response controller merely patches metadata: `kubectl patch pod <pod> -p '{"metadata":{"labels":{"quarantine":"true"}}}'`.
- **Cilium Connection Handling:** Cilium immediately applies eBPF drop filters to new connections and terminates active TCP sessions for pods carrying the quarantine selector.

### 5.2 Automatic Rollback (TTL Mechanism)
- Containment actions record an `action_id`, target `pod_uid`, original labels, and an expiration timestamp (default: +15 minutes).
- An asynchronous reconciliation loop inspects quarantined pods. If an analyst has not explicitly promoted or resolved the incident before TTL expiry, the controller removes the `quarantine` label, restoring normal connectivity.

## 6. Least-Privilege RBAC Design (Zero Delete)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: runtimelens-response-controller
  namespace: runtimelens
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: runtimelens-pod-isolator
  namespace: tenant-a
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "patch"] # STRICTLY NO DELETE PERMISSION ANYWHERE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: runtimelens-pod-isolator-binding
  namespace: tenant-a
subjects:
  - kind: ServiceAccount
    name: runtimelens-response-controller
    namespace: runtimelens
roleRef:
  kind: Role
  name: runtimelens-pod-isolator
  apiGroup: rbac.authorization.k8s.io
```

### RBAC Negative Permission Verification
Automated test asserts in CI and Phase 1:
```bash
kubectl auth can-i delete pods --as=system:serviceaccount:runtimelens:runtimelens-response-controller -n tenant-a
# MUST return: "no"
```
