# RISK MANAGEMENT REGISTER

## 1. Risk Matrix & Governance

| Risk ID | Description | Likelihood | Impact | Trigger Indicator | Preventive & Contingency Mitigation | Owner | Status |
|:---|:---|:---:|:---:|:---|:---|:---:|:---:|
| **RSK-01** | ARM64 eBPF compatibility issues with Falco/Cilium inside Ubuntu VM | Medium | High | Falco probe fails to load or kernel panics during Phase 1 | Use standard Ubuntu 24.04 kernel with BTF; Phase 1 Feasibility Gate switches to cloud Linux VM if local VM fails | Himanshu | OPEN |
| **RSK-02** | ScaleDown API rate limiting, credit exhaustion, or data privacy concerns | Medium | High | HTTP 429 or 402 returned during test runs | Hard request timeouts, exponential backoff, response caching by state hash; CI runs 100% offline with recorded fixtures. [SOURCE: ScaleDown operates Zero Data Retention (ZDR) and does not train on customer inputs] | Himanshu | OPEN |
| **RSK-03** | VM memory or disk exhaustion during 400 runs | Medium | Medium | Kubelet OOMKills, slow response times, disk space alert | Allocate 6–8 GB RAM, 40 GB disk; run scenarios in resumable batches (25–50) with `run_checkpoint.json`; automated teardown hook after each run; runner pauses if VM available memory <1.2 GB or aborts if free disk <5 GB | Himanshu | OPEN |
| **RSK-04** | Statistical power insufficient for minority attack classes | Low | High | Wide bootstrap CIs spanning zero across attack classes | Execute 20–30 run pilot to estimate empirical variance, power, and CI width via bootstrap simulation; calibrate minimum effect size post-pilot; designate claim exploratory if power <0.80 | Himanshu | OPEN |
| **RSK-05** | Information leakage between Dev and Held-Out Test sets | Low | Critical | Identical pod names or temporal timestamps in model inputs | Grouped split by `run_id` + variant; automated CI test asserts zero IDs/timestamps in features or state; frozen SHA-256 hash | Himanshu | OPEN |
| **RSK-06** | Prompt injection bypasses via attacker-controlled process args | Medium | Medium | Adversarial test suite flips attack scenario to `benign` | Defense-in-depth sanitization (128 char truncate, control char strip, tags); deterministic fact overrides strictly supersede model | Himanshu | OPEN |
| **RSK-07** | Automated quarantine causes cascading service disruption | Low | High | False-positive quarantine isolates critical payment service | Dry-run default; allowlisted lab namespaces only; pre-installed NetworkPolicy; automated TTL rollback reconciliation loop; zero pod delete permissions | Himanshu | OPEN |
| **RSK-08** | Academic report and poster revisions delayed | Medium | Medium | Deliverables lagging behind technical milestones | Stage 1 structural revisions executed immediately via checklist; teammates Altaf & Kamal dedicated to documentation deliverables | Altaf / Kamal | OPEN |
| **RSK-09** | Primary research claim yields negative result ($\Delta\text{Macro-F1} \le 0$) | Medium | Low | ScaleDown with baseline fails to outperform classical ML | Pre-registered criteria in `docs/PREREGISTRATION.md` treats negative results as valid academic contributions; full failure analysis and SRE cost/latency justification | Himanshu | OPEN |
| **RSK-10** | Model decode run-to-run non-determinism on continuous Score and select Noul flags | Medium | Medium | Identical requests yield variance in Score (observed 2.406 vs 2.361) and Noul probabilities, while Choice probabilities remain deterministic | Measure model run-to-run variance on a Dev subset; cache responses keyed by `SHA256(model_id + rubric_version + state_hash)`; incorporate empirical run-to-run variance into reported bootstrap uncertainty intervals | Himanshu | OPEN |

---

## 2. Go/No-Go Decision Criteria
- **Feasibility Gate (Phase 1):** If eBPF/BTF cannot be stabilized within 24 hours in the local VM, immediately execute fallback to a provisioned Ubuntu Cloud VM (Hetzner/AWS).
- **Model Gate (Phase 7):** If ScaleDown API is inaccessible or unresponsive during manual smoke test, verify fallback baselines operate in degraded mode and notify faculty guide.
- **Evaluation Gate (Phase 8):** If held-out test split hash does not match Git commit manifest, immediately halt evaluation run and investigate data contamination.
