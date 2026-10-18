# Code Review: Ticket 09b (Telemetry Normalizers & Capture Audit)

**Diff Range:** `main` $\rightarrow$ `ahead/09b`
**Review Type:** Dual-Axis Code Review (`@code-review`)

---

## Standards
- **Typing & Linting:** All functions in `hubble.py`, `prometheus.py`, `trivy.py`, and `audit_capture.py` are strictly typed and formatted via `ruff`.
- **Fault-Tolerant Parsing:** Normalizers safely handle optional sub-dictionaries (`flow.get("IP", {})`, `flow.get("l4", {})`) without throwing `KeyError` on sparse records.
- **Smell Baseline Audit:**
  - *Feature Envy:* Avoided; each normalizer processes only its corresponding telemetry source.
  - *Duplicated Code:* Minimal; each source parses a distinct schema (Hubble vs Prometheus vs Trivy).

## Spec
- **Deliverables Adherence:** Implements 100% of Ticket 09b code deliverables:
  - Hubble flow normalizer populating `NetworkContext` and network facts.
  - Prometheus normalizer computing `cpu_usage_mcores` and relative anomaly.
  - Trivy normalizer populating `has_critical_vulnerability` and CVE list.
  - Verification script `audit_capture.py` passing against live raw sample data.
- **Scope Creep:** None observed.

## Summary
- **Standards:** 0 findings (Clean).
- **Spec:** 0 findings (100% compliant with Ticket 09b specification).
- **Status:** APPROVED / CLEAN.
