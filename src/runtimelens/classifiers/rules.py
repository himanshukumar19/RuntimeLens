"""Deterministic rule-based baseline classifiers (Decision D-14, D-19).

Implements three distinct rule evaluation baselines:
1. classify_rules_default (Baseline A): Evaluates ONLY pinned default Falco rules
   via exact name matching, with ZERO baseline context and ZERO pod-spec-derived facts.
2. classify_rules_default_plus_lab (Baseline A+): Evaluates default rules PLUS custom lab rules,
   without baseline context.
3. classify_rules_context (Baseline B): Hand-written context-aware rules that explicitly evaluate
   workload baseline profiles and pod-spec facts.

Heuristic Severity Numbers (Documented engineering heuristics):
- 5.0: Critical confirmed escape (host runtime socket mount, hostPath traversal).
- 4.0: High cryptomining (multi-signal compute + network egress).
- 3.8: High privilege abuse (unexpected interactive shell execution in non-debug container).
- 3.5: Medium-high suspicious binary execution (execution from /dev/shm, dropped binary).
- 3.2: Medium privilege abuse (catch-all for unexpected baseline deviations: unauthorized binaries).
- 3.0: Standard default Falco alert without baseline context.
- 2.0: Low suspicious reconnaissance (isolated /etc/shadow read in unprivileged container).
- 1.0: Informational benign baseline operation.

Rule confidence is set to None (Not Applicable) to ensure deterministic heuristic outputs
are not evaluated as calibrated statistical posterior probabilities by downstream policy gates.
"""

from __future__ import annotations

from runtimelens.models.decision import ClassificationResult
from runtimelens.models.event import CanonicalEvent


def classify_rules_default(event: CanonicalEvent) -> ClassificationResult:
    """Baseline A: Maps ONLY pinned default Falco rules to classes with zero baseline context."""
    # 1. Telemetry degradation check: unknown is reachable when telemetry is impaired
    if event.health.is_telemetry_degraded or len(event.health.missing_sources) > 0:
        return ClassificationResult(
            predicted_class="unknown",
            severity=3.0,  # Documented heuristic severity for degraded state
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_v1",
        )

    rule_name = event.telemetry_source.source_rule_name or ""

    # 2. Pinned Falco default rules matched by exact equality (zero pod-spec facts):
    if rule_name in {
        "Detect release_agent File Container Escapes",
        "Debugfs Launched in Privileged Container",
        "Linux Kernel Module Injection Detected",
    }:
        return ClassificationResult(
            predicted_class="container_escape",
            severity=5.0,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_v1",
        )

    # Corroborating cryptomining loader signals from default Falco rules
    if rule_name in {
        "Execution from /dev/shm",
        "Drop and execute new binary in container",
    }:
        return ClassificationResult(
            predicted_class="cryptomining",
            severity=3.5,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_v1",
        )

    if rule_name in {
        "Terminal shell in container",
        "Read sensitive file untrusted",
        "Contact K8S API Server From Container",
        "Netcat Remote Code Execution in Container",
    }:
        is_high = rule_name in {
            "Terminal shell in container",
            "Netcat Remote Code Execution in Container",
        }
        severity_val = 3.8 if is_high else 3.0
        return ClassificationResult(
            predicted_class="privilege_abuse",
            severity=severity_val,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_v1",
        )

    return ClassificationResult(
        predicted_class="benign",
        severity=1.0,
        confidence=None,
        classifier_type="rules",
        model_version="rules_default_v1",
    )


def classify_rules_default_plus_lab(event: CanonicalEvent) -> ClassificationResult:
    """Baseline A+: Evaluates default rules PLUS custom lab rules without baseline context."""
    # 1. Telemetry degradation check
    if event.health.is_telemetry_degraded or len(event.health.missing_sources) > 0:
        return ClassificationResult(
            predicted_class="unknown",
            severity=3.0,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_plus_lab_v1",
        )

    rule_name = event.telemetry_source.source_rule_name or ""

    # Check custom lab rules first
    if rule_name == "Launch Sensitive Mount Container":
        return ClassificationResult(
            predicted_class="container_escape",
            severity=5.0,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_plus_lab_v1",
        )

    if rule_name == "Suspicious Mining Port Egress":
        return ClassificationResult(
            predicted_class="cryptomining",
            severity=4.0,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_plus_lab_v1",
        )

    if rule_name == "Interactive Shell Spawned in Non-Debug Container":
        return ClassificationResult(
            predicted_class="privilege_abuse",
            severity=3.8,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_plus_lab_v1",
        )

    if rule_name == "Read Sensitive Host Information Untrusted":
        return ClassificationResult(
            predicted_class="privilege_abuse",
            severity=3.0,
            confidence=None,
            classifier_type="rules",
            model_version="rules_default_plus_lab_v1",
        )

    # Fallback to default rules
    return classify_rules_default(event)


def classify_rules_context(event: CanonicalEvent) -> ClassificationResult:
    """Baseline B: Hand-written context-aware rules evaluating workload baseline profiles."""
    facts = event.facts
    baseline = event.baseline

    # Compute deterministic evidence flags
    evidence_flags: dict[str, float] = {
        "baseline_deviation": 1.0 if baseline.baseline_deviation_detected else 0.0,
        "shell_unexpected": (
            1.0 if (facts.is_shell_process and not baseline.shell_expected) else 0.0
        ),
        "resource_exposure": (
            1.0 if (facts.host_runtime_socket_mounted or facts.sensitive_host_path_mounted) else 0.0
        ),
        "resource_abuse": 1.0 if facts.is_cpu_abnormal else 0.0,
    }

    # 1. Telemetry degradation check: unknown when telemetry is impaired
    if event.health.is_telemetry_degraded or len(event.health.missing_sources) > 0:
        return ClassificationResult(
            predicted_class="unknown",
            severity=3.0,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    # 2. Verified Container Escape from actual pod spec
    if facts.host_runtime_socket_mounted or facts.sensitive_host_path_mounted:
        return ClassificationResult(
            predicted_class="container_escape",
            severity=5.0,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    # 3. Cryptomining multi-signal
    if facts.is_cpu_abnormal and facts.is_outbound_egress:
        return ClassificationResult(
            predicted_class="cryptomining",
            severity=4.0,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    # 4. Unauthorized shell spawn
    if facts.is_shell_process and not baseline.shell_expected:
        return ClassificationResult(
            predicted_class="privilege_abuse",
            severity=3.8,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    # 5. Multi-deviation catch-all: if identity file access is combined with another deviation,
    # or any other baseline deviation is detected, it is NOT classified benign!
    other_deviations = [d for d in baseline.deviations if d != "sensitive_identity_file_access"]
    if other_deviations or (
        baseline.baseline_deviation_detected
        and "sensitive_identity_file_access" not in baseline.deviations
    ):
        return ClassificationResult(
            predicted_class="privilege_abuse",
            severity=3.2,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    # 6. Isolated sensitive file read in unprivileged container (unconfirmed reconnaissance)
    if "sensitive_identity_file_access" in baseline.deviations:
        return ClassificationResult(
            predicted_class="benign",
            severity=2.0,
            confidence=None,
            evidence_flags=evidence_flags,
            classifier_type="rules",
            model_version="rules_context_v1",
        )

    return ClassificationResult(
        predicted_class="benign",
        severity=1.0,
        confidence=None,
        evidence_flags=evidence_flags,
        classifier_type="rules",
        model_version="rules_context_v1",
    )


# Alias for default vertical slice classifier
classify_rules = classify_rules_context
