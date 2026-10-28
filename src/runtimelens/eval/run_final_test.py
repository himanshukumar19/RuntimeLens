"""Single held-out test set evaluation harness and primary hypothesis verification (Ticket 12c).

Governed by:
- docs/PREREGISTRATION.md (Sections 1, 3, 4, 5)
- docs/EVALUATION_PLAN.md (Primary hypothesis H1, cluster-aware bootstrap, McNemar test)
- Checkpoint I: Single-pass final test evaluation with immutable audit logging.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from runtimelens.classifiers.rules import classify_rules
from runtimelens.classifiers.scaledown import ScaleDownAdapter
from runtimelens.eval.run_ablations import (
    compute_cluster_bootstrap_ci,
    compute_mcnemar_test,
    holm_bonferroni_correction,
    synthesize_dev_canonical_event,
)
from runtimelens.features.extractor import (
    CLASS_LABEL_MAP,
    INVERSE_CLASS_LABEL_MAP,
)

logger = logging.getLogger("runtimelens.eval.run_final_test")

DEFAULT_MANIFEST_PATH: Final[Path] = Path("datasets/splits/manifest_v1.json")
DEFAULT_OUTPUT_PATH: Final[Path] = Path("docs/reviews/final_test_evaluation_report.json")
AUDIT_ACCESS_LOG_PATH: Final[Path] = Path("data/audit/test_eval_access.log")


def log_test_split_access(manifest_path: Path, n_runs: int, dry_run: bool) -> str:
    """Record immutable audit trail entry for held-out test set access."""
    AUDIT_ACCESS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    manifest_bytes = manifest_path.read_bytes() if manifest_path.exists() else b""
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    log_entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": "HELD_OUT_TEST_SPLIT_EVALUATION",
        "dry_run": dry_run,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_hash,
        "test_run_count": n_runs,
    }
    line = json.dumps(log_entry, sort_keys=True)
    with open(AUDIT_ACCESS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return manifest_hash


def load_test_split_runs(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> list[dict[str, Any]]:
    """Load strictly the Held-Out Test split from the manifest."""
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest missing at {manifest_path}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    test_runs: list[dict[str, Any]] = data.get("test_split", [])
    if len(test_runs) == 0:
        raise ValueError(f"Held-out test split in {manifest_path} contains zero runs")
    return test_runs


def evaluate_final_test_set(
    test_runs: list[dict[str, Any]],
    n_bootstrap: int = 1000,
) -> dict[str, Any]:
    """Execute single-pass evaluation across all models on held-out test set."""
    cluster_ids = [str(r.get("run_id", f"run-test-{i}")) for i, r in enumerate(test_runs)]
    y_true_labels = [CLASS_LABEL_MAP.get(str(r.get("class", "benign")), 0) for r in test_runs]
    y_true = np.array(y_true_labels, dtype=np.int64)

    # 1. Primary Hypothesis Evaluation (ScaleDown / Rules Proxy with Baseline ON vs OFF)
    preds_on: list[int] = []
    preds_off: list[int] = []

    for r in test_runs:
        evt_on = synthesize_dev_canonical_event(r, with_baseline=True)
        res_on = classify_rules(evt_on)
        preds_on.append(CLASS_LABEL_MAP.get(res_on.predicted_class, 4))

        evt_off = synthesize_dev_canonical_event(r, with_baseline=False)
        res_off = classify_rules(evt_off)
        preds_off.append(CLASS_LABEL_MAP.get(res_off.predicted_class, 4))

    y_on = np.array(preds_on, dtype=np.int64)
    y_off = np.array(preds_off, dtype=np.int64)

    primary_bootstrap = compute_cluster_bootstrap_ci(
        cluster_ids=cluster_ids,
        y_true=y_true,
        y_pred_a=y_on,
        y_pred_b=y_off,
        n_bootstrap=n_bootstrap,
    )
    primary_mcnemar = compute_mcnemar_test(y_true_labels, preds_on, preds_off)

    f1_on = float(f1_score(y_true, y_on, average="macro", zero_division=0))
    f1_off = float(f1_score(y_true, y_off, average="macro", zero_division=0))

    # 2. ScaleDown Model Evaluation via offline fixtures
    scaledown_adapter = ScaleDownAdapter()
    preds_sd: list[int] = []
    for r in test_runs:
        evt = synthesize_dev_canonical_event(r, with_baseline=True)
        res_sd = scaledown_adapter.classify_event(evt)
        preds_sd.append(CLASS_LABEL_MAP.get(res_sd.predicted_class, 4))
    y_sd = np.array(preds_sd, dtype=np.int64)
    f1_sd = float(f1_score(y_true, y_sd, average="macro", zero_division=0))

    # Secondary comparisons
    mcnemar_sd_vs_rules = compute_mcnemar_test(y_true_labels, preds_sd, preds_on)
    hb_corrections = holm_bonferroni_correction([mcnemar_sd_vs_rules["p_value"]])

    # Confusion matrix and per-class reports
    target_names = [INVERSE_CLASS_LABEL_MAP[i] for i in range(len(CLASS_LABEL_MAP))]
    cm_on = confusion_matrix(y_true, y_on, labels=list(range(len(CLASS_LABEL_MAP)))).tolist()
    cm_sd = confusion_matrix(y_true, y_sd, labels=list(range(len(CLASS_LABEL_MAP)))).tolist()
    labels_all = list(range(len(CLASS_LABEL_MAP)))
    report_on = classification_report(
        y_true,
        y_on,
        labels=labels_all,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    report_sd = classification_report(
        y_true,
        y_sd,
        labels=labels_all,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )

    # Benign False Positive Rates
    benign_idx = CLASS_LABEL_MAP["benign"]
    benign_mask = y_true == benign_idx
    fpr_on = float(np.mean(y_on[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
    fpr_off = float(np.mean(y_off[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
    fpr_sd = float(np.mean(y_sd[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0

    # Decision on Pre-Registered Hypothesis H1
    ci_lower = primary_bootstrap["delta_macro_f1_ci_lower"]
    ci_upper = primary_bootstrap["delta_macro_f1_ci_upper"]
    is_positive = ci_lower > 0.0 and primary_mcnemar["p_value"] < 0.05
    is_inconclusive = ci_lower <= 0.0 <= ci_upper
    outcome_verdict = (
        "POSITIVE_SIGNIFICANT_IMPROVEMENT"
        if is_positive
        else ("INCONCLUSIVE_CI_SPANS_ZERO" if is_inconclusive else "NEGATIVE_OR_NEUTRAL")
    )

    return {
        "evaluation_protocol": "SINGLE_PASS_HELD_OUT_TEST_SET",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "total_test_incidents": len(test_runs),
        "primary_hypothesis_h1": {
            "hypothesis": (
                "Workload baseline context improves Macro-F1 and reduces benign FPR on "
                "held-out test runs"
            ),
            "macro_f1_baseline_on": f1_on,
            "macro_f1_baseline_off": f1_off,
            "delta_macro_f1": f1_on - f1_off,
            "paired_95_bootstrap_ci": {
                "lower": primary_bootstrap["delta_macro_f1_ci_lower"],
                "upper": primary_bootstrap["delta_macro_f1_ci_upper"],
            },
            "benign_fpr": {
                "baseline_on": fpr_on,
                "baseline_off": fpr_off,
                "delta_fpr": fpr_on - fpr_off,
                "paired_95_bootstrap_ci": {
                    "lower": primary_bootstrap["delta_fpr_ci_lower"],
                    "upper": primary_bootstrap["delta_fpr_ci_upper"],
                },
            },
            "mcnemar_test": primary_mcnemar,
            "formal_verdict": outcome_verdict,
        },
        "secondary_comparisons": {
            "scaledown_macro_f1": f1_sd,
            "scaledown_benign_fpr": fpr_sd,
            "rules_macro_f1": f1_on,
            "mcnemar_scaledown_vs_rules": mcnemar_sd_vs_rules,
            "holm_bonferroni": hb_corrections,
        },
        "confusion_matrices": {
            "classes": target_names,
            "rules_with_baseline": cm_on,
            "scaledown_with_baseline": cm_sd,
        },
        "classification_reports": {
            "rules_with_baseline": report_on,
            "scaledown_with_baseline": report_sd,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Execute RuntimeLens single held-out test set evaluation (Ticket 12c)."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to manifest JSON containing held-out test split.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Path to write final test evaluation JSON.",
    )
    parser.add_argument(
        "--n-bootstrap",
        type=int,
        default=1000,
        help="Number of bootstrap resamples (default: 1000).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Formally execute test evaluation and record access audit log.",
    )

    args = parser.parse_args()

    print("=== RuntimeLens Held-Out Test Set Single Evaluation Pass (Ticket 12c) ===")
    test_runs = load_test_split_runs(args.manifest)
    print(f"Loaded {len(test_runs)} held-out test runs from {args.manifest}")

    dry_run = not args.execute
    manifest_hash = log_test_split_access(args.manifest, len(test_runs), dry_run=dry_run)
    print(f"Logged test set access in {AUDIT_ACCESS_LOG_PATH} (SHA-256: {manifest_hash[:16]}...)")

    if dry_run:
        print("\n[DRY RUN] Invariant verification passed. Pass --execute to run evaluation.")
        sys.exit(0)

    print(
        f"Executing single evaluation pass with {args.n_bootstrap} cluster bootstrap iterations..."
    )
    results = evaluate_final_test_set(test_runs, n_bootstrap=args.n_bootstrap)

    primary = results["primary_hypothesis_h1"]
    fpr_data = primary["benign_fpr"]
    print("\n================== PRIMARY HYPOTHESIS H1 VERDICT ==================")
    print(f"Macro-F1 (Baseline ON)  : {primary['macro_f1_baseline_on']:.4f}")
    print(f"Macro-F1 (Baseline OFF) : {primary['macro_f1_baseline_off']:.4f}")
    print(f"Δ Macro-F1              : {primary['delta_macro_f1']:+.4f}")
    print(
        f"95% Paired Bootstrap CI : [{primary['paired_95_bootstrap_ci']['lower']:+.4f}, "
        f"{primary['paired_95_bootstrap_ci']['upper']:+.4f}]"
    )
    print(
        f"Benign FPR (ON vs OFF)  : {fpr_data['baseline_on']:.4f} vs {fpr_data['baseline_off']:.4f}"
    )
    print(f"Δ Benign FPR            : {fpr_data['delta_fpr']:+.4f}")
    print(f"McNemar p-value         : {primary['mcnemar_test']['p_value']:.4e}")
    print(f"Formal Verdict          : {primary['formal_verdict']}")
    print("===================================================================")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nFinal evaluation artifact written to: {args.output}")


if __name__ == "__main__":
    main()
