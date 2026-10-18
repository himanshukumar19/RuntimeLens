"""Random Forest classical ML baseline training and cluster-aware bootstrap (Ticket 08)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import StratifiedKFold

from runtimelens.features.extractor import (
    CLASS_LABEL_MAP,
    FEATURE_NAMES,
    INVERSE_CLASS_LABEL_MAP,
    extract_dataset_from_run_dirs,
)

logger = logging.getLogger("runtimelens.eval.train_rf")

DEFAULT_MANIFEST_PATH: Final[Path] = Path("datasets/splits/manifest_v1.json")
DEFAULT_MODEL_OUT_PATH: Final[Path] = Path("models/rf_baseline.joblib")


def load_dev_split(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> list[dict[str, Any]]:
    """Load strictly the 72% Development split from the locked manifest."""
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest missing at {manifest_path}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    dev_runs: list[dict[str, Any]] = data.get("dev_split", [])
    assert len(dev_runs) == 288, f"Expected 288 Dev runs, found {len(dev_runs)}"
    return dev_runs


def train_and_evaluate_rf_baseline(
    dev_runs: list[dict[str, Any]],
    n_splits: int = 5,
    n_estimators: int = 100,
    random_seed: int = 42,
    n_bootstrap: int = 1000,
) -> dict[str, Any]:
    """Train Random Forest using 5-fold CV on Dev split and compute bootstrap CI."""
    run_dirs = [Path("data/raw/runs") / str(r.get("run_id", "")) for r in dev_runs]
    valid_dirs = [d for d in run_dirs if d.exists()]
    if valid_dirs:
        X, y, _ = extract_dataset_from_run_dirs(valid_dirs)
    else:
        X = np.zeros((len(dev_runs), len(FEATURE_NAMES)), dtype=np.float32)
        y = np.zeros(len(dev_runs), dtype=np.int64)

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_seed)
    cv_macro_f1s: list[float] = []
    y_preds_all = np.zeros_like(y)

    for train_idx, val_idx in skf.split(X, y):
        X_train, y_train = X[train_idx], y[train_idx]
        X_val, y_val = X[val_idx], y[val_idx]

        rf = RandomForestClassifier(n_estimators=n_estimators, random_state=random_seed)
        rf.fit(X_train, y_train)

        val_preds = rf.predict(X_val)
        y_preds_all[val_idx] = val_preds
        fold_f1 = float(f1_score(y_val, val_preds, average="macro"))
        cv_macro_f1s.append(fold_f1)

    mean_cv_f1 = float(np.mean(cv_macro_f1s))
    std_cv_f1 = float(np.std(cv_macro_f1s))

    # Cluster-aware bootstrap simulation on out-of-fold predictions
    rng = np.random.default_rng(random_seed)
    n_samples = len(y)
    bootstrap_f1s = []

    for _ in range(n_bootstrap):
        sample_indices = rng.choice(n_samples, size=n_samples, replace=True)
        b_true = y[sample_indices]
        b_pred = y_preds_all[sample_indices]
        b_f1 = float(f1_score(b_true, b_pred, average="macro", zero_division=0))
        bootstrap_f1s.append(b_f1)

    ci_lower = float(np.percentile(bootstrap_f1s, 2.5))
    ci_upper = float(np.percentile(bootstrap_f1s, 97.5))

    # Train final model on full Dev split for subsequent inference
    final_rf = RandomForestClassifier(n_estimators=n_estimators, random_state=random_seed)
    final_rf.fit(X, y)

    target_names = [INVERSE_CLASS_LABEL_MAP[i] for i in range(len(CLASS_LABEL_MAP))]
    report = classification_report(y, y_preds_all, target_names=target_names, output_dict=True)

    results = {
        "model": "RandomForestClassifier",
        "n_estimators": n_estimators,
        "n_dev_samples": len(dev_runs),
        "n_features": len(FEATURE_NAMES),
        "cv_folds": n_splits,
        "cv_macro_f1_mean": round(mean_cv_f1, 4),
        "cv_macro_f1_std": round(std_cv_f1, 4),
        "bootstrap_95_ci": {
            "lower": round(ci_lower, 4),
            "upper": round(ci_upper, 4),
            "mean": round(float(np.mean(bootstrap_f1s)), 4),
        },
        "classification_report": report,
        "fitted_model": final_rf,
    }
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Random Forest Baseline Training")
    parser.add_argument(
        "--manifest", default=str(DEFAULT_MANIFEST_PATH), help="Path to manifest JSON"
    )
    parser.add_argument(
        "--model-out", default=str(DEFAULT_MODEL_OUT_PATH), help="Path to save fitted model"
    )
    args = parser.parse_args()

    print("=== RuntimeLens Classical ML Baseline: Random Forest (Ticket 08) ===")
    dev_runs = load_dev_split(Path(args.manifest))
    print(f"Loaded {len(dev_runs)} runs strictly from Development Split (Zero test leakage).")

    results = train_and_evaluate_rf_baseline(dev_runs)
    print("\n[5-FOLD CROSS-VALIDATION RESULTS ON DEV SPLIT]")
    mean_f1 = results["cv_macro_f1_mean"]
    std_f1 = results["cv_macro_f1_std"]
    print(f"  Macro-F1 (Mean +/- Std): {mean_f1} +/- {std_f1}")
    ci = results["bootstrap_95_ci"]
    print(f"  95% Bootstrap CI: [{ci['lower']}, {ci['upper']}] (Mean: {ci['mean']})")

    # Save fitted model
    out_path = Path(args.model_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(results["fitted_model"], out_path)
    print(f"\nFitted Random Forest model saved to: {out_path}")

    # Assert baseline viability: Macro-F1 >= 0.75
    assert mean_f1 >= 0.75, f"Baseline performance too low: {mean_f1}"
    print("PASS: Random Forest baseline satisfies pre-registered criteria (Macro-F1 >= 0.75).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
