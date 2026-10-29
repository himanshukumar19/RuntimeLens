# Dataset Anti-Leakage and Baseline Verification

Dataset Anti-Leakage and Baseline Verification ensures empirical integrity in RuntimeLens experiments. It audits run directories and feature datasets to verify that ground truth threat classes, scenario IDs, and run IDs never contaminate feature vectors or canonical events consumed by the classifiers.

## Sub-features

- `audit-feature-leakage` asserts that the 19 extracted feature vectors contain zero ground-truth labels or run IDs.
- `audit-grouped-splits` checks that train/dev/test splits group strictly by `run_id` without cross-split overlap.
- `audit-telemetry-completeness` verifies that runs contain the required 5 telemetry sources (Falco, Audit, Hubble, Prometheus, Trivy).
- `audit-baseline-deviations` confirms that baseline deviation flags correctly reflect discrepancies against workload profiles.

## How to get to it (user POV)

- Run `uv run python scripts/control_runtimelens.py audit-dataset --runs-dir <dir>`.
- Run `uv run python scripts/verify_dataset.py --runs-dir <dir>`.
- Run unit tests via `uv run pytest tests/unit/test_leakage.py tests/unit/test_verify_dataset_cpu_band.py`.

## Driving it with control-runtimelens

Preconditions:
- Python environment synced via `uv sync --extra dev`.
- Dataset directory or run artifacts available.

- **Run feature leakage verification test.**
  ```bash
  uv run pytest tests/unit/test_leakage.py -v
  ```
  Expected output: all tests pass confirming manifest split disjointness and absence of test run references in baselines.
- **Run dataset audit script.**
  ```bash
  uv run python scripts/control_runtimelens.py audit-dataset --runs-dir data/raw/runs
  ```
  Expected output: per-run telemetry audit verifying absence of class leak tokens in facts, features, and event payloads.

## Gotchas

- Feature vectors must strictly have 19 dimensions derived solely from operational signals, never from metadata.
- Synthetic datasets from prior invalid iterations (such as `data/invalid_v0/`) are quarantined and intentionally fail verification checks.
- Test split access is governed by manifest hash locks; tampering with split manifests invalidates the benchmark.
- In `scripts/verify_dataset.py`, pass the directory via `--runs-dir <path>`, not as a positional argument.
