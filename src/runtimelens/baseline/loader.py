"""Declarative YAML baseline loader with staleness tracking (Decision D-08, Ticket 05)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import yaml

from runtimelens.baseline.models import WorkloadBaseline

logger = logging.getLogger("runtimelens.baseline.loader")

DEFAULT_BASELINES_DIR = Path("baselines")
STALENESS_THRESHOLD_DAYS = 30


class BaselineStore:
    """Read-only store for declarative Git-versioned workload baselines.

    Zero auto-learning: Baselines are strictly declarative and immutable at runtime.
    """

    def __init__(self, baselines_dir: Path = DEFAULT_BASELINES_DIR) -> None:
        self.baselines_dir = baselines_dir
        self._cache: dict[str, WorkloadBaseline] = {}
        self.load_all()

    def load_all(self) -> None:
        """Load all YAML baseline profiles from the baselines directory."""
        if not self.baselines_dir.exists():
            logger.warning("Baselines directory %s does not exist", self.baselines_dir)
            return

        for yaml_file in self.baselines_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                baseline = WorkloadBaseline.model_validate(data)
                self._cache[baseline.metadata.workload] = baseline
                logger.info("Loaded baseline profile for workload: %s", baseline.metadata.workload)
            except Exception as e:
                logger.error("Failed to load baseline from %s: %e", yaml_file, e)

    def get_baseline(self, workload_name: str) -> WorkloadBaseline | None:
        """Retrieve the declarative baseline for a workload."""
        return self._cache.get(workload_name)

    def is_stale(self, baseline: WorkloadBaseline) -> bool:
        """Check if a baseline exceeds the 30-day revalidation window."""
        try:
            created = datetime.fromisoformat(baseline.metadata.created_at.replace("Z", "+00:00"))
            age_days = (datetime.now(UTC) - created).days
            return age_days > STALENESS_THRESHOLD_DAYS
        except Exception:
            return False
