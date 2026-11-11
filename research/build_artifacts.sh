#!/usr/bin/env bash
# Rebuild every presentation artefact from measured artefacts.
#
# Usage:
#   bash research/build_artifacts.sh            # figures + deck + paper
#   bash research/build_artifacts.sh --analyse  # also recompute live statistics
#
# Assumes the live experiment has already been run (research/results/*.jsonl).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--analyse" ]]; then
  echo "==> recomputing live statistics"
  uv run python -m research.analyse_live_results
fi

echo "==> rendering figures"
uv run python research/figures/make_figures.py

echo "==> building deck"
node research/deck/build_deck.js

echo "==> rendering deck PDF"
/Applications/LibreOffice.app/Contents/MacOS/soffice --headless \
  --convert-to pdf --outdir docs/presentation \
  docs/presentation/RuntimeLens_presentation.pptx >/dev/null

echo "==> injecting live results into the paper"
uv run python -m research.inject_paper_results || true

echo "==> compiling paper"
( cd docs/paper && tectonic runtimelens_paper.tex >/dev/null )

echo
echo "artifacts:"
ls -la docs/presentation/RuntimeLens_presentation.pptx \
       docs/presentation/RuntimeLens_presentation.pdf \
       docs/paper/runtimelens_paper.pdf
