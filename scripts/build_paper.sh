#!/usr/bin/env bash
# Build the RuntimeLens IEEE paper.
#   LaTeX (IEEEtran) -> tectonic -> docs/paper/runtimelens_paper.pdf
#
# Figures:
#   figures/pipeline_lr.pdf        mermaid source: figures/pipeline_lr.mermaid
#   fig_*.png                      research/figures/ (see \graphicspath in the .tex)
#
# Usage: bash scripts/build_paper.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/docs/paper"

echo "==> regenerating the pipeline figure (mermaid -> pdf)"
if command -v mmdc >/dev/null 2>&1; then
  mmdc -i figures/pipeline_lr.mermaid -o figures/pipeline_lr.pdf -b white --size 1200 --scale 2 -q
  echo "    figures/pipeline_lr.pdf refreshed"
else
  echo "    mmdc not found — using the committed figures/pipeline_lr.pdf"
fi

echo "==> compiling with tectonic"
tectonic -X compile --keep-logs runtimelens_paper.tex

echo "==> done"
ls -la runtimelens_paper.pdf
