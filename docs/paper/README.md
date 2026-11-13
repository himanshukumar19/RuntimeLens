# IEEE paper (RuntimeLens)

Conference-format source and build for the RuntimeLens paper.

| File | What it is |
|:--|:--|
| `runtimelens_paper.tex` | Source. `IEEEtran` conference mode, two columns, letter page, 5 pages. |
| `runtimelens_paper.pdf` | Compiled output (tectonic). |
| `figures/pipeline_lr.pdf` | Fig. 1 — pipeline diagram, rendered from `figures/pipeline_lr.mermaid` (mermaid, left-to-right, vector PDF). |
| `figures/pipeline_lr.mermaid` | Editable source for Fig. 1. |
| `figures/architecture.pdf` / `.png` | Poster-style vertical architecture diagram (kept for the poster, not used by the paper). |
| `make_architecture_figure.py` | Generator for the vertical architecture diagram. |

## Build

```bash
bash scripts/build_paper.sh
```

The script refreshes Fig. 1 from the mermaid source (needs `mmdc`) and compiles with
`tectonic`. Compile from this directory so `\graphicspath` resolves
`research/figures/` for the four chart PNGs (`fig_dataset`, `fig_model_comparison`,
`fig_live_ab`, `fig_asr`).

## Typesetting notes (why the preamble looks unusual)

- **Bold/italic are loaded explicitly.** IEEEtran selects the URW Times family
  (`ptm`), which has no bold or italic shapes in the TU encoding used by XeTeX —
  every `\textbf` silently rendered as regular text. The preamble selects the TeX
  Gyre Termes / Heros / Cursor clones by file name, which restores real bold and
  italic. Do not remove that block.
- **Fig. 1 is a full-width `figure*`.** The previous vertical architecture figure
  was scaled to the column width and its lower stages were clipped by the caption
  block, which is what produced the overlapping diagram. The landscape figure
  plus `\begin{figure*}[t]` keeps every stage visible.
- **Author block** follows the institute template: one row of members with roll
  numbers underneath, the college line, then the instructor line. The department
  is intentionally not listed.
