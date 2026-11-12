# Review — IEEE paper (title, author block, figures, bolding)

Ticket: ad-hoc course deliverable work (no RuntimeLens ticket ID). Date: 2026-11-12.
Preceded by: `docs/reviews/course-deck-1.md` … `course-deck-3.md`.
Scope note: the presentation (`final_presentation.pptx/.pdf`) was explicitly left untouched
by the requester for this round; only the IEEE paper was changed.

## 1. Diff review
- `docs/paper/runtimelens_paper.tex` — author block, bold title, font setup, landscape Fig. 1, targeted bolding.
- `docs/paper/runtimelens_paper.pdf` + `.log` — rebuilt output.
- `docs/paper/figures/pipeline_lr.mermaid` + `.pdf` — new landscape pipeline figure (vector).
- `docs/paper/README.md`, `scripts/build_paper.sh` — build instructions and script.
- No change to `src/`, `docs/report/`, `research/`, or the deck.

## 2. Author block (requirement 1, 3, 4)
- Replaced `Himanshu Kumar, Altaf Raja, and Kamal Nayan Kumar` + department + "Corresponding author"
  with the institute template: one row of members with roll numbers beneath
  (Kamal Nayan Kumar 23BDS026 · Altaf Raja 23BCS011 · Himanshu Kumar 23BCS055),
  then `Indian Institute of Information Technology, Dharwad, India`, then `Instructor: Dr. Malay Kumar`.
- Department line removed as requested. Verified in the rendered PDF, page 1.

## 3. Title and bolding (requirement 2, 4)
- `\title{\bfseries ...}` — the title now renders bold (verified in the PDF).
- Root cause found for why bold previously did not appear anywhere: IEEEtran selects the URW
  Times family (`ptm`), which has no bold/italic shapes under the TU (XeTeX) encoding
  (`LaTeX Font Warning: Font shape TU/ptm/b/n undefined` — 7 occurrences in the old log).
  The preamble now selects TeX Gyre Termes/Heros/Cursor by file name, so real bold and italic
  render. The old log line 19-38 warnings come from class load and are harmless.
- Key numbers and claims bolded: abstract headline metrics, the three contributions, the
  safety invariants ("zero pod-deletion privileges", "the model never adjudicates them",
  "quarantine is reversible by construction"), the primary-hypothesis result, the
  inconclusive live replication, and the best values in Table II.

## 4. Figures (requirement 5)
- Root cause of the overlap: the old Fig. 1 used the vertical `architecture.pdf`
  (233 × 356 pt) scaled to `\columnwidth`, so its lower stages ran into the caption block
  (visible as a clipped "Audit: append-only JSONL" box on page 2 of the old PDF).
- Fix: new landscape `pipeline_lr.pdf` (912 × 314 pt, vector, mermaid source committed) placed
  as a full-width `figure*` at `0.94\textwidth`. All seven stages are visible; nothing overlaps.
- The vertical architecture PDF/PNG is kept for the poster and is no longer referenced by the paper.

## 5. Verification (requirement 6)
- `tectonic -X compile` → clean build, 5 pages, letter size.
- Log checks: 0 `Overfull` boxes, 0 undefined references/citations, no LaTeX errors.
- All 5 pages rendered at 95 dpi and inspected visually: title, author block, abstract,
  all five figures, three tables, and the two-column references — no overlap, no clipping,
  no overflow, consistent typography.

## 6. Secrets & privacy
- No credentials in the changed files; the paper references the environment variable name
  only (`SCALEDOWN_API_KEY`), never a value. `check_secrets.py` clean.

## 7. Safety
- No cluster, VM, network, or API access; document work only.

## 8. Honesty
- No numbers changed. All figures and tables carry the same measured values as before
  (0.5333 / 0.5133 / +0.0201 [+0.0132, +0.0275] / 3.6% / 18.4% / 94.7% / ASR 30%→0% /
  live replication inconclusive).

## 9. Unfixed / carried forward
- The known artifact conflict (rules vs typed-decision arm in
  `docs/reviews/ablation_study_results.json` vs the headline table) remains flagged inside the
  paper's own limitations paragraph; it is not silently reconciled.
- The class-load `TU/ptm` font warnings (7) remain in the log; they come from IEEEtran
  initialisation and do not affect the output.
