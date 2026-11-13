# Review — Slide guide PDF + deck wording correction

Ticket: ad-hoc course deliverable work (no RuntimeLens ticket ID). Date: 2026-11-12.
Preceded by: `docs/reviews/course-deck-1.md`, `course-deck-2.md`.

## 1. Diff review
- `docs/slide_guide/` — new: `slide_guide.md` (source), `style.css`, `build.sh`, `print_pdf.js`, `README.md`, `.gitignore`, and the rendered `RuntimeLens_slide_guide.pdf` (18 pages, A4).
- `research/deck/build_final.js` + rebuilt `final_presentation.pptx/.pdf` — two wording corrections on slide 13:
  - "Live A/B … FPR halved" → "benign FPR −27.3 pp (p=0.084, n.s.)" — the deck previously overstated the effect; the measured value is −0.2727 with p = 0.0840 (`research/results/live_analysis.md`).
  - "0.0% ASR … all four tiers" → "from 30.0% raw (lab) · live tier-3 0.0%" — the four-tier zero is a lab-fixture result; on the live `gpt-oss-20b` arm tier 2 was 5.0% (`research/results/adversarial_aggregate.json`).
- No `src/` changes; no behaviour changes; no new runtime dependencies (pandoc + Playwright/Chromium already present).

## 2. Secrets & privacy
- No credentials, keys, or tokens in any new file; `check_secrets.py` pattern unchanged.
- The guide quotes only file paths, metric names and measured values. No private data, no credentials of any kind.

## 3. Safety verification
- No cluster, VM, network, or API access. Document build only (local pandoc + headless Chromium on local HTML).

## 4. Tests / checks run
- `bash docs/slide_guide/build.sh` → 18-page PDF, two-pass build (pass 1 reads real page numbers for the slide index).
- `pdfinfo RuntimeLens_slide_guide.pdf` → A4, 18 pages.
- `pdftotext -layout` → slide index resolves all 17 slides to page numbers (no "—" left).
- All 18 rendered pages inspected visually at 100 dpi: boxes, tables, page breaks, footer.
- Deck: `validate.py final_presentation.pptx` → PASSED; slide 13 re-rendered and inspected.

## 5. Correctness & robustness
- Every zero in the deck was traced to a source file before being described (Appendix A of the guide): benchmark errors (`data/benchmarks/latest.json`), ASR (`research/results/adversarial_aggregate.json`, `docs/report/final_report.md` §8), RBAC verbs (`lab/rbac/response-controller-rbac.yaml`), leakage gate (`docs/report/final_report.md` §7.4), live call failures (`research/results/live_analysis.md`).
- Each zero states what it proves *and* what it does not prove (e.g. live tier-2 ASR was 5.0%; "0 failed calls" ≠ "0 mistakes").
- Known repo conflicts carried forward unchanged and flagged in the guide: ablation artefact vs headline, 1.2 s vs ±30 s window, SHA-256 vs HMAC-SHA256, 7,879.6 vs 12,847.1 ev/s.

## 6. Docs & consistency
- Guide cross-references the same sources as `PROJECT_FOR_PPT.md`; no new claims introduced.
- `docs/slide_guide/README.md` documents the rebuild path and the content rules.

## 7. Honesty
- The guide repeats the deck's honest positions (modest +0.0201, live null kept, lab-only, SLOs not defined, no token-compression feature) and adds the two corrections above.

## 8. Unfixed issues
- MEDIUM (carried): ablation artefact contradicts the published 0.5333 headline — needs an owner decision.
- LOW: the guide PDF is rendered by Chromium, so pagination differs slightly from a LaTeX build; rebuilding may shift page numbers by ±1 (the build script recomputes the index automatically).

## 9. Risks
- Build requires Playwright's Chromium at a pinned npx path in `build.sh` (`/Users/nayan/.npm/_npx/e41f203b7505f1fb/node_modules`); on another machine the path must be adjusted or `NODE_PATH` set.
