# Review — Course deliverables (deck, paper, PPT index)

Ticket: ad-hoc course deliverable work (no RuntimeLens ticket ID). Date: 2026-11-12.

## 1. Diff review
- Scope: `research/` (evaluation harness, figures, deck builders), `docs/paper/` (IEEE paper + PDF), `docs/presentation/` (light deck + renders), `PROJECT_FOR_PPT.md`, `ppt_assets/`, `final_presentation.pptx/.pdf`, build config (`Makefile`, `pyproject.toml`, `uv.lock` — research extra).
- No behavioural change under `src/`. No debug artifacts; no TODOs added.
- `research/deck/make_backgrounds.py`, `research/inject_paper_results.py` reformatted/lint-cleaned (ruff F401/E501) — no logic change.
- Large binaries committed (~9 MB total): PPTX/PDF decks, figure PNGs, JPEG renders. Accepted deliberately for a course artefact repo.

## 2. Secrets & privacy
- `.env` ignored (`.gitignore:2`), never opened, never staged.
- `uv run python scripts/check_secrets.py $(git ls-files --others --exclude-standard) Makefile pyproject.toml` → exit 0.
- Regex scan for key-like tokens (x-api-key, sk-, gsk_, api_key literals) across all new files → no matches.
- `college_logo.jpeg` (IIIT Dharwad logo, user-provided attachment) — public institutional asset, moved into `research/deck/assets/`.
- `research/results/*` contain model outputs only; `data/raw/runs/` stays untracked (gitignored).

## 3. Safety verification
- No cluster, VM, or live API invocation in this work. No kubectl, no network calls.
- Terminal panels in the deck are labelled "Output trimmed"; figures plot recorded artifacts only (`make_figures.py` cites sources in docstrings).
- No deletes, no outside-namespace actions.

## 4. Tests
- `uv run pytest tests/unit tests/contract tests/integration` → **282 passed in 11.61s** (2026-11-12)
- `uv run ruff check .` → All checks passed
- `uv run ruff format --check .` → 112 files formatted
- `validate.py final_presentation.pptx` → All validations PASSED
- Deck re-rendered (LibreOffice → pdftoppm) and all 17 slides inspected visually; defects fixed (dark table text, chart negative axis, terminal line wraps, dead space).

## 5. Correctness & robustness
- Every number in `PROJECT_FOR_PPT.md` and both decks cites a source file. Known data conflicts documented (not silently resolved): `ablation_study_results.json` secondary block (scaledown 0.0520, rules 0.5333) vs published 0.5333 headline; 1.2 s vs ±30 s correlation window; SHA-256 vs HMAC-SHA256 audit chain; 7,879.6 (hash-chained) vs 12,847.1 ev/s (in-memory).
- NOT FOUND items marked explicitly (SLOs, error budget, CD, at-rest encryption, pen test, ScaleDown token-compression feature).

## 6. Docs & consistency
- Consistent with `docs/DECISIONS.md` (D-00…D-28), `docs/EVALUATION_PLAN.md`, `docs/PREREGISTRATION.md`. `PROJECT_FOR_PPT.md` §16 / MISSING INFORMATION carry the discrepancies.

## 7. Honesty
- Lab positive (+0.0201 ΔMacro-F1) and live null both reported. ASR 30%→0.0% full stack. No invented metrics; 402-credit ScaleDown limitation disclosed.

## 8. Unfixed issues (with severity)
- MEDIUM: ablation artifact vs headline contradiction unresolved (owner decision needed).
- LOW: LibreOffice QA preview substitutes Calibri metrics; PowerPoint render may differ ±1 line.
- LOW: exhibit screenshots from lab (01–05) reflect VM state at capture time; not re-executed this session.

## 9. Risks
- Binary bloat in git history (~9 MB). No push performed; remote untouched.
- `final_presentation.pptx` validated by schema checker only, not by PowerPoint itself.
