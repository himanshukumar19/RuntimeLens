# Presentation and paper

| File | What it is |
|---|---|
| `RuntimeLens_presentation.pptx` | The project deck (20 slides, 16:9). Light theme: "Cloud & Control". |
| `RuntimeLens_presentation.pdf` | Rendered PDF of the same deck. |
| `../paper/runtimelens_paper.tex` | IEEE conference-format paper (5 pages). |
| `../paper/runtimelens_paper.pdf` | Compiled paper (tectonic). |

## Deck structure

| # | Slide | Section |
|---|---|---|
| 1 | Title — RuntimeLens: teach the cluster to tell an attack from a bad day | — |
| 2 | Falco sees the syscall; it cannot read the room | Problem |
| 3 | Three things current tools cannot do | Problem |
| 4 | What others built, and where they stopped | Literature survey |
| 5 | Nobody does all five (capability matrix) | Literature survey |
| 6 | Give the classifier the job description; never let it push the button | Our solution |
| 7 | Five feeds in, one safe action out | Architecture |
| 8 | What it runs on (tech stack) | Architecture |
| 9 | One real incident, start to finish | Workflow |
| 10 | Six fixed questions, one shared answer sheet | Workflow |
| 11 | Does a decision model beat a rule? | Analysis |
| 12 | Which piece actually earns its keep? (ablations) | Analysis |
| 13 | We also ran it live against real APIs | Analysis |
| 14 | What the real ScaleDown API returns | Analysis |
| 15 | Can a hostile command line fool it? (defence ladder) | Analysis |
| 16 | Fast enough for a busy cluster | Analysis |
| 17 | What this project adds to the field | Contribution |
| 18 | What we will not claim at the viva | Limitations |
| 19 | Selected literature | References |
| 20 | Takeaways | Closing |

## Rebuilding

```bash
# charts from measured artefacts
uv run python research/figures/make_figures.py

# deck + PDF
node research/deck/build_deck.js
/Applications/LibreOffice.app/Contents/MacOS/soffice --headless \
    --convert-to pdf --outdir docs/presentation \
    docs/presentation/RuntimeLens_presentation.pptx

# paper
cd docs/paper && tectonic runtimelens_paper.tex
```

## Design system

- Layout 13.333 x 7.5 in (LAYOUT_WIDE).
- Light only. Background is a cool blue-white `EDF3FA`; cards are white `FFFFFF`
  and pale tints `F5F9FD`. The dominant accent is steel teal `0F5E8E`; supporting
  accent is bright sky `1B8FD6`. Status colors (`1F9D6B` green, `C97B12` amber,
  `C8433C` red) appear only where a decision is being shown.
- Type: Playfair Display for hero titles, Geist for everything else, Geist Mono
  for code and identifiers.
- Motif: icon-in-circle and a soft cloud glyph. No dark surfaces, no accent
  stripes.
- Writing: short sentences, plain words, no jargon without a one-line gloss.

## Sourcing rule

Every number on a slide comes from one of:

- `docs/GATE_REPORTS.md` and `docs/report/final_report.md` (lab corpus),
- `data/benchmarks/latest.json` (pipeline benchmark),
- `datasets/splits/manifest_v1.json` (400-run split),
- `research/results/*.json` and `*.jsonl` (live measured calls).

No slide contains a number that was not produced by one of those.
