# Slide guide (companion PDF)

Plain-English walkthrough of the 17-slide course presentation
(`final_presentation.pptx` / `final_presentation.pdf`).

| File | What it is |
|:--|:--|
| `slide_guide.md` | Source. Markdown with fenced divs for the boxes (`slidehead`, `termsbox`, `caveat`, `qabox`, `zerobox`). |
| `style.css` | Print stylesheet. Palette matches the deck (light blue `#E9EFF7` ground, `#0E7E9E` cyan accent, `#12263A` ink). |
| `build.sh` | Build: pandoc → HTML → Chromium print → PDF. Two passes, so the "Slide index" table carries real page numbers. |
| `print_pdf.js` | Playwright/Chromium print driver (A4, running headers/footers). |
| `RuntimeLens_slide_guide.pdf` | Output — 18 pages. |

## Rebuild

```bash
bash docs/slide_guide/build.sh
```

Requirements: `pandoc`, `node` with Playwright + Chromium (already present in this
environment). The build writes `slide_guide.html` (intermediate) and
`RuntimeLens_slide_guide.pdf`.

## Content rules for this document

- Every number must come from a file in the repository; the file path is printed next to it.
- Terms are explained in plain words at first use, then used directly.
- Anything the repository does not support is written as a limit, never as a claim.
- Appendix A traces every `0` in the deck: what it proves and what it does not.
