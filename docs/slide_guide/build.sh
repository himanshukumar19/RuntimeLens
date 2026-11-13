#!/usr/bin/env bash
# Build the RuntimeLens slide guide PDF.
#   markdown (slide_guide.md) -> pandoc -> styled HTML -> Playwright/Chromium -> PDF
# Two passes: the first render is used to read the real page number of every
# slide band, which is then written into the "Slide index" table.
# Usage: bash docs/slide_guide/build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PANDOC_MD="${1:-slide_guide.md}"
PW_PATH="/Users/nayan/.npm/_npx/e41f203b7505f1fb/node_modules:${NODE_PATH:-}"

echo "==> pandoc: $PANDOC_MD -> slide_guide.html"
pandoc "$PANDOC_MD" \
  --from markdown+fenced_divs+pipe_tables+raw_tex \
  --to html5 \
  --standalone \
  --toc --toc-depth=1 \
  --metadata title="RuntimeLens — Slide-by-Slide Guide" \
  --css style.css \
  --embed-resources \
  -o slide_guide.html

echo "==> injecting box labels + slide-index placeholder"
python3 - <<'PY'
import re
from pathlib import Path

p = Path("slide_guide.html")
html = p.read_text()

LABELS = {
    "termsbox": "Terms used here",
    "caveat": "Honest caveat",
    "qabox": "If they ask",
    "plainbox": "",
}

def zerobox_label(m):
    body = m.group(1)
    probe = body.lstrip()
    mm = re.match(r"<p><strong>(\d+)\.\s*(.*?)</strong>(.*?)</p>", probe, flags=re.S)
    if not mm:
        return f'<div class="zerobox"><span class="box-label">Zero</span>{body}</div>'
    num, head, rest = mm.group(1), mm.group(2), mm.group(3)
    new_body = f"<p><strong>{head}</strong>{rest}</p>" + probe[mm.end():]
    return (f'<div class="zerobox"><span class="box-label">Zero {num}</span>'
            f"{new_body}</div>")

html = re.sub(r'<div class="zerobox">(.*?)</div>', zerobox_label, html, flags=re.S)

def add_label(m):
    cls, body = m.group(1), m.group(2)
    label = LABELS.get(cls, "")
    if not label:
        return m.group(0)
    return f'<div class="{cls}"><span class="box-label">{label}</span>{body}</div>'

html = re.sub(r'<div class="(termsbox|caveat|qabox|plainbox)">(.*?)</div>', add_label, html, flags=re.S)

# slide index placeholder, inserted right after the TOC block
if "<!--SLIDE_INDEX-->" not in html:
    html = html.replace("</nav>", "</nav>\n<!--SLIDE_INDEX-->", 1)

p.write_text(html)
print("labels injected")
PY

echo "==> pass 1: render PDF (for page numbers)"
NODE_PATH="$PW_PATH" node print_pdf.js >/dev/null

echo "==> computing slide index page numbers"
python3 - <<'PY'
import re, subprocess
from pathlib import Path

html = Path("slide_guide.html").read_text()
slides = re.findall(r'<div class="slidehead">\s*<p><strong>(Slide (\d+)[^<]*)</strong>', html)

text = subprocess.run(["pdftotext", "-layout", "RuntimeLens_slide_guide.pdf", "-"],
                       capture_output=True, text=True).stdout
pages = text.split("\f")

def norm(t):
    return re.sub(r"\s+", " ", t.replace("\u2014", "-").replace("\u2013", "-")).strip()

def page_of(title):
    needle = norm(title)
    short = needle.split(" - ", 1)[1] if " - " in needle else needle
    for i, page in enumerate(pages, 1):
        flat = norm(page)
        if needle in flat or short in flat:
            return i
    return None

rows = []
for full, num in slides:
    title = full.split("—", 1)[1].strip() if "—" in full else full
    pg = page_of(full)
    rows.append((num, title, pg))

tbl = ['<div id="slide-index"><h2>Slide index</h2><table>',
       "<tr><th>Slide</th><th>Title</th><th>Page</th></tr>"]
for num, title, pg in rows:
    tbl.append(f"<tr><td>{num}</td><td>{title}</td><td>{pg if pg else '—'}</td></tr>")
tbl.append("</table></div>")
index_html = "\n".join(tbl)

html = html.replace("<!--SLIDE_INDEX-->", index_html)
Path("slide_guide.html").write_text(html)
print(f"index built with {len(rows)} slides")
PY

echo "==> pass 2: final render"
NODE_PATH="$PW_PATH" node print_pdf.js

echo "==> done"
ls -la RuntimeLens_slide_guide.pdf
