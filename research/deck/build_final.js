/* RuntimeLens — Cloud Security and SRE final course deck (17 slides, 16:9).
 * Content source of truth: PROJECT_FOR_PPT.md. No numbers invented here.
 * Theme: "Light Blue" — bg E9EFF7, card FFFFFF, border C9D6E5, cyan 0E7E9E.
 */
const pptxgen = require("pptxgenjs");
const path = require("path");
const fs = require("fs");

const ROOT = __dirname + "/../..";
const ASSETS = ROOT + "/ppt_assets";
const ICON = "/private/var/folders/xf/h6j_p9x14lb4nw22yl7xyth80000gn/T/opencode/dark_build/icons";
const OUT = ROOT + "/final_presentation.pptx";

const BG = "E9EFF7", CARD = "FFFFFF", LINE = "C9D6E5", TXT = "12263A", MUTED = "4E6076";
const CYAN = "0E7E9E", GREEN = "177E54", AMBER = "B45309", RED = "C8433C";
const TITLE_FONT = "Calibri", BODY = "Calibri", MONO = "Consolas";
const W = 13.333, H = 7.5, M = 0.6, CW = W - 2 * M;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "RuntimeLens team";
pres.title = "RuntimeLens — Cloud Security and SRE";

function iconPath(n) { return path.join(ICON, n + ".png"); }

function baseSlide() {
  const s = pres.addSlide();
  s.background = { color: BG };
  return s;
}

function footer(s, page) {
  s.addShape(pres.shapes.RECTANGLE, { x: M, y: 7.0, w: CW, h: 0.012, fill: { color: LINE }, line: { type: "none" } });
  s.addText("Cloud Security and SRE", { x: M, y: 7.08, w: 5.5, h: 0.32, fontFace: BODY, fontSize: 12, color: MUTED, align: "left", margin: 0, valign: "middle" });
  s.addText([{ text: "RuntimeLens", options: { color: MUTED } }, { text: `   ·   ${String(page).padStart(2, "0")} / 17`, options: { color: CYAN, bold: true } }], { x: W - M - 4, y: 7.08, w: 4, h: 0.32, fontFace: BODY, fontSize: 12, align: "right", margin: 0, valign: "middle" });
}

function contentSlide(title, page, notes) {
  const s = baseSlide();
  s.addShape(pres.shapes.RECTANGLE, { x: M, y: 0.52, w: 0.12, h: 0.56, fill: { color: CYAN }, line: { type: "none" } });
  s.addText(title, { x: 0.86, y: 0.44, w: CW - 0.26, h: 0.72, fontFace: TITLE_FONT, fontSize: 32, bold: true, color: TXT, align: "left", valign: "middle", margin: 0 });
  if (notes) s.addNotes(notes);
  footer(s, page);
  return s;
}

function card(s, x, y, w, h, opts = {}) {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.075, fill: { color: CARD }, line: { color: LINE, width: 1 }, shadow: { type: "outer", color: "000000", opacity: 0.16, blur: 8, angle: 90, offset: 2 }, ...(opts.shape || {}) });
}

function chip(s, text, x, y, w, color = CYAN, opts = {}) {
  s.addText(text, { x, y, w, h: 0.34, fontFace: BODY, fontSize: opts.fontSize || 12.5, bold: true, color, align: "center", valign: "middle", margin: 0, fill: { color: opts.fill || "DDE7F2" }, line: { color: LINE, width: 0.75 }, shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.17 });
}

function terminal(s, { x, y, w, h, title, lines, rowH = 0.34, fontSize = 12.5 }) {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.075, fill: { color: "0B1220" }, line: { color: "22304A", width: 1 }, shadow: { type: "outer", color: "12263A", opacity: 0.28, blur: 10, angle: 90, offset: 3 } });
  [["F87171", 0], ["F59E0B", 1], ["34D399", 2]].forEach(([c, i]) => s.addShape(pres.shapes.OVAL, { x: x + 0.22 + i * 0.26, y: y + 0.21, w: 0.14, h: 0.14, fill: { color: c }, line: { type: "none" } }));
  s.addText(title, { x: x + 1.1, y: y + 0.1, w: w - 1.3, h: 0.32, fontFace: MONO, fontSize: 12, color: "8A97AB", align: "center", valign: "middle", margin: 0 });
  s.addShape(pres.shapes.RECTANGLE, { x: x + 0.2, y: y + 0.53, w: w - 0.4, h: 0.012, fill: { color: "22304A" }, line: { type: "none" } });
  lines.forEach((ln, i) => s.addText(ln.map(([t, c]) => ({ text: t, options: { color: c } })), { x: x + 0.26, y: y + 0.63 + i * rowH, w: w - 0.52, h: rowH, fontFace: MONO, fontSize, margin: 0, valign: "middle", align: "left" }));
}

const CY = (s, n, x, y, size) => s.addImage({ path: iconPath(n), x, y, w: size, h: size });
function heading(s, text, x, y, w, opts = {}) {
  s.addText(text, { x, y, w, h: opts.h || 0.4, fontFace: TITLE_FONT, fontSize: opts.size || 19, bold: true, color: TXT, margin: 0, valign: "middle", align: opts.align || "left" });
}
function body(s, items, x, y, w, h, opts = {}) {
  const arr = items.map((t, i) => ({ text: t, options: { bullet: { code: "2022", indent: 12 }, color: opts.color || "22384F", breakLine: true } }));
  s.addText(arr, { x, y, w, h, fontFace: BODY, fontSize: opts.fontSize || 15.5, align: "left", valign: "top", margin: 0, lineSpacingMultiple: 1.15, paraSpaceAfter: 6 });
}
function caption(s, text, x, y, w, opts = {}) {
  s.addText(text, { x, y, w, h: opts.h || 0.3, fontFace: BODY, fontSize: opts.fontSize || 13, color: MUTED, align: opts.align || "left", valign: "top", margin: 0, lineSpacingMultiple: 1.12 });
}

function tableStyle() {
  return { fontFace: BODY, fontSize: 13.5, color: TXT, border: [{ type: "solid", color: LINE, pt: 1 }, { type: "solid", color: LINE, pt: 1 }, { type: "solid", color: LINE, pt: 1 }, { type: "solid", color: LINE, pt: 1 }], margin: [6, 10, 6, 10], valign: "middle" };
}
const headCell = (t, opts = {}) => ({ text: t, options: { bold: true, color: CYAN, fontSize: 14, fill: { color: "DDE7F2" }, ...opts } });

/* ============ SLIDE 1 — COVER ============ */
{
  const s = baseSlide();
  s.addShape(pres.shapes.OVAL, { x: 9.7, y: 4.45, w: 5.6, h: 5.6, fill: { color: CYAN, transparency: 90 }, line: { type: "none" } });
  s.addShape(pres.shapes.OVAL, { x: 10.9, y: 5.6, w: 3.2, h: 3.2, fill: { color: CYAN, transparency: 88 }, line: { type: "none" } });
  s.addText("CLOUD SECURITY AND SRE   ·   IIIT DHARWAD", { x: M, y: 0.72, w: 7.4, h: 0.35, fontFace: MONO, fontSize: 13, color: CYAN, charSpacing: 2.5, margin: 0 });
  s.addImage({ path: __dirname + "/assets/college_logo.jpeg", x: 8.28, y: 0.62, w: 4.45, h: 0.75 });
  s.addText("RuntimeLens", { x: M, y: 1.12, w: 12.1, h: 1.15, fontFace: TITLE_FONT, fontSize: 66, bold: true, color: TXT, margin: 0, valign: "middle" });
  s.addShape(pres.shapes.RECTANGLE, { x: M, y: 2.34, w: 3.05, h: 0.025, fill: { color: CYAN }, line: { type: "none" } });
  s.addText("Context-aware runtime and orchestration threat classification for multi-tenant Kubernetes, using a typed-decision model.", { x: M, y: 2.5, w: 9.6, h: 0.95, fontFace: BODY, fontSize: 18, color: "22384F", margin: 0, lineSpacingMultiple: 1.15, valign: "top" });
  s.addText("“Runtime detection that knows what your workload is supposed to do.”", { x: M, y: 3.42, w: 10.5, h: 0.4, fontFace: BODY, fontSize: 15.5, italic: true, color: CYAN, margin: 0 });
  card(s, M, 4.12, 6.1, 2.35);
  heading(s, "Team Members", M + 0.28, 4.38, 5.6, { size: 22, h: 0.42 });
  s.addShape(pres.shapes.RECTANGLE, { x: M + 0.28, y: 4.92, w: 1.05, h: 0.03, fill: { color: CYAN }, line: { type: "none" } });
  s.addText([
    { text: "Himanshu Kumar  23BCS055", options: { bold: true, color: TXT, breakLine: true, paraSpaceAfter: 10 } },
    { text: "Altaf Raja  23BCS011", options: { bold: true, color: TXT, breakLine: true, paraSpaceAfter: 10 } },
    { text: "Kamal Nayan Kumar  23BDS026", options: { bold: true, color: TXT } },
  ], { x: M + 0.28, y: 5.06, w: 5.6, h: 1.3, fontFace: BODY, fontSize: 16.5, margin: 0, lineSpacingMultiple: 1.15, valign: "top" });
  card(s, 7.0, 4.12, 5.73, 2.35);
  heading(s, "COURSE", 7.28, 4.28, 5.2, { size: 12.5, h: 0.28 });
  s.addText([
    { text: "Cloud Security and SRE", options: { bold: true, color: TXT, breakLine: true, paraSpaceAfter: 8 } },
    { text: "Instructor:  Dr. Malay Kumar", options: { color: "22384F" } },
  ], { x: 7.28, y: 4.66, w: 5.2, h: 1.6, fontFace: BODY, fontSize: 15, margin: 0, lineSpacingMultiple: 1.15, valign: "top" });
  s.addNotes("Open with the one-liner: RuntimeLens classifies runtime threats by comparing telemetry against what each workload is supposed to do. Introduce the team and instructor, then the agenda: problem, why it is new, how it works, and the measured results. Everything in this deck is from our repo — numbers carry file paths.");
}

/* ============ SLIDE 2 — PROBLEM ============ */
{
  const s = contentSlide("Rules see syscalls. They can’t see intent.", 2, "One bold sentence: rule engines judge each event alone. Then walk the three impact cards left to right: alert fatigue (numbers from our benchmark of Falco as the baseline), blind multi-step attacks, and the shared-kernel blast radius. Close with the strip: without context, routine looks hostile, so real attacks get ignored.");
  s.addText("Falco-style tools judge each event alone — no workload context, so real attacks blend in and noise wins.", { x: M, y: 1.28, w: CW, h: 0.45, fontFace: BODY, fontSize: 18, bold: true, color: TXT, margin: 0, valign: "middle" });
  const y = 1.92, h = 3.1, w = 3.91, gap = (CW - 3 * w) / 2;
  const cards = [
    { icon: "bell", title: "Alert fatigue", lines: ["Falco: Macro-F1 0.333", "Benign FPR 18.4%", "Containment precision 54.2%"], src: "report §7.3" },
    { icon: "eye", title: "Blind to multi-step", lines: ["Escape + token theft + egress", "each looks benign alone —", "rules cannot chain them"], src: "GCID, 2026 — our motivation" },
    { icon: "network", title: "One kernel, many tenants", lines: ["Shared kernel + control plane", "one compromised tenant", "spreads laterally"], src: "THREAT_MODEL §1 (Jarkas ’25)" },
  ];
  cards.forEach((c, i) => {
    const x = M + i * (w + gap);
    card(s, x, y, w, h);
    CY(s, c.icon, x + 0.3, y + 0.3, 0.5);
    heading(s, c.title, x + 0.3, y + 0.92, w - 0.6, { size: 21, h: 0.4 });
    body(s, c.lines, x + 0.3, y + 1.36, w - 0.6, 1.15, { fontSize: 15.5 });
    caption(s, c.src, x + 0.3, y + h - 0.38, w - 0.6, { fontSize: 11.5 });
  });
  s.addText([{ text: "Without context → ", options: { color: MUTED } }, { text: "every maintenance shell looks hostile, so the real one gets ignored.", options: { color: RED, bold: true } }], { x: M, y: 5.3, w: CW, h: 0.4, fontFace: BODY, fontSize: 16.5, margin: 0, valign: "middle" });
}

/* ============ SLIDE 3 — OBJECTIVES & SCOPE ============ */
{
  const s = contentSlide("Five goals. One pre-registered question.", 3, "Left card is the spine of the project: a pre-registered, paired baseline ON/OFF comparison, locked before we touched the test split. Right grid: the four supporting goals. Below the line, explicitly what we did not build — say it out loud before the examiner asks.");
  const y = 1.32, leftW = 5.5, rightX = M + leftW + 0.35, rightW = CW - leftW - 0.35;
  card(s, M, y, leftW, 3.62);
  CY(s, "clipboard", M + 0.3, y + 0.3, 0.5);
  heading(s, "1 · Pre-registered hypothesis", M + 0.3, y + 0.9, leftW - 0.6, { size: 20.5 });
  body(s, [
    "H₁: baseline context changes Macro-F1 and/or benign FPR",
    "Paired ON/OFF comparison, same incidents",
    "Locked 2026-10-17 — before test split access",
    "Both outcomes reported as measured",
  ], M + 0.3, y + 1.32, leftW - 0.6, 2.1, { fontSize: 15.5 });
  const cells = [
    { n: "2", icon: "layers", t: "Five-source fusion", d: "Falco + audit + Hubble + metrics + Trivy → one state" },
    { n: "3", icon: "shield", t: "SRE-safe response", d: "Zero pod-delete RBAC · dry-run · 900 s TTL auto-rollback" },
    { n: "4", icon: "activity", t: "Honest measurement", d: "Cluster bootstrap CIs · McNemar · 4-tier ASR · Holm correction" },
    { n: "5", icon: "file", t: "Reproducible delivery", d: "84-run corpus · 282 passing tests · report, paper, demo" },
  ];
  const cw = (rightW - 0.3) / 2, ch = 1.66;
  cells.forEach((c, i) => {
    const x = rightX + (i % 2) * (cw + 0.3), cy = y + Math.floor(i / 2) * (ch + 0.3);
    card(s, x, cy, cw, ch);
    CY(s, c.icon, x + 0.22, cy + 0.2, 0.4);
    heading(s, `${c.n} · ${c.t}`, x + 0.22, cy + 0.66, cw - 0.44, { size: 16.5, h: 0.3 });
    body(s, [c.d], x + 0.22, cy + 0.96, cw - 0.44, 0.66, { fontSize: 12, color: "3A5068" });
  });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y: 5.18, w: CW, h: 0.78, rectRadius: 0.08, fill: { color: "FFF6DE" }, line: { color: AMBER, width: 1, dashType: "dash" } });
  heading(s, "NOT IN SCOPE", M + 0.28, 5.24, 2.1, { size: 12, h: 0.24, });
  s.addText("Pod termination (design-only)  ·  production rollout  ·  ScaleDown token compression (does not exist)  ·  formal SLOs  ·  non-dry-run quarantine", { x: M + 0.28, y: 5.5, w: CW - 0.56, h: 0.35, fontFace: BODY, fontSize: 14.5, color: "8F5A06", margin: 0, valign: "middle" });
}

/* ============ SLIDE 4 — LITERATURE ============ */
{
  const s = contentSlide("The field — and the gap we fill", 4, "Five rows only, the closest work. For each: what it does and the limitation it leaves. The pattern: taxonomy without a defense loop, kernel policy without context, audit context without fusion, honeypots without audit — and the contamination attack that motivates our sanitizer. Full bibliography is on the last reference slide.");
  const bodyCell = (t, j, i) => ({ text: t, options: { fontFace: BODY, fontSize: 14, color: j === 2 ? "8F5A06" : TXT, fill: { color: i % 2 ? CARD : "F3F7FC" }, margin: [8, 12, 8, 12], valign: "middle", border: { type: "solid", color: LINE, pt: 1 } } });
  const rows = [
    [headCell("Paper / tool"), headCell("What it does"), headCell("Gap it leaves")],
    ["Jarkas et al. · ACM CSUR 2025", "5-layer container threat taxonomy (our model)", "Taxonomy only — no runtime defense loop"],
    ["Galletta · arXiv 2026", "Stateful in-kernel eBPF security policies", "Kernel policy — no workload context"],
    ["Franzil et al. · Comp. Networks 2026", "Sharpens K8s audit logs with context", "Audit stream only — no 5-source fusion"],
    ["Chen et al. · Shadowkube · 2025", "Learned baseline + honeypots, closest precedent", "No typed decision · no hash-chained audit"],
    ["Karanjai et al. · arXiv 2026", "Context contamination in LLM log analysis", "Attack, not a defense — motivates our sanitizer"],
  ].map((r, i) => i === 0 ? r : r.map((c, j) => bodyCell(c, j, i)));
  s.addTable(rows, { x: M, y: 1.34, w: CW, colW: [3.6, 4.6, 3.93], rowH: [0.5, 0.86, 0.86, 0.86, 0.86, 0.86], border: { type: "solid", color: LINE, pt: 1 } });
  caption(s, "22-reference bibliography in PROJECT_FOR_PPT.md §19  ·  taxonomy in THREAT_MODEL §1  ·  DOIs verified against paper source", M, 6.62, CW, { fontSize: 12.5 });
}

/* ============ SLIDE 5 — EXISTING VS OURS ============ */
{
  const s = contentSlide("Same telemetry. Different outcome.", 5, "Three rows — rules, classical ML, and LLM agents — same limitation column. Read the color code aloud: red is the before, green is after us. Bottom line: we did not replace their wins, we closed the loop around them.");
  const rows = [
    [headCell("Existing approach"), headCell("Limitation"), headCell("RuntimeLens")],
    [{ text: "Falco default rules", options: {} }, { text: "Macro-F1 0.333 · FPR 18.4%", options: { color: RED, bold: true } }, { text: "Macro-F1 0.533 · FPR 3.6%", options: { color: GREEN, bold: true } }],
    [{ text: "Random Forest on K8s logs", options: {} }, { text: "0.481 dev F1 · heavy feature engineering", options: { color: RED } }, { text: "Kept as an arm · typed decision on top", options: { color: GREEN } }],
    [{ text: "LLM triage / SOC agents", options: {} }, { text: "Injection-prone · no safe actuation", options: { color: RED } }, { text: "4-tier defense · ASR 30% → 0.0% · engine final", options: { color: GREEN } }],
  ];
  s.addTable(rows.map((r, i) => i === 0 ? r : r.map((c) => ({ ...c, options: { fontFace: BODY, fontSize: 15, color: TXT, fill: { color: i % 2 ? "F3F7FC" : CARD }, margin: [10, 14, 10, 14], valign: "middle", border: { type: "solid", color: LINE, pt: 1 }, ...(c.options || {}) } }))), { x: M, y: 1.34, w: CW, colW: [3.35, 4.35, 4.43], rowH: [0.5, 1.15, 1.15, 1.15] });
  caption(s, "Macro-F1 / FPR from docs/report/final_report.md §7.3  ·  ASR from research/results/adversarial_aggregate.md  ·  identical dev budget (ABL design)", M, 5.85, CW, { fontSize: 12.5 });
}

/* ============ SLIDE 6 — NOVELTY ============ */
{
  const s = contentSlide("Three things we built that don’t exist together", 6, "Card 1 is the architecture claim: all five pieces, one loop. Card 2 is the evaluation claim: pre-registered and honest, with a clean null kept in the write-up. Card 3 is the safety claim: the model advises, deterministic code decides. If asked what is genuinely ours — it is the loop plus the discipline, not any single brick.");
  const y = 1.36, w = 3.91, h = 4.35, gap = (CW - 3 * w) / 2;
  const cards = [
    { icon: "workflow", t: "The closed loop", d: "5-source eBPF telemetry → declared baseline → typed decision → hash-chained audit → auto-rollback.", foot: "No 2022–26 system ships all five.", a: CYAN },
    { icon: "scale", t: "Honest measurement", d: "Pre-registered, paired ON/OFF, locked pre-test. +0.0201 ΔMacro-F1 lab; live replication inconclusive — reported anyway.", foot: "Most course projects stop at the first good number.", a: GREEN },
    { icon: "shield", t: "Safe by construction", d: "Dry-run default · zero pod-delete verbs · 900 s TTL rollback · overrides outrank model confidence.", foot: "Probabilistic AI, mission-critical infra.", a: GREEN },
  ];
  cards.forEach((c, i) => {
    const x = M + i * (w + gap);
    card(s, x, y, w, h);
    CY(s, c.icon, x + 0.32, y + 0.32, 0.55);
    heading(s, c.t, x + 0.32, y + 1.02, w - 0.64, { size: 22, h: 0.42 });
    body(s, [c.d], x + 0.32, y + 1.5, w - 0.64, 1.95, { fontSize: 15 });
    s.addShape(pres.shapes.RECTANGLE, { x: x + 0.32, y: y + h - 0.78, w: 0.75, h: 0.028, fill: { color: c.a }, line: { type: "none" } });
    caption(s, c.foot, x + 0.32, y + h - 0.62, w - 0.64, { fontSize: 12, color: "3A5068" });
  });
}

/* ============ SLIDE 7 — ARCHITECTURE (native shapes) ============ */
{
  const s = contentSlide("From five streams to one auditable decision", 7, "Numbered stages left to right. Amber dashes mark the trust boundary — everything left of the sanitizer is attacker-controlled bytes. Stress stage 6: the model advises, the policy engine decides. Stage 7: every decision lands in a hash-chained audit — tamper-evident, verifiable in the demo.");
  const laneY = 1.42;
  // trust boundary A — untrusted
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y: laneY, w: 4.1, h: 3.62, rectRadius: 0.09, fill: { color: "FDEEDC" }, line: { color: AMBER, width: 1.25, dashType: "dash" } });
  caption(s, "UNTRUSTED — ATTACKER BYTES", M + 0.2, laneY + 0.08, 3.7, { fontSize: 10.5, color: "8F5A06", align: "left" });
  const chips = ["Falco syscalls", "K8s audit webhook", "Hubble flows", "cAdvisor / Prometheus", "Trivy CVE cache"];
  chips.forEach((t, i) => chip(s, t, M + 0.25, laneY + 0.42 + i * 0.44, 2.15, CYAN, { fontSize: 10.5 }));
  heading(s, "1 · Normalize", M + 0.25, laneY + 0.36 + 5 * 0.44, 3.5, { size: 12.5, h: 0.28 });
  caption(s, "Pydantic CanonicalEvent · secrets redacted", M + 0.25, laneY + 0.62 + 5 * 0.44, 3.6, { fontSize: 10, color: MUTED });

  const arrow = (x, y, w) => s.addShape(pres.shapes.RIGHT_ARROW, { x, y, w, h: 0.42, fill: { color: CYAN }, line: { type: "none" } });
  arrow(4.78, laneY + 1.6, 0.34);

  // middle stage cards
  const midX = 5.28, midW = 3.1;
  card(s, midX, laneY, midW, 1.06);
  heading(s, "2 · Correlate ±30s", midX + 0.2, laneY + 0.08, midW - 0.4, { size: 13, h: 0.3 });
  caption(s, "Falco ↔ audit window · dedup", midX + 0.2, laneY + 0.38, midW - 0.4, { fontSize: 11 });
  card(s, midX, laneY + 1.24, midW, 1.06);
  heading(s, "3 · Baseline compare", midX + 0.2, laneY + 1.32, midW - 0.4, { size: 13, h: 0.3 });
  caption(s, "Declared YAML · drift facts (33.6 µs normalize)", midX + 0.2, laneY + 1.62, midW - 0.4, { fontSize: 11 });
  card(s, midX, laneY + 2.48, midW, 1.14);
  heading(s, "4 · Sanitize", midX + 0.2, laneY + 2.56, midW - 0.4, { size: 13, h: 0.3 });
  caption(s, "XML-escape · <untrusted_args> · 128-char cap · keyword strip", midX + 0.2, laneY + 2.86, midW - 0.4, { fontSize: 11 });

  arrow(8.46, laneY + 1.6, 0.34);

  // trust boundary B — control loop
  const rightX = 8.88, rightW = W - M - rightX;
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: rightX, y: laneY, w: rightW, h: 3.62, rectRadius: 0.09, fill: { color: "E7F6EE" }, line: { color: AMBER, width: 1.25, dashType: "dash" } });
  caption(s, "CONTROL PLANE — TRUSTED", rightX + 0.2, laneY + 0.08, rightW - 0.4, { fontSize: 10.5, color: "8F5A06" });
  card(s, rightX + 0.2, laneY + 0.42, rightW - 0.4, 1.08);
  heading(s, "5 · Classify — one pass", rightX + 0.38, laneY + 0.48, rightW - 0.76, { size: 13, h: 0.3 });
  caption(s, "Rules  ·  Random Forest  ·  ScaleDown classify-1 (Choice + Score + Noul)", rightX + 0.38, laneY + 0.78, rightW - 0.76, { fontSize: 11 });
  card(s, rightX + 0.2, laneY + 1.68, rightW - 0.4, 1.08);
  heading(s, "6 · Policy engine decides", rightX + 0.38, laneY + 1.74, rightW - 0.76, { size: 13, h: 0.3 });
  caption(s, "Confidence ≥ 0.70 · severity ≥ 4.0 · allowlisted ns · overrides outrank model", rightX + 0.38, laneY + 2.04, rightW - 0.76, { fontSize: 11 });
  card(s, rightX + 0.2, laneY + 2.94, rightW - 0.4, 0.56);
  heading(s, "7 · Act + audit", rightX + 0.38, laneY + 2.97, rightW - 0.76, { size: 13, h: 0.26 });
  caption(s, "Log · alert · review · quarantine → SHA-256 JSONL", rightX + 0.38, laneY + 3.2, rightW - 0.76, { fontSize: 10 });

  // bottom legend
  caption(s, "1–5 attacker-controlled input path  ·  6 deterministic code outranks model confidence  ·  7 reversible actuation, every decision hash-chained", M, 5.32, CW, { fontSize: 13, color: "3A5068" });
  caption(s, "Latency p50: normalize 33.6 µs → rules 1.9 µs → policy 1.5 µs → audit 85.9 µs  ·  full pipeline diagram: ppt_assets/architecture.png", M, 5.66, CW, { fontSize: 12.5 });
}

/* ============ SLIDE 8 — TECH STACK ============ */
{
  const s = contentSlide("Pinned stack, no magic", 8, "Five groups, everything version-pinned. Call out that CI is fully offline and every tool here is free — nothing experimental sneaks in. If they ask for a live link, it is a kind cluster on a VM, deliberately.");
  const groups = [
    { icon: "cloud", t: "Cloud & infra", items: "kind v0.22.0 · Kubernetes 1.29.2\nCilium 1.20.1 · Falco 0.45.0 (eBPF)\nkindest/node v1.29.2 · Ubuntu 24.04 · kernel 6.8" },
    { icon: "server", t: "Backend", items: "Python ≥ 3.12 · Pydantic v2\nhttpx · scikit-learn ≥ 1.4\nuv · hatchling · JSON Schema" },
    { icon: "cpu", t: "Models & AI", items: "ScaleDown classify-1 (prod)\nGroq: gpt-oss-20b · qwen3.8-27b (A/B)\nRF arm · NIM prompt-guards (tier 3)" },
    { icon: "lock", t: "Security", items: "Namespaced RBAC · zero delete verbs\nDefault-deny NetworkPolicy · PSA + quotas\nSanitizer · gitleaks · pre-commit" },
    { icon: "gauge", t: "Observability", items: "Prometheus :9090 (15 metrics)\nGrafana dashboard.json · tracing: none\nJSONL audit · SHA-256 chain · verify_chain()" },
  ];
  const y = 1.3, ch = 2.05, topW = 3.91, gap = (CW - 3 * topW) / 2, botW = 3.91, botGap = (CW - 2 * botW) / 3;
  groups.slice(0, 3).forEach((g, i) => {
    const x = M + i * (topW + gap);
    card(s, x, y, topW, ch);
    CY(s, g.icon, x + 0.24, y + 0.22, 0.42);
    heading(s, g.t, x + 0.78, y + 0.2, topW - 1.0, { size: 17.5, h: 0.46 });
    s.addText(g.items, { x: x + 0.24, y: y + 0.72, w: topW - 0.48, h: 0.82, fontFace: MONO, fontSize: 10.5, color: "3A5068", margin: 0, lineSpacingMultiple: 1.18, valign: "top" });
  });
  groups.slice(3).forEach((g, i) => {
    const x = M + botGap + i * (botW + botGap);
    const y2 = y + ch + 0.3;
    card(s, x, y2, botW, ch);
    CY(s, g.icon, x + 0.24, y2 + 0.22, 0.42);
    heading(s, g.t, x + 0.78, y2 + 0.2, botW - 1.0, { size: 17.5, h: 0.46 });
    s.addText(g.items, { x: x + 0.24, y: y2 + 0.72, w: botW - 0.48, h: 0.82, fontFace: MONO, fontSize: 10.5, color: "3A5068", margin: 0, lineSpacingMultiple: 1.18, valign: "top" });
  });
  caption(s, "Every version pinned in pyproject.toml / DECISIONS D-06  ·  no external services in CI  ·  lab VM: 6–8 GB RAM, 40 GB disk budget", M, 6.35, CW, { fontSize: 12 });
}

/* ============ SLIDE 9 — CLOUD SECURITY ============ */
{
  const s = contentSlide("Every threat has a deterministic answer", 9, "Left table: each attack we modeled and the control that neutralizes it — note row 3 is the heart of the design: the pod spec, not the model, decides. Right: badges for the practice we follow. Bottom callout: the measured result of the injection suite, 30% raw ASR to zero under the full stack.");
  const rows = [
    [headCell("Threat"), headCell("Control that answers it")],
    ["Malicious command line (“ignore previous instructions…”)", "Sanitizer — keyword strip · <untrusted_args> wrap · XML escape"],
    ["Stolen SA token · exec via API server", "Namespaced allowlist RBAC — zero delete verbs"],
    ["hostPath / runtime socket → container escape", "Deterministic overrides from pod spec — not model judgment"],
    ["Cryptomining egress", "Hubble + cAdvisor fusion · sustained-CPU fact · tiered response"],
    ["Baseline poisoning via telemetry", "Declared YAML baselines · leakage gate: 0 class tokens in raw data"],
  ].map((r, i) => i === 0 ? r : r.map((c, j) => ({ text: c, options: { fontFace: BODY, fontSize: 12.5, color: j === 0 ? "8F5A06" : TXT, fill: { color: i % 2 ? CARD : "F3F7FC" }, margin: [7, 12, 7, 12], valign: "middle", border: { type: "solid", color: LINE, pt: 1 } } })));
  s.addTable(rows, { x: M, y: 1.32, w: 7.5, colW: [2.9, 4.6], rowH: [0.42, 0.72, 0.72, 0.72, 0.72, 0.72] });

  const bx = 8.42, bw = W - M - bx;
  heading(s, "PRACTICE", bx, 1.32, bw, { size: 12, h: 0.3 });
  const badges = ["Least privilege", "Zero trust", "Defense in depth", "OWASP LLM01/02", "CIS Pod Security"];
  badges.forEach((b, i) => chip(s, b, bx, 1.68 + i * 0.47, bw, GREEN, { fontSize: 13.5 }));

  card(s, bx, 4.14, bw, 1.3);
  heading(s, "Measured", bx + 0.24, 4.24, bw - 0.48, { size: 11.5, h: 0.24 });
  s.addText([{ text: "ASR  ", options: { color: MUTED, fontSize: 13 } }, { text: "30% → 0.0%", options: { color: GREEN, bold: true, fontSize: 26, fontFace: TITLE_FONT } }], { x: bx + 0.24, y: 4.5, w: bw - 0.48, h: 0.5, margin: 0, valign: "middle" });
  caption(s, "10 payloads × 4 tiers, 2 reps · full stack neutralizes", bx + 0.24, 5.02, bw - 0.48, { fontSize: 11 });

  caption(s, "All lab endpoints bound to 127.0.0.1  ·  secrets env-only, CI-scanned  ·  sanitizer redacts before any model call", M, 6.35, 7.5, { fontSize: 12 });
}

/* ============ SLIDE 10 — SRE ============ */
{
  const s = contentSlide("Measured reliability — honest gaps", 10, "Left: the four numbers we can defend from latest.json. Flag the missing SLOs first — they will ask. Right: the benchmark screenshot, not a mock. Bottom: CI is offline and verify-only; say the 282 passing tests out loud.");
  const y = 1.3, sw = 6.0;
  const sli = [
    { v: "7,879.6", u: "events/s", d: "full hash-chained audit · 5×1,000 events · 0 errors" },
    { v: "122.6 µs", u: "p50 end-to-end", d: "normalize 33.6 · rules 1.9 · policy 1.5 · audit 85.9 µs" },
    { v: "0.00%", u: "errors", d: "5,000 events · every trial · hash chain verified" },
    { v: "85.9 µs", u: "audit write (p50)", d: "~70% of pipeline budget — cost of tamper evidence, paid on purpose" },
  ];
  sli.forEach((c, i) => {
    const x = M + (i % 2) * (sw / 2 + 0.12), cy = y + Math.floor(i / 2) * 1.62;
    const w2 = sw / 2 - 0.12;
    card(s, x, cy, w2, 1.48);
    s.addText(c.v, { x: x + 0.2, y: cy + 0.12, w: w2 - 0.4, h: 0.62, fontFace: TITLE_FONT, fontSize: 33, bold: true, color: CYAN, margin: 0, valign: "middle" });
    s.addText(c.u, { x: x + 0.2, y: cy + 0.72, w: w2 - 0.4, h: 0.24, fontFace: BODY, fontSize: 12.5, bold: true, color: TXT, margin: 0, valign: "middle" });
    caption(s, c.d, x + 0.2, cy + 0.98, w2 - 0.4, { fontSize: 9.5, h: 0.45 });
  });
  s.addText([{ text: "Formal SLOs / error budget: ", options: { color: "8F5A06", bold: true } }, { text: "not defined — nothing claimed", options: { color: MUTED } }], { x: M, y: 4.56, w: sw, h: 0.3, fontFace: BODY, fontSize: 12, margin: 0, valign: "middle" });

  const ix = 7.0, iw = W - M - ix;
  terminal(s, { x: ix, y, w: iw, h: 3.3, title: "zsh — benchmark_pipeline.py", lines: [
    [["$ ", "34D399"], ["uv run python scripts/benchmark_pipeline.py", "F1F5F9"]],
    [["5 trials × 1,000 events  ·  errors: ", "8A97AB"], ["0", "34D399"]],
    [[" ", "F1F5F9"]],
    [["throughput  ", "8A97AB"], ["7,879.6 events/s", "22D3EE"], ["  (median)", "8A97AB"]],
    [["p50 latency ", "8A97AB"], ["122.6 µs", "22D3EE"]],
    [["normalize ", "8A97AB"], ["33.6 µs", "F1F5F9"], ["  rules ", "8A97AB"], ["1.9 µs", "F1F5F9"], ["  policy ", "8A97AB"], ["1.5 µs", "F1F5F9"]],
    [["audit      ", "8A97AB"], ["85.9 µs", "F59E0B"], ["  (~70% of budget)", "8A97AB"]],
    [["audit chain verify_chain ... ", "8A97AB"], ["OK", "34D399"]],
  ], rowH: 0.3, fontSize: 11.5 });
  caption(s, "Output trimmed. Numbers from data/benchmarks/latest.json — benchmark screenshot: docs/report/screenshots/03_pipeline_benchmark.png", ix, y + 3.42, iw, { fontSize: 11, h: 0.45 });

  heading(s, "CI — offline, verify-only", M, 5.02, 6.0, { size: 13.5, h: 0.3 });
  const steps = ["Checkout", "Secrets scan", "gitleaks", "ruff + fmt", "mypy", "282 tests ✓"];
  const sx = M, stepW = 1.42, gap2 = 0.575, sy = 5.36;
  steps.forEach((t, i) => {
    chip(s, t, sx + i * (stepW + gap2), sy, stepW, i === steps.length - 1 ? GREEN : CYAN, { fontSize: 11 });
    if (i < steps.length - 1) s.addShape(pres.shapes.RIGHT_ARROW, { x: sx + i * (stepW + gap2) + stepW + 0.08, y: sy + 0.05, w: 0.42, h: 0.24, fill: { color: LINE }, line: { type: "none" } });
  });
  caption(s, "No cluster, no API keys, no network in CI  ·  no CD / blue-green / canary — demo deploys to kind on demand", M, 5.82, CW, { fontSize: 12 });
}

/* ============ SLIDE 11 — AI / LLM ============ */
{
  const s = contentSlide("One state in, three typed answers out", 11, "Left: what the LLM actually does — one calibrated decode, three typed questions, never chat. Right: measured tokens and cost per call from the 14 live smoke calls — these are real numbers, not vendor claims. End with the honest line: no prompt compression exists in this project.");
  const y = 1.32, lw = 5.95;
  card(s, M, y, lw, 3.2);
  heading(s, "How the LLM is used", M + 0.28, y + 0.2, lw - 0.56, { size: 17.5 });
  body(s, [
    "Not chat, not RAG — one serialized incident state, one calibrated decode pass",
    "classify-1 answers: attack_type (Choice, 5 classes) · severity (Score 0–4) · 4 Noul flags",
    "Advisory only — the policy engine is the final authority",
    "Temp 0 · 5.0 s hard timeout → degraded mode → human review",
  ], M + 0.28, y + 0.68, lw - 0.56, 2.4, { fontSize: 13.5 });
  card(s, M, y + 3.26, lw, 1.42);
  heading(s, "Models", M + 0.28, y + 3.42, lw - 0.56, { size: 12.5, h: 0.26 });
  s.addText([
    { text: "Prod:  ", options: { bold: true, color: TXT } }, { text: "ScaleDown classify-1 (hosted SLM)", options: { color: "3A5068", breakLine: true, paraSpaceAfter: 4 } },
    { text: "A/B:  ", options: { bold: true, color: TXT } }, { text: "gpt-oss-20b · qwen3.8-27b (Groq)", options: { color: "3A5068", breakLine: true, paraSpaceAfter: 4 } },
    { text: "Tier 3:  ", options: { bold: true, color: TXT } }, { text: "Llama Guard 4 + Nemotron safety guard (NIM)", options: { color: "3A5068" } },
  ], { x: M + 0.28, y: y + 3.72, w: lw - 0.56, h: 0.82, fontFace: BODY, fontSize: 12, margin: 0, lineSpacingMultiple: 1.14, valign: "top" });

  const cx = 6.85, cw = W - M - cx;
  card(s, cx, y, cw, 4.56);
  heading(s, "Measured calls — tokens in", cx + 0.28, y + 0.2, cw - 0.56, { size: 14.5 });
  const labels = ["c12", "c13", "c14", "c05", "c10", "c11", "c07", "c08", "c09", "c04"];
  const tokens = [1820, 1952, 1934, 1910, 1808, 1808, 1808, 1856, 1808, 1910];
  s.addChart(pres.charts.BAR, [{ name: "Input tokens (6 questions)", labels, values: tokens }], {
    x: cx + 0.2, y: y + 0.52, w: cw - 0.4, h: 2.5, barDir: "col",
    chartColors: [CYAN], chartArea: { fill: { color: CARD } }, plotArea: { fill: { color: CARD } },
    showValue: true, dataLabelPosition: "outEnd", dataLabelColor: TXT, dataLabelFontSize: 10, dataLabelFontFace: MONO,
    catAxisLabelColor: MUTED, catAxisLabelFontSize: 10, catAxisLabelFontFace: MONO, catGridLine: { style: "none" },
    valAxisLabelColor: MUTED, valAxisLabelFontSize: 9, valGridLine: { color: LINE, size: 0.75 },
    showLegend: false, showTitle: false, valAxisMaxVal: 2100,
  });
  s.addText([{ text: "$0.000090–0.000098", options: { bold: true, color: TXT, fontSize: 16 } }, { text: "  per call · mean $0.0000931", options: { color: MUTED, fontSize: 12 } }], { x: cx + 0.28, y: y + 3.1, w: cw - 0.56, h: 0.32, margin: 0, valign: "middle" });
  s.addText([{ text: "≈ $0.093", options: { bold: true, color: CYAN, fontSize: 21 } }, { text: " per 1,000 decisions", options: { color: MUTED, fontSize: 12 } }], { x: cx + 0.28, y: y + 3.42, w: cw - 0.56, h: 0.38, margin: 0, valign: "middle" });
  caption(s, "Pre-filter ON: 99.2% recall · −64.5% API cost (ABL-PREF)", cx + 0.28, y + 3.82, cw - 0.56, { fontSize: 12, color: "3A5068" });
  caption(s, "No prompt/token compression in this project — typed-decision classifier only.", cx + 0.28, y + 4.12, cw - 0.56, { fontSize: 11, color: "8F5A06" });
}

/* ============ SLIDE 12 — METHODOLOGY ============ */
{
  const s = contentSlide("Six gates to an honest result", 12, "Walk the line left to right — emphasize Gate 5: pre-registration was locked before we ever opened the test split. That is why the modest +0.0201 is credible. End at gate 6: every claim on this slide is re-runnable from the repo.");
  const steps = [
    { n: "1", t: "Feasibility gate", d: "Kernel / BTF check on Ubuntu 24.04 VM before any code" },
    { n: "2", t: "Lab bring-up", d: "kind + Cilium + Falco · 3 tenants × 4 workloads" },
    { n: "3", t: "Vertical slice", d: "make demo — 4 scenarios end-to-end, audit verified" },
    { n: "4", t: "Corpus capture", d: "84 live runs · 55 templates · zero leakage gate" },
    { n: "5", t: "Pre-registration", d: "Locked 2026-10-17 — before test-split access" },
    { n: "6", t: "Evaluate & deliver", d: "ABL battery · live A/B · report · paper · this deck" },
  ];
  const lineY = 2.9;
  s.addShape(pres.shapes.RECTANGLE, { x: M + 0.4, y: lineY - 0.008, w: CW - 0.8, h: 0.016, fill: { color: LINE }, line: { type: "none" } });
  const colW = (CW - 0.8) / 6;
  steps.forEach((c, i) => {
    const x = M + 0.4 + i * colW;
    s.addShape(pres.shapes.OVAL, { x: x + colW / 2 - 0.21, y: lineY - 0.21, w: 0.42, h: 0.42, fill: { color: CYAN }, line: { color: BG, width: 2 } });
    s.addText(c.n, { x: x + colW / 2 - 0.21, y: lineY - 0.21, w: 0.42, h: 0.42, fontFace: TITLE_FONT, fontSize: 16, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
    heading(s, c.t, x, lineY + 0.46, colW - 0.1, { size: 15.5, h: 0.32, align: "center" });
    caption(s, c.d, x, lineY + 0.84, colW - 0.1, { fontSize: 10.5, align: "center", h: 1.4 });
  });
  caption(s, "Scope shed first, never the core eval (D-17): human feedback loop → risk score → live quarantine → Grafana panels → Hubble/Trivy normalizers", M, 5.28, CW, { fontSize: 13, align: "center", color: "3A5068" });
  caption(s, "Mode A pair programming · authors ran and approved every gate · full log: docs/GATE_REPORTS.md (1,556 lines)", M, 5.62, CW, { fontSize: 12.5, align: "center" });
}

/* ============ SLIDE 13 — RESULTS ============ */
{
  const s = contentSlide("Modest where it counts — zero where it matters", 13, "Three headline numbers first, slowly. Then the before/after pair chart: Falco 0.333 against RuntimeLens 0.533, same budget. End on the honest line under the chart — the live replication was inconclusive, and we report it as measured.");
  const y = 1.32, w = 3.91, h = 2.05, gap = (CW - 3 * w) / 2;
  const big = [
    { v: "0.5333", d: "Macro-F1 (lab, 112-run held-out)", s: "vs 0.3333 Falco · +0.2000" },
    { v: "3.6%", d: "benign false-positive rate", s: "vs 18.4% Falco · −41.7% relative" },
    { v: "0.0%", d: "prompt-injection ASR, full stack", s: "from 30.0% raw · all four tiers" },
  ];
  big.forEach((c, i) => {
    const x = M + i * (w + gap);
    card(s, x, y, w, h);
    s.addText(c.v, { x: x + 0.28, y: y + 0.18, w: w - 0.56, h: 1.0, fontFace: TITLE_FONT, fontSize: 54, bold: true, color: CYAN, margin: 0, valign: "middle" });
    s.addText(c.d, { x: x + 0.28, y: y + 1.16, w: w - 0.56, h: 0.3, fontFace: BODY, fontSize: 15, bold: true, color: TXT, margin: 0, valign: "middle" });
    caption(s, c.s, x + 0.28, y + 1.46, w - 0.56, { fontSize: 12, color: "3A5068" });
  });
  card(s, M, 3.62, CW, 2.35);
  heading(s, "Before → after — same telemetry, same evaluation budget", M + 0.3, 3.74, CW - 0.6, { size: 15 });
  s.addChart(pres.charts.BAR, [
    { name: "Falco default rules", labels: ["Macro-F1"], values: [0.3333] },
    { name: "RuntimeLens (ScaleDown)", labels: ["Macro-F1"], values: [0.5333] },
  ], {
    x: M + 0.3, y: 4.12, w: 5.6, h: 1.7, barDir: "bar", barGapWidthPct: 60,
    chartColors: [MUTED, GREEN], chartArea: { fill: { color: CARD } }, plotArea: { fill: { color: CARD } },
    showValue: true, dataLabelPosition: "outEnd", dataLabelColor: TXT, dataLabelFontSize: 13, dataLabelFontFace: MONO, dataLabelFormatCode: "0.000",
    catAxisLabelColor: TXT, catAxisLabelFontSize: 13, catGridLine: { style: "none" },
    valAxisLabelColor: MUTED, valAxisLabelFontSize: 9, valAxisMaxVal: 0.62, valGridLine: { color: LINE, size: 0.75 },
    showLegend: true, legendPos: "b", legendColor: MUTED, legendFontSize: 12, valAxisMinVal: 0,
  });
  s.addText([
    { text: "Also measured: ", options: { color: MUTED, breakLine: true, paraSpaceAfter: 4 } },
    { text: "RF 84-run corpus: 0.5603 ± 0.0700 F1 · 4.8% FPR", options: { color: "22384F", breakLine: true, paraSpaceAfter: 4 } },
    { text: "Live A/B (n=28, 2 arms): Macro-F1 inconclusive, FPR halved", options: { color: "22384F", breakLine: true, paraSpaceAfter: 4 } },
    { text: "Pre-registered Δ +0.0201 [+0.0132, +0.0275]", options: { color: "22384F" } },
  ], { x: 7.15, y: 4.15, w: 5.25, h: 1.72, fontFace: BODY, fontSize: 12.5, margin: 0, lineSpacingMultiple: 1.18, valign: "top" });
  caption(s, "Sources: docs/report/final_report.md §7 · research/results/live_analysis.md · ablation_study_results.json — reported as measured, including the null.", M, 6.12, CW, { fontSize: 12 });
}

/* ============ SLIDE 14 — DEMO ============ */
{
  const s = contentSlide("Five minutes · four scenarios · one proof", 14, "Run make demo. Stop on scenario 3 — the dry-run quarantine with TTL is the money moment: no pod is deleted, rollback is automatic. Finish with verify_chain to prove the audit trail is tamper-evident. The full recording is in docs/demo/runtimelens_demo.mp4.");
  const steps = [
    { n: "1", d: "Benign nginx passes its baseline → action LOG · audit hash-chained" },
    { n: "2", d: "Unexpected /bin/sh in database pod → ALERT / human review" },
    { n: "3", d: "hostPath + socket (escape) → dry-run NetworkPolicy quarantine" },
    { n: "4", d: "Sustained CPU + egress → ALERT + review queue" },
    { n: "5", d: "verify_chain + make lab-verify → tamper-evidence proven" },
  ];
  const y = 1.4, lw = 6.6;
  steps.forEach((c, i) => {
    const cy = y + i * 0.88;
    s.addShape(pres.shapes.OVAL, { x: M, y: cy, w: 0.52, h: 0.52, fill: { color: i === 2 ? AMBER : CYAN }, line: { type: "none" } });
    s.addText(c.n, { x: M, y: cy, w: 0.52, h: 0.52, fontFace: TITLE_FONT, fontSize: 18, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
    body(s, [c.d], M + 0.78, cy, lw - 0.78, 0.8, { fontSize: 15.5 });
    if (i < steps.length - 1) s.addShape(pres.shapes.RECTANGLE, { x: M + 0.25, y: cy + 0.52, w: 0.03, h: 0.36, fill: { color: LINE }, line: { type: "none" } });
  });
  const ix = 7.55, iw = W - M - ix;
  terminal(s, { x: ix, y, w: iw, h: 4.0, title: "zsh — demo.py --auto", lines: [
    [["$ ", "34D399"], ["uv run python scripts/demo.py --auto", "F1F5F9"]],
    [[" ", "F1F5F9"]],
    [["Scenario 1  benign nginx     → ", "8A97AB"], ["LOG", "34D399"]],
    [["Scenario 2  unexpected sh    → ", "8A97AB"], ["ALERT", "F59E0B"], [" · 0.64", "8A97AB"]],
    [["Scenario 3  hostPath+socket  → ", "8A97AB"], ["QUARANTINE", "22D3EE"]],
    [["Scenario 4  CPU + egress     → ", "8A97AB"], ["ALERT + REVIEW", "F59E0B"]],
    [[" ", "F1F5F9"]],
    [["audit chain verify_chain ... ", "8A97AB"], ["OK", "34D399"], ["  · fbae87…", "8A97AB"]],
  ], rowH: 0.34, fontSize: 11.5 });
  caption(s, "Live run — output trimmed. Audit chain verified inline.", ix, y + 4.12, iw, { fontSize: 11 });
  caption(s, "Full recording: docs/demo/runtimelens_demo.mp4", ix, y + 4.34, iw, { fontSize: 11.5 });
}

/* ============ SLIDE 15 — CHALLENGES / FUTURE ============ */
{
  const s = contentSlide("What broke — and what ships next", 15, "Left column: failures we owned, with the one that still stings — the ablation artifact contradicting the headline. Right: realistic next steps, no vaporware. If asked which limitation matters most: lab-to-real transfer — everything else is engineering.");
  const y = 1.32, w = (CW - 0.4) / 2, h = 4.6;
  card(s, M, y, w, h);
  CY(s, "triangle", M + 0.28, y + 0.26, 0.44);
  heading(s, "Challenges & limits", M + 0.82, y + 0.24, w - 1.1, { size: 18, h: 0.44 });
  body(s, [
    "Leakage bug: F1 = 1.0 — tag invalidated, retrained",
    "Vendor 70–500 ms claim struck; measured ≈ 1.04 s",
    "ScaleDown 402 credits — live calls capped at 14",
    "Live macro-F1 inconclusive (n=28) — kept as-is",
    "Ablation artifact contradicts 0.5333 headline",
    "Lab-only · data/raw gitignored · no SLOs, no CD",
    "Docs disagree: 1.2 s vs ±30 s correlation window",
  ], M + 0.28, y + 0.86, w - 0.56, 3.5, { fontSize: 14, color: "8F5A06" });
  const rx = M + w + 0.4;
  card(s, rx, y, w, h);
  CY(s, "rocket", rx + 0.28, y + 0.26, 0.44);
  heading(s, "Future work", rx + 0.82, y + 0.24, w - 1.1, { size: 18, h: 0.44 });
  body(s, [
    "On-node quantized SLM — telemetry never leaves the pod",
    "Field trial on a non-lab cluster, pre-registered again",
    "Scoped SA-token revocation tier — still reversible, zero deletes",
    "Hubble + Trivy normalizers into the hot path",
    "Review-queue reclassifications → automatic baseline diffs",
  ], rx + 0.28, y + 0.86, w - 0.56, 3.5, { fontSize: 14, color: "14694A" });
}

/* ============ SLIDE 16 — CONCLUSION ============ */
{
  const s = contentSlide("Three things to remember", 16, "Deliver the three beats verbatim, then stop talking. If they ask for one sentence: RuntimeLens is the proof that context — declared by the operator — beats generic rules, and that an honest null is worth more than a tuned one.");
  const y = 1.34, w = CW, h = 1.02, gap = 0.28;
  const takeaways = [
    { n: "1", t: "Context beats rules", d: "0.5333 Macro-F1 · 3.6% benign FPR — vs 0.333 / 18.4% for Falco." },
    { n: "2", t: "Honest beats impressive", d: "Pre-registered; +0.0201 kept; the live null kept too — nothing tuned after the fact." },
    { n: "3", t: "Safe to run where it matters", d: "Dry-run · zero delete verbs · 900 s TTL rollback · hash-chained audit." },
  ];
  takeaways.forEach((c, i) => {
    const cy = y + i * (h + gap);
    card(s, M, cy, w, h);
    s.addShape(pres.shapes.OVAL, { x: M + 0.24, y: cy + h / 2 - 0.32, w: 0.64, h: 0.64, fill: { color: "E3F6EC" }, line: { color: GREEN, width: 1.5 } });
    s.addText(c.n, { x: M + 0.24, y: cy + h / 2 - 0.32, w: 0.64, h: 0.64, fontFace: TITLE_FONT, fontSize: 24, bold: true, color: GREEN, align: "center", valign: "middle", margin: 0 });
    heading(s, c.t, M + 1.15, cy + 0.13, w - 1.5, { size: 21, h: 0.38 });
    body(s, [c.d], M + 1.15, cy + 0.5, w - 1.5, 0.42, { fontSize: 15 });
  });
  s.addText("Thank you", { x: M, y: 5.7, w: CW, h: 0.62, fontFace: TITLE_FONT, fontSize: 32, bold: true, color: CYAN, align: "center", margin: 0, valign: "middle" });
  s.addText("github.com/himanshukumar19/RuntimeLens   ·   PROJECT_FOR_PPT.md   ·   docs/GATE_REPORTS.md", { x: M, y: 6.32, w: CW, h: 0.3, fontFace: MONO, fontSize: 12, color: MUTED, align: "center", margin: 0, valign: "middle" });
  s.addNotes("Thank the panel, then answer questions. If asked for the repo link, it is on this slide and in PROJECT_FOR_PPT.md §20.");
}

/* ============ SLIDE 17 — REFERENCES ============ */
{
  const s = contentSlide("References", 17, "Point to the full bibliography in PROJECT_FOR_PPT.md §4 and §19 rather than reading every entry. Mention the two load-bearing ones from memory: Jarkas for the threat model, Shadowkube as the closest precedent.");
  const colW = (CW - 0.4) / 2;
  const refs = [
    "Jarkas et al., ACM Computing Surveys, 2025 — 5-layer container threat taxonomy",
    "Galletta, arXiv:2609.13930, 2026 — stateful eBPF policies",
    "Islam & Rashid, 2026 — GCID: rules cannot chain (our motivation)",
    "Ryu et al., Comput. Mater. Continua 86(3), 2026 — hybrid eBPF detection",
    "Chen et al., Shadowkube, Cybersecurity, 2025 — closest precedent",
    "Franzil et al., Comput. Networks 276, 2026 — context-aware audit logs",
    "Aly et al., OCR-APT, ACM CCS 2025 · Malul et al., GenKubeSec, 2024",
    "Karanjai et al., arXiv:2607.14493, 2026 — context contamination (our sanitizer)",
    "Grinsztajn et al., NeurIPS D&B 2022 — why forests beat nets on tabular",
    "McNemar, Psychometrika 1947 · Holm, Scand. J. Stat. 1979",
    "ScaleDown AI — Platform docs & Decisions API reference, 2026",
    "Falco (CNCF) · Cilium/Hubble · Kubernetes · scikit-learn · Prometheus",
  ];
  const left = refs.slice(0, 6), right = refs.slice(6);
  const mkRefs = (arr) => arr.map((t) => ({ text: t, options: { bullet: { code: "2022", indent: 10 }, color: "3A5068", breakLine: true, paraSpaceAfter: 12 } }));
  s.addText(mkRefs(left), { x: M, y: 1.5, w: colW, h: 4.6, fontFace: BODY, fontSize: 15, margin: 0, lineSpacingMultiple: 1.15, valign: "top" });
  s.addText(mkRefs(right), { x: M + colW + 0.4, y: 1.5, w: colW, h: 4.6, fontFace: BODY, fontSize: 15, margin: 0, lineSpacingMultiple: 1.15, valign: "top" });
  s.addText("Every number in this deck traces to a file in the repo.", { x: M, y: 5.35, w: CW, h: 0.35, fontFace: BODY, fontSize: 14.5, italic: true, color: CYAN, margin: 0, valign: "middle" });
  caption(s, "Full list: PROJECT_FOR_PPT.md §19 — 22 papers · 6 tool references · all DOIs verified in docs/paper/runtimelens_paper.tex", M, 5.78, CW, { fontSize: 13 });
}

/* ============ WRITE ============ */
pres.writeFile({ fileName: OUT }).then(() => console.log("wrote", OUT));
