"""Generate publication-quality figures for the RuntimeLens deck and paper.

Reads measured artefacts only:
  * research/results/*.json   live typed-decision evaluation (this repo)
  * docs/report/final_report.md numbers already recorded in the lab gate reports
  * data/benchmarks/latest.json pipeline throughput benchmark
  * datasets/splits/manifest_v1.json 400-run split manifest

No figure may contain a number that was not produced by one of those sources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[2]
FIGS = Path(__file__).resolve().parent
RESULTS = ROOT / "research" / "results"

INK = "#14243A"
INK_SOFT = "#33465C"
MUTED = "#5E718A"
GRID = "#D8E0EA"
PAPER = "#FFFFFF"
GREEN = "#1F9D6B"
RED = "#C8433C"
AMBER = "#C97B12"
BLUE = "#1B8FD6"
VIOLET = "#0F5E8E"
TEAL = "#1296B8"

SANS = "Geist"
MONO = "Geist Mono"

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": [SANS, "Helvetica Neue", "Arial", "DejaVu Sans"],
        "figure.facecolor": PAPER,
        "axes.facecolor": PAPER,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK_SOFT,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "font.size": 11,
        "figure.dpi": 200,
        "savefig.dpi": 200,
    }
)


def _finish(fig, path: Path, title: str, subtitle: str = "") -> None:
    fig.patch.set_facecolor(PAPER)
    fig.text(0.012, 0.972, title, ha="left", va="top", fontsize=15, fontweight="bold", color=INK)
    if subtitle:
        fig.text(0.012, 0.912, subtitle, ha="left", va="top", fontsize=10.5, color=MUTED)
    fig.savefig(path, bbox_inches="tight", facecolor=PAPER, pad_inches=0.28)
    plt.close(fig)
    print(f"wrote {path}")


def _style(ax, *, xgrid: bool = False) -> None:
    ax.grid(axis="x" if xgrid else "y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


# ---------------------------------------------------------------------------
# 1. Model comparison (macro-F1 and benign FPR)
# ---------------------------------------------------------------------------


def chart_model_comparison(live_arms: list[dict[str, Any]]) -> Path:
    """Falco rules vs Random Forest vs ScaleDown vs live typed-decision arms."""
    rows = [
        ("Falco default rules", 0.3333, 18.4, RED),
        ("Random Forest (dev)", 0.4812, 6.2, AMBER),
        ("Random Forest (84-run)", 0.5603, 4.8, AMBER),
        ("ScaleDown Classify-1", 0.5333, 3.6, BLUE),
    ]
    for arm in live_arms:
        label = f"Live {arm['arm']}"
        rows.append(
            (
                label,
                arm["with_baseline"]["macro_f1"],
                arm["with_baseline"]["benign_fpr"] * 100,
                VIOLET,
            )
        )

    labels = [r[0] for r in rows]
    f1 = [r[1] for r in rows]
    fpr = [r[2] for r in rows]
    colors = [r[3] for r in rows]
    y = list(range(len(rows)))

    fig, ax = plt.subplots(figsize=(9.6, 5.0))
    _style(ax, xgrid=True)
    ax.barh(y, f1, height=0.52, color=colors, alpha=0.92, zorder=3)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 0.92)
    ax.set_xlabel("Macro-F1 (higher is better)")
    for i, (v, c, p) in enumerate(zip(f1, colors, fpr, strict=False)):
        ax.text(
            v + 0.012,
            i,
            f"{v:.3f}",
            va="center",
            ha="left",
            fontsize=10.5,
            fontweight="bold",
            color=c,
        )
        ax.text(
            v + 0.085, i, f"benign FPR {p:.1f}%", va="center", ha="left", fontsize=9.5, color=MUTED
        )

    _finish(
        fig,
        FIGS / "fig_model_comparison.png",
        "Macro-F1 by classifier, with benign false-positive rate",
        "Lab corpus: 112-run held-out split. Live arms: same rubric on the 28-incident suite",
    )
    return FIGS / "fig_model_comparison.png"


# ---------------------------------------------------------------------------
# 2. Ablation deltas
# ---------------------------------------------------------------------------


def chart_ablations() -> Path:
    data = [
        ("ABL-TELEM\nMulti-source fusion vs Falco only", 0.2000, "Macro-F1", BLUE),
        ("ABL-QUEST\nChoice+Noul vs Choice only", 0.0410, "Macro-F1", BLUE),
        ("ABL-BASE\nWorkload baseline ON vs OFF", 0.0201, "Macro-F1", VIOLET),
        ("ABL-PREF\nRule pre-filter ON vs OFF", 0.6450, "cost saved", TEAL),
        ("ABL-GATE\nConfidence 0.50 -> 0.80", 0.25, "to review", AMBER),
    ]
    labels = [d[0] for d in data]
    values = [d[1] for d in data]
    notes = ["Macro-F1", "Macro-F1", "Macro-F1", "inference cost", "routed to review"]
    colors = [d[3] for d in data]

    fig, ax = plt.subplots(figsize=(9.6, 4.6))
    _style(ax, xgrid=True)
    y = list(range(len(data)))
    ax.barh(y, values, height=0.5, color=colors, zorder=3)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 0.78)
    for i, (v, n, c) in enumerate(zip(values, notes, colors, strict=False)):
        ax.text(
            v + 0.012,
            i,
            f"+{v:.4g}  {n}",
            va="center",
            ha="left",
            fontsize=10.5,
            fontweight="bold",
            color=c,
        )
    _finish(
        fig,
        FIGS / "fig_ablations.png",
        "Pre-registered ablation battery (lab corpus)",
        "Each bar isolates one design decision; all values recorded in docs/GATE_REPORTS.md",
    )
    return FIGS / "fig_ablations.png"


# ---------------------------------------------------------------------------
# 3. Live paired A/B with bootstrap CI
# ---------------------------------------------------------------------------


def chart_live_ab(live_arms: list[dict[str, Any]]) -> Path:
    """Two panels: the two halves of the pre-registered hypothesis.

    Left  : Delta macro-F1 (with baseline context - without).
    Right : Delta benign false-positive rate.
    Both  : point estimate with a 10,000-iteration paired bootstrap 95% CI.
    """
    if not live_arms:
        raise SystemExit("no live arms available")

    panels = [
        ("delta_macro_f1", "Delta macro-F1  (with - without baseline)"),
        ("delta_benign_fpr", "Delta benign false-positive rate"),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(11.6, 5.0))
    labels = [a["arm"] for a in live_arms]

    for ax, (key, xlabel) in zip(axes, panels, strict=False):
        _style(ax, xgrid=True)
        ax.axvline(0, color=INK_SOFT, linewidth=1.1, zorder=2)
        deltas, los, his = [], [], []
        for arm in live_arms:
            boot = arm["paired_bootstrap"][key]
            deltas.append(arm[key])
            los.append(boot["lo"])
            his.append(boot["hi"])
        y = list(range(len(live_arms)))
        span = max(abs(min(los)), abs(max(his)), 0.01) * 1.5
        for i in y:
            color = VIOLET if los[i] > 0 else (RED if his[i] < 0 else AMBER)
            ax.plot(
                [los[i], his[i]],
                [i, i],
                color=INK_SOFT,
                linewidth=2.2,
                solid_capstyle="round",
                zorder=4,
            )
            ax.scatter(
                [deltas[i]], [i], s=140, color=color, zorder=5, edgecolor=PAPER, linewidth=1.8
            )
            ax.annotate(
                f"{deltas[i]:+.4f}  [{los[i]:+.3f}, {his[i]:+.3f}]",
                (0, i + 0.36),
                ha="center",
                va="center",
                fontsize=9,
                fontweight="bold",
                color=INK,
            )
        ax.set_yticks(y, labels)
        ax.set_ylim(len(live_arms) - 0.4, -0.85)
        ax.set_xlabel(xlabel)
        ax.set_xlim(-span, span)

    fig.tight_layout(rect=(0, 0, 1, 0.86))
    _finish(
        fig,
        FIGS / "fig_live_ab.png",
        "Live paired A/B: the two halves of the pre-registered hypothesis",
        "10,000-iteration paired bootstrap over incidents; an interval that crosses zero "
        "is not a detected effect",
    )
    return FIGS / "fig_live_ab.png"


def chart_asr(aggregate: dict[str, Any]) -> Path:
    """Prompt-injection ASR across the four defence tiers, averaged over runs."""
    tiers = ["0", "1", "2", "3"]
    tier_names = [
        "Tier 0\nRaw, no sanitization",
        "Tier 1\nSanitizer + XML escaping",
        "Tier 2\n+ deterministic fact overrides",
        "Tier 3\n+ NIM prompt-guard ensemble",
    ]
    offline = [30.0, 10.0, 10.0, 0.0]

    fig, ax = plt.subplots(figsize=(9.6, 4.6))
    _style(ax)
    x = list(range(len(tiers)))
    ax.plot(
        x,
        offline,
        marker="o",
        linewidth=2.4,
        markersize=8,
        color=INK_SOFT,
        label="Lab corpus (recorded fixtures)",
        zorder=4,
    )
    for xi, v in zip(x, offline, strict=False):
        ax.annotate(
            f"{v:.0f}%",
            (xi, v),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=10,
            fontweight="bold",
            color=INK_SOFT,
        )

    palette = {"groq-20b": BLUE, "groq-qwen27b": TEAL, "groq-120b": VIOLET}
    for block in aggregate.get("arms", []):
        arm = block["arm"]
        series = [t["asr_mean"] * 100 for t in block["tiers"]]
        color = palette.get(arm, BLUE)
        ax.plot(
            x,
            series,
            marker="s",
            linewidth=2.2,
            markersize=7,
            color=color,
            label=f"Live: {arm}",
            zorder=4,
        )
        for xi, v in zip(x, series, strict=False):
            ax.annotate(
                f"{v:.0f}%",
                (xi, v),
                textcoords="offset points",
                xytext=(0, -18),
                ha="center",
                fontsize=9,
                fontweight="bold",
                color=color,
            )

    ax.set_xticks(x, tier_names)
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_ylim(-6, 45)
    ax.legend(frameon=False, loc="upper right", fontsize=10)
    _finish(
        fig,
        FIGS / "fig_asr.png",
        "Prompt-injection attack success rate across four defence tiers",
        "ASR = share of true attacks flipped to benign, averaged over completed runs",
    )
    return FIGS / "fig_asr.png"


def chart_latency() -> Path:
    stages = [
        "Audit write + hash chain",
        "Normalize + correlate",
        "Rule classification",
        "Policy engine",
    ]
    p50 = [85.9, 33.6, 1.9, 1.5]
    total = sum(p50)
    colors = [AMBER, BLUE, TEAL, VIOLET]

    fig, ax = plt.subplots(figsize=(7.6, 5.2))
    _style(ax)
    ypos = list(range(len(stages)))[::-1]
    bars = ax.barh(ypos, p50, color=colors, height=0.56, zorder=3)
    for bar, v in zip(bars, p50, strict=False):
        share = v / total * 100
        ax.text(
            v + total * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{v:.1f} us   {share:.0f}%",
            va="center",
            ha="left",
            fontsize=10.5,
            fontweight="bold",
            color=INK,
            zorder=5,
        )
    ax.set_yticks(ypos, stages)
    ax.set_xlim(0, total * 1.24)
    ax.set_xlabel("p50 microseconds per event")
    ax.grid(axis="x", color=GRID)
    ax.grid(axis="y", visible=False)
    ax.text(
        total * 1.22,
        ypos[0] + 0.62,
        f"{total:.0f} us total",
        ha="right",
        va="bottom",
        fontsize=10,
        color=MUTED,
    )
    _finish(
        fig,
        FIGS / "fig_latency.png",
        "Where the time goes: pipeline p50 latency per stage",
        "5 trials x 1,000 synthetic events; 7,879.6 events/s, 0 errors "
        "(data/benchmarks/latest.json)",
    )
    return FIGS / "fig_latency.png"


# ---------------------------------------------------------------------------
# 6. Dataset composition
# ---------------------------------------------------------------------------


def chart_dataset() -> Path:
    manifest = json.loads((ROOT / "datasets" / "splits" / "manifest_v1.json").read_text())
    dev = manifest["target_counts"]["dev"]
    test = manifest["target_counts"]["test"]
    classes = ["benign", "container_escape", "privilege_abuse", "cryptomining", "unknown"]
    colors = [GREEN, RED, AMBER, VIOLET, MUTED]
    fig, ax = plt.subplots(figsize=(9.2, 4.2))
    _style(ax)
    x = list(range(len(classes)))
    ax.bar(
        x,
        [dev[c] for c in classes],
        width=0.62,
        color=colors,
        alpha=0.95,
        zorder=3,
        label=f"Dev split ({manifest['target_counts']['dev']['total']} runs)",
    )
    ax.bar(
        x,
        [test[c] for c in classes],
        width=0.62,
        color=colors,
        alpha=0.45,
        zorder=4,
        hatch="///",
        edgecolor=PAPER,
        linewidth=0.0,
        label=f"Test split ({manifest['target_counts']['test']['total']} runs)",
    )
    for xi, c in enumerate(classes):
        ax.text(xi, dev[c] + 3, str(dev[c]), ha="center", fontsize=10, fontweight="bold", color=INK)
        ax.text(xi, test[c] + 3, str(test[c]), ha="center", fontsize=9.5, color=MUTED)
    ax.set_xticks(x, [c.replace("_", "\n") for c in classes])
    ax.set_ylabel("Live cluster runs")
    ax.set_ylim(0, 145)
    ax.legend(frameon=False, loc="upper right", fontsize=10)
    _finish(
        fig,
        FIGS / "fig_dataset.png",
        "400-run live cluster corpus: dev / held-out test split",
        "Grouped by scenario template so no template appears in both splits",
    )
    return FIGS / "fig_dataset.png"


# ---------------------------------------------------------------------------
# 7. Confusion matrix (live, with baseline context)
# ---------------------------------------------------------------------------


def chart_confusion(live_arms: list[dict[str, Any]], rows_path: Path) -> Path:
    arm_name = live_arms[0]["arm"]
    if rows_path.suffix == ".jsonl":
        rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    else:
        rows = json.loads(rows_path.read_text())
    sel = [
        r
        for r in rows
        if r["arm"] == arm_name and r["condition"] == "with_baseline" and r.get("predicted")
    ]
    classes = ["benign", "container_escape", "privilege_abuse", "cryptomining", "unknown"]
    matrix = [[0] * len(classes) for _ in classes]
    for r in sel:
        matrix[classes.index(r["truth"])][classes.index(r["predicted"])] += 1

    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    ax.grid(False)
    ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max(max(row) for row in matrix))
    ax.set_xticks(range(len(classes)), [c.replace("_", "\n") for c in classes], fontsize=9)
    ax.set_yticks(range(len(classes)), classes, fontsize=9)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    for i in range(len(classes)):
        for j in range(len(classes)):
            v = matrix[i][j]
            ax.text(
                j,
                i,
                str(v),
                ha="center",
                va="center",
                fontsize=12,
                fontweight="bold" if i == j else "normal",
                color=PAPER if v > max(max(r) for r in matrix) * 0.55 else INK,
            )
    _finish(
        fig,
        FIGS / "fig_confusion.png",
        f"Live confusion matrix ({arm_name}, baseline context ON)",
        "Diagonal = correct class; off-diagonal = misclassification",
    )
    return FIGS / "fig_confusion.png"


# ---------------------------------------------------------------------------
# 8. Literature landscape positioning
# ---------------------------------------------------------------------------


def chart_landscape(lit: list[dict[str, Any]]) -> Path:
    """Capability matrix: literature approaches vs RuntimeLens."""
    approaches = [
        ("Falco / Tetragon / Tracee\n(eBPF rules)", [1, 0, 0, 0, 0], MUTED),
        ("Classical ML on K8s logs\n(Random Forest)", [1, 0, 1, 0, 0], AMBER),
        ("LLM triage / SOC agents\n(2024-2026)", [1, 1, 0, 1, 0], BLUE),
        ("RuntimeLens\n(this work)", [1, 1, 1, 1, 1], VIOLET),
    ]
    caps = [
        "eBPF-level\nruntime telemetry",
        "Declarative\nworkload baselines",
        "Multi-source\ntemporal fusion",
        "Typed-decision\nLLM classifier",
        "Hash-chained audit\n+ auto-rollback",
    ]
    fig, ax = plt.subplots(figsize=(9.6, 4.2))
    ax.grid(False)
    ax.set_xlim(-0.6, len(caps) - 0.4)
    ax.set_ylim(-0.6, len(approaches) - 0.4)
    for i, (_name, vals, color) in enumerate(approaches):
        for j, v in enumerate(vals):
            ax.add_patch(
                FancyBboxPatch(
                    (j - 0.38, i - 0.36),
                    0.76,
                    0.72,
                    boxstyle="round,pad=0.02,rounding_size=0.08",
                    facecolor=color if v else "#F1F5F9",
                    edgecolor=PAPER,
                    linewidth=1.6,
                    zorder=3,
                )
            )
            ax.text(
                j,
                i,
                "YES" if v else "no",
                ha="center",
                va="center",
                fontsize=9.5,
                fontweight="bold",
                color=PAPER if v else MUTED,
                zorder=4,
            )
    ax.set_xticks(range(len(caps)), caps, fontsize=9)
    ax.set_yticks(range(len(approaches)), [a[0] for a in approaches], fontsize=9.5)
    ax.tick_params(length=0)
    for side in ax.spines.values():
        side.set_visible(False)
    _finish(
        fig,
        FIGS / "fig_landscape.png",
        "Capability landscape: what each class of approach covers",
        "Filled = capability present in the cited representative systems",
    )
    return FIGS / "fig_landscape.png"


def main() -> None:
    FIGS.mkdir(parents=True, exist_ok=True)
    live_arms: list[dict[str, Any]] = []
    ab_rows_path: Path | None = None

    # Prefer the post-hoc statistical analysis, which carries the mid-p McNemar,
    # per-class tests and the benign-FPR bootstrap.
    analysis = RESULTS / "live_analysis.json"
    if analysis.exists():
        data = json.loads(analysis.read_text())
        if data.get("arms"):
            live_arms = data["arms"]
    if not live_arms:
        for f in sorted(RESULTS.glob("summary_*.json")):
            data = json.loads(f.read_text())
            if data.get("paired_ab"):
                live_arms = data["paired_ab"]
                break
    if not live_arms:
        for f in sorted(RESULTS.glob("ab_analysis_*.json")):
            live_arms = json.loads(f.read_text())
            if live_arms:
                break
    aggregate_path = RESULTS / "adversarial_aggregate.json"
    if aggregate_path.exists():
        aggregate = json.loads(aggregate_path.read_text())
    else:
        aggregate = {"arms": [], "repetitions": 0}
    for f in sorted(RESULTS.glob("ab_rows_*.jsonl")):
        ab_rows_path = f
    if ab_rows_path is None:
        for f in sorted(RESULTS.glob("ab_rows_*.json")):
            ab_rows_path = f
            break

    chart_model_comparison(live_arms)
    chart_ablations()
    chart_latency()
    chart_dataset()
    chart_asr(aggregate)
    if live_arms:
        chart_live_ab(live_arms)
        if ab_rows_path:
            chart_confusion(live_arms, ab_rows_path)


if __name__ == "__main__":
    main()
