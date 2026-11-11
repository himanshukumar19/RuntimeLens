"""Render the single-column architecture figure used by the IEEE paper.

Vertical band layout: a single 3.5-inch column reads top-to-bottom, which is
the only arrangement where every box label stays inside its box.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(parents=True, exist_ok=True)

INK = "#0B1220"
LINE = "#94A3B8"
BLUE = "#2D7FF9"
TEAL = "#12B5CB"
AMBER = "#EFA02E"
VIOLET = "#7B5CE7"
GREEN = "#00A97F"
GREY = "#64748B"

fig, ax = plt.subplots(figsize=(3.5, 5.2))
ax.set_xlim(0, 100)
ax.set_ylim(0, 122)
ax.axis("off")

BANDS = [
    ("Telemetry sources",
     ["Falco eBPF syscalls  ·  K8s audit log",
      "Hubble flows  ·  Prometheus  ·  Trivy"], BLUE),
    ("Normalise + correlate",
     ["Source normalisers  ·  secret redaction",
      "Temporal window ($\\pm$30 s) by ns + pod UID"], TEAL),
    ("Baseline engine",
     ["Git-versioned per-workload YAML profile",
      "Deterministic deviation list"], AMBER),
    ("Typed-decision classifier",
     ["choice (5 classes)  ·  score (severity 0-4)",
      "4 noul flags  ·  schema-constrained output"], VIOLET),
    ("Deterministic policy engine",
     ["Safety overrides  ·  conflict table",
      "Confidence $\\geq$0.70  ·  severity $\\geq$4.0"], GREEN),
    ("Response",
     ["log  ·  alert  ·  human review",
      "reversible quarantine + TTL rollback"], GREY),
]

X = 1.5
W = 97.0
BAND_H = 15.0
GAPY = 4.0
y = 116.0

for i, (title, items, color) in enumerate(BANDS):
    ax.add_patch(
        FancyBboxPatch((X, y - BAND_H), W, BAND_H,
                       boxstyle="round,pad=0.3,rounding_size=1.6",
                       facecolor="#F8FAFC", edgecolor=color, linewidth=1.0, zorder=2)
    )
    ax.add_patch(
        FancyBboxPatch((X + 1.4, y - 4.4), 2.6, 3.2,
                       boxstyle="round,pad=0.18,rounding_size=0.9",
                       facecolor=color, edgecolor=color, linewidth=0, zorder=3)
    )
    ax.text(X + 5.4, y - 2.8, title, ha="left", va="center", color=color,
            fontsize=6.0, fontweight="bold", zorder=4)
    for j, item in enumerate(items):
        ax.text(X + 5.4, y - 7.4 - j * 3.9, item, ha="left", va="center",
                color=INK, fontsize=5.0, zorder=4)
    if i < len(BANDS) - 1:
        ax.add_patch(
            FancyArrowPatch((X + W / 2, y - BAND_H - 0.2), (X + W / 2, y - BAND_H - GAPY + 0.4),
                            arrowstyle="-|>", mutation_scale=5, color=LINE, linewidth=0.9, zorder=1)
        )
    y -= BAND_H + GAPY

ax.add_patch(
    FancyBboxPatch((X, y - 8.0), W, 8.0,
                   boxstyle="round,pad=0.3,rounding_size=1.6",
                   facecolor="#F1F5F9", edgecolor=GREY, linewidth=1.0, zorder=2)
)
ax.text(X + W / 2, y - 4.0, "Audit: append-only JSONL, each record hashes the previous (SHA-256)",
        ha="center", va="center", color=INK, fontsize=4.8, zorder=4)

fig.tight_layout()
fig.savefig(OUT / "architecture.pdf", bbox_inches="tight", facecolor="white", pad_inches=0.02)
fig.savefig(OUT / "architecture.png", dpi=320, bbox_inches="tight", facecolor="white", pad_inches=0.02)
print("wrote", OUT / "architecture.pdf")
