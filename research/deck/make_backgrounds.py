"""Generate light-theme background assets for the RuntimeLens deck.

Geometry is drawn in figure inches. The figure is 19.2 x 10.8, the slide is
13.333 x 7.5, so one slide inch is 1.44 figure inches. Art is kept right of
figure x = 12.0 (slide x 8.33) so it never runs under the title column.

Run with:

    uv run python research/deck/make_backgrounds.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Circle, FancyBboxPatch, Polygon

ASSETS = Path(__file__).resolve().parent / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

BG_TOP = "#F7FAFD"
BG_BOT = "#E2EAF5"
CLOUD = "#D8E6F4"
CLOUD_EDGE = "#0F5E8E"
STEEL = "#0F5E8E"
SKY = "#1B8FD6"
TEAL = "#1296B8"
LINE = "#C3D2E2"

SLIDE_IN = 13.333 / 19.2  # slide inches per figure inch


def _wash(ax, top=BG_TOP, bot=BG_BOT, n=900):
    """Opaque vertical wash drawn as an image, so there are no band seams."""
    t = np.linspace(0.0, 1.0, n)[:, None]
    top_rgb = np.array(matplotlib.colors.to_rgb(top))
    bot_rgb = np.array(matplotlib.colors.to_rgb(bot))
    grad = top_rgb[None, None, :] * (1 - t[:, :, None]) + bot_rgb[None, None, :] * t[:, :, None]
    grad = np.repeat(grad, 8, axis=1)
    ax.imshow(grad, extent=(0, 19.2, 0, 10.8), origin="upper", aspect="auto", zorder=0)


def _hex(cx, cy, r):
    return [
        (cx + r * np.cos(np.radians(a)), cy + r * np.sin(np.radians(a))) for a in range(0, 360, 60)
    ]


def _dots(ax, x0, y0, cols, rows, step, color=STEEL, alpha=0.16, r=0.02):
    for row in range(rows):
        for col in range(cols):
            ax.add_patch(
                Circle(
                    (x0 + col * step, y0 + row * step),
                    r,
                    facecolor=color,
                    alpha=alpha,
                    zorder=1,
                )
            )


def _cloud_path(ax, cx, cy, scale):
    """Contour of the union of four lobes, returned as an (n, 2) polygon."""
    lobes = [(-1.28, 0.02, 0.78), (-0.42, 0.42, 0.98), (0.48, 0.30, 0.92), (1.10, -0.02, 0.66)]
    lobes = [(cx + lx * scale, cy + ly * scale, lr * scale) for lx, ly, lr in lobes]

    xs = np.linspace(cx - 2.4 * scale, cx + 2.2 * scale, 700)
    ys = np.linspace(cy - 1.0 * scale, cy + 1.6 * scale, 500)
    gx, gy = np.meshgrid(xs, ys)
    mask = np.zeros_like(gx, dtype=np.float64)
    for ox, oy, r in lobes:
        mask += ((gx - ox) ** 2 + (gy - oy) ** 2 <= r**2).astype(np.float64)

    cs = ax.contour(gx, gy, mask, levels=[0.5], colors="none")
    seg = max(cs.allsegs[0], key=len)
    cs.remove()
    return seg, lobes


def _cloud_network(ax, cx, cy, scale):
    """A cloud silhouette built from nodes, sitting behind the hero type."""
    poly, lobes = _cloud_path(ax, cx, cy, scale)

    ax.add_patch(
        Polygon(
            poly,
            closed=True,
            facecolor=CLOUD,
            edgecolor=CLOUD_EDGE,
            linewidth=2.0,
            alpha=0.92,
            zorder=2,
        )
    )

    # evenly spaced rim nodes, walking the silhouette by arc length
    closed = np.vstack([poly, poly[0]])
    seglen = np.hypot(*np.diff(closed, axis=0).T)
    cum = np.concatenate([[0], np.cumsum(seglen)])
    want = np.linspace(0, cum[-1], 10, endpoint=False)
    rim = []
    for w in want:
        i = int(np.searchsorted(cum, w, side="right") - 1)
        i = min(i, len(poly) - 1)
        rim.append(tuple(closed[i]))

    inner_frac = [
        (-0.72, 0.12),
        (-0.18, 0.55),
        (0.42, 0.32),
        (0.98, 0.02),
        (-0.30, -0.12),
        (0.26, -0.08),
        (0.78, -0.22),
    ]
    inner = [(cx + p[0] * scale, cy + p[1] * scale) for p in inner_frac]

    links = [(0, 1), (1, 2), (2, 3), (4, 5), (5, 6), (1, 5), (2, 6), (0, 4)]
    for i, j in links:
        ax.plot(
            [inner[i][0], inner[j][0]],
            [inner[i][1], inner[j][1]],
            color=STEEL,
            linewidth=1.1,
            alpha=0.4,
            zorder=3,
        )
    for i, (x, y) in enumerate(inner):
        ax.plot(
            [x, rim[(i * 2 + 1) % len(rim)][0]],
            [y, rim[(i * 2 + 1) % len(rim)][1]],
            color=STEEL,
            linewidth=0.9,
            alpha=0.28,
            zorder=3,
        )

    for x, y in inner:
        ax.add_patch(
            Circle((x, y), 0.085, facecolor="#FFFFFF", edgecolor=STEEL, linewidth=1.5, zorder=5)
        )
        ax.add_patch(Circle((x, y), 0.036, facecolor=SKY, zorder=6))
    for x, y in rim:
        ax.add_patch(
            Circle((x, y), 0.1, facecolor="#FFFFFF", edgecolor=STEEL, linewidth=1.6, zorder=5)
        )
        ax.add_patch(Circle((x, y), 0.042, facecolor=STEEL, zorder=6))


def hero():
    fig = plt.figure(figsize=(19.2, 10.8), dpi=100, facecolor=BG_TOP)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 19.2)
    ax.set_ylim(0, 10.8)
    ax.set_axis_off()
    _wash(ax)

    _dots(ax, 1.5, 0.9, 12, 8, 0.42, alpha=0.13, r=0.019)

    _cloud_network(ax, 15.35, 5.85, 2.15)

    for cx, cy, r in [(12.5, 8.3, 0.46), (18.55, 3.5, 0.4), (18.95, 9.0, 0.28)]:
        ax.add_patch(
            Polygon(
                _hex(cx, cy, r),
                closed=True,
                fill=False,
                edgecolor=SKY,
                linewidth=1.5,
                alpha=0.6,
                zorder=2,
            )
        )

    for x in (14.85, 16.05, 17.25):
        ax.add_patch(
            FancyBboxPatch(
                (x, 1.35),
                0.8,
                1.9,
                boxstyle="round,pad=0.03,rounding_size=0.16",
                facecolor="#DCE8F4",
                edgecolor=STEEL,
                linewidth=1.5,
                alpha=0.9,
                zorder=3,
            )
        )
        for j in range(3):
            ax.add_patch(
                Circle((x + 0.2, 1.7 + j * 0.52), 0.062, facecolor=STEEL, alpha=0.75, zorder=4)
            )

    fig.savefig(ASSETS / "bg_hero.png", facecolor=BG_TOP)
    plt.close(fig)
    print("wrote bg_hero.png")


def closing():
    fig = plt.figure(figsize=(19.2, 10.8), dpi=100, facecolor=BG_TOP)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 19.2)
    ax.set_ylim(0, 10.8)
    ax.set_axis_off()
    _wash(ax)

    # ring motif sweeping the top-right corner, clear of the text column
    cx, cy = 22.9, 8.6
    for i, r in enumerate([2.1, 2.9, 3.7, 4.5, 5.3]):
        ax.add_patch(
            Circle(
                (cx, cy),
                r,
                fill=False,
                edgecolor=STEEL if i % 2 == 0 else SKY,
                linewidth=2.2 if i == 0 else 1.6,
                alpha=0.42,
                zorder=1,
            )
        )
    ax.add_patch(Circle((cx, cy), 0.45, facecolor=STEEL, alpha=0.85, zorder=2))

    _dots(ax, 1.2, 0.9, 9, 6, 0.4, alpha=0.12, r=0.018)

    for hx, hy, r in [(17.2, 1.25, 0.36), (18.9, 2.5, 0.28), (16.1, 0.85, 0.24)]:
        ax.add_patch(
            Polygon(
                _hex(hx, hy, r),
                closed=True,
                fill=False,
                edgecolor=TEAL,
                linewidth=1.5,
                alpha=0.45,
                zorder=2,
            )
        )

    fig.savefig(ASSETS / "bg_closing.png", facecolor=BG_TOP)
    plt.close(fig)
    print("wrote bg_closing.png")


def soft():
    fig = plt.figure(figsize=(6.4, 3.6), dpi=100, facecolor="#F0F5FB")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 64)
    ax.set_ylim(0, 36)
    ax.set_axis_off()
    _dots(ax, 1.8, 1.8, 30, 17, 2.05, color="#C9D7E8", alpha=0.5, r=0.05)
    fig.savefig(ASSETS / "bg_soft.png", facecolor="#F0F5FB")
    plt.close(fig)
    print("wrote bg_soft.png")


def panel():
    fig = plt.figure(figsize=(5.4, 9.0), dpi=100, facecolor="#E7EDF5")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 54)
    ax.set_ylim(0, 90)
    ax.set_axis_off()
    r = 5.4
    for row in range(17):
        for col in range(11):
            cx = r * 1.7 + col * r * 2.68 + (row % 2) * r * 1.34
            cy = r * 1.9 + row * r * 2.5
            ax.add_patch(
                Polygon(
                    _hex(cx, cy, r),
                    closed=True,
                    fill=False,
                    edgecolor="#C3D2E2",
                    linewidth=1.15,
                    alpha=0.55,
                    zorder=1,
                )
            )
    fig.savefig(ASSETS / "bg_panel.png", facecolor="#E7EDF5")
    plt.close(fig)
    print("wrote bg_panel.png")


if __name__ == "__main__":
    hero()
    closing()
    soft()
    panel()
