"""Post-hoc statistical analysis of the live typed-decision evaluation.

Reads the raw per-call rows produced by research/live_typed_decision_eval.py
and recomputes the full statistical protocol described in the paper:

  * macro-F1, per-class P/R/F1, accuracy, benign FPR (both conditions)
  * group-level paired bootstrap (B = 10,000) for the macro-F1 and FPR deltas
  * mid-p McNemar test on per-item correctness (Fagerland et al. 2013)
  * per-class one-vs-rest mid-p McNemar with Holm correction
  * FPR at fixed TPR and precision@K
  * confusion matrices

Usage:
    uv run python -m research.analyse_live_results
"""

from __future__ import annotations

import json
import math
import random
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "research" / "results"

CLASSES = ("benign", "container_escape", "privilege_abuse", "cryptomining", "unknown")


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def compute_metrics(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    per_class: dict[str, dict[str, float]] = {}
    for cls in CLASSES:
        tp = sum(1 for t, p in pairs if t == cls and p == cls)
        fp = sum(1 for t, p in pairs if t != cls and p == cls)
        fn = sum(1 for t, p in pairs if t == cls and p != cls)
        precision, recall, f1 = _prf(tp, fp, fn)
        per_class[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": tp + fn,
        }
    benign_total = sum(1 for t, _ in pairs if t == "benign")
    benign_fp = sum(1 for t, p in pairs if t == "benign" and p != "benign")
    return {
        "n": len(pairs),
        "accuracy": sum(1 for t, p in pairs if t == p) / len(pairs) if pairs else 0.0,
        "macro_f1": statistics.fmean(c["f1"] for c in per_class.values()),
        "benign_fpr": benign_fp / benign_total if benign_total else 0.0,
        "benign_recall": 1.0 - (benign_fp / benign_total if benign_total else 0.0),
        "per_class": per_class,
    }


def mcnemar_midp(b: int, c: int) -> dict[str, float]:
    """Mid-p McNemar test (Fagerland et al. 2013).

    b = A correct / B wrong, c = A wrong / B correct. The mid-p version
    corrects the exact conditional test's inflated type-I error at small
    discordant counts by adding half the probability at the observed tail.
    """
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n": 0, "p_value": 1.0}
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2**n)
    mid_p = tail - 0.5 * (math.comb(n, k) / (2**n))
    p = min(1.0, 2 * mid_p)
    return {"b": b, "c": c, "n": n, "p_value": p}


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni step-down adjusted p-values."""
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(items)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, (key, p) in enumerate(items):
        val = min(1.0, (m - i) * p)
        running = max(running, val)
        adjusted[key] = running
    return adjusted


def paired_bootstrap(
    ids: list[str],
    truth: dict[str, str],
    on: dict[str, str],
    off: dict[str, str],
    iterations: int = 10000,
    seed: int = 20261111,
) -> dict[str, Any]:
    rng = random.Random(seed)
    ids = sorted(ids)
    d_f1: list[float] = []
    d_fpr: list[float] = []
    d_acc: list[float] = []
    for _ in range(iterations):
        sample = [ids[rng.randrange(len(ids))] for _ in ids]
        ma = compute_metrics([(truth[i], on[i]) for i in sample])
        mb = compute_metrics([(truth[i], off[i]) for i in sample])
        d_f1.append(ma["macro_f1"] - mb["macro_f1"])
        d_fpr.append(ma["benign_fpr"] - mb["benign_fpr"])
        d_acc.append(ma["accuracy"] - mb["accuracy"])

    def ci(v: list[float]) -> dict[str, float]:
        s = sorted(v)
        lo = s[int(0.025 * len(s))]
        hi = s[min(len(s) - 1, int(0.975 * len(s)))]
        return {"lo": lo, "hi": hi, "mean": statistics.fmean(v)}

    def p_two(v: list[float]) -> float:
        return min(
            1.0, 2 * min(sum(1 for x in v if x <= 0) / len(v), sum(1 for x in v if x >= 0) / len(v))
        )

    return {
        "iterations": iterations,
        "seed": seed,
        "delta_macro_f1": {**ci(d_f1), "p_two_sided": p_two(d_f1)},
        "delta_benign_fpr": {**ci(d_fpr), "p_two_sided": p_two(d_fpr)},
        "delta_accuracy": {**ci(d_acc), "p_two_sided": p_two(d_acc)},
    }


def precision_at_k(scored: list[tuple[float, bool]], k: int) -> float:
    top = sorted(scored, key=lambda kv: kv[0], reverse=True)[:k]
    if not top:
        return 0.0
    return sum(1 for _, is_true in top if is_true) / len(top)


def fpr_at_tpr(scored: list[tuple[float, bool]], target_tpr: float) -> float:
    """FPR at the threshold that achieves at least target_tPR on the positives."""
    positives = [s for s in scored if s[1]]
    negatives = [s for s in scored if not s[1]]
    if not positives or not negatives:
        return 0.0
    best = (0.0, 0.0)
    for threshold in sorted({s[0] for s in scored}, reverse=True):
        tpr = sum(1 for s, t in positives if s >= threshold) / len(positives)
        fpr = sum(1 for s, t in negatives if s >= threshold) / len(negatives)
        if tpr >= target_tpr:
            if tpr > best[0] or (tpr == best[0] and fpr < best[1]):
                best = (tpr, fpr)
            break
    return best[1]


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------


def analyse(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"arms": []}
    for arm in sorted({r["arm"] for r in rows}):
        sel = [r for r in rows if r["arm"] == arm and r.get("predicted")]
        if not sel:
            continue
        truth = {r["incident_id"]: r["truth"] for r in sel}
        on = {r["incident_id"]: r["predicted"] for r in sel if r["condition"] == "with_baseline"}
        off = {
            r["incident_id"]: r["predicted"] for r in sel if r["condition"] == "without_baseline"
        }
        ids = sorted(set(on) & set(off))
        if len(ids) < 4:
            continue

        m_on = compute_metrics([(truth[i], on[i]) for i in ids])
        m_off = compute_metrics([(truth[i], off[i]) for i in ids])
        boot = paired_bootstrap(ids, truth, on, off)

        b = sum(1 for i in ids if on[i] == truth[i] and off[i] != truth[i])
        c = sum(1 for i in ids if on[i] != truth[i] and off[i] == truth[i])
        mc = mcnemar_midp(b, c)

        per_class_mc: dict[str, float] = {}
        for cls in CLASSES:
            pos = [i for i in ids if truth[i] == cls]
            if not pos:
                continue
            bb = sum(1 for i in pos if on[i] == cls and off[i] != cls)
            cc = sum(1 for i in pos if on[i] != cls and off[i] == cls)
            per_class_mc[cls] = mcnemar_midp(bb, cc)["p_value"]
        adjusted = holm(per_class_mc)

        lat = [r["latency_ms"] for r in sel if r.get("latency_ms")]
        conf_on = [
            r.get("confidence")
            for r in sel
            if r["condition"] == "with_baseline" and r.get("confidence") is not None
        ]

        # confidence-scored analysis for precision@K, using the "on" condition
        scored = [
            (float(r.get("confidence") or 0.0), r["truth"] == r["predicted"])
            for r in sel
            if r["condition"] == "with_baseline"
        ]
        attack_scored = [
            (float(r.get("confidence") or 0.0), r["truth"] != "benign")
            for r in sel
            if r["condition"] == "with_baseline" and r["truth"] != "benign"
        ]

        # The most operationally dangerous error in a security system: a real
        # attack dismissed as routine activity.
        attacks_benign_on = sum(1 for i in ids if truth[i] != "benign" and on[i] == "benign")
        attacks_benign_off = sum(1 for i in ids if truth[i] != "benign" and off[i] == "benign")
        confusion = {t: dict.fromkeys(CLASSES, 0) for t in CLASSES}
        for i in ids:
            confusion[truth[i]][on[i]] += 1

        out["arms"].append(
            {
                "arm": arm,
                "model": next(r["model"] for r in rows if r["arm"] == arm),
                "n_incidents": len(ids),
                "n_attacks": sum(1 for i in ids if truth[i] != "benign"),
                "n_calls": len(sel),
                "call_failures": sum(1 for r in rows if r["arm"] == arm and not r.get("predicted")),
                "with_baseline": m_on,
                "without_baseline": m_off,
                "delta_macro_f1": m_on["macro_f1"] - m_off["macro_f1"],
                "delta_benign_fpr": m_on["benign_fpr"] - m_off["benign_fpr"],
                "delta_accuracy": m_on["accuracy"] - m_off["accuracy"],
                "attacks_called_benign": {
                    "with_baseline": attacks_benign_on,
                    "without_baseline": attacks_benign_off,
                    "delta": attacks_benign_on - attacks_benign_off,
                },
                "paired_bootstrap": boot,
                "mcnemar_midp": mc,
                "per_class_mcnemar_raw_p": per_class_mc,
                "per_class_mcnemar_holm_p": adjusted,
                "precision_at_k": {str(k): precision_at_k(scored, k) for k in (5, 10, 25, 50)},
                "fpr_at_tpr": {str(t): fpr_at_tpr(attack_scored, t) for t in (0.90, 0.95)},
                "mean_confidence_with_baseline": statistics.fmean(conf_on) if conf_on else None,
                "latency_ms": {
                    "mean": statistics.fmean(lat) if lat else None,
                    "median": statistics.median(lat) if lat else None,
                    "min": min(lat) if lat else None,
                    "max": max(lat) if lat else None,
                },
                "confusion_with_baseline": confusion,
            }
        )
    return out


def markdown(out: dict[str, Any]) -> str:
    lines = ["# Live typed-decision evaluation — statistical summary", ""]
    for a in out["arms"]:
        boot = a["paired_bootstrap"]["delta_macro_f1"]
        fpr_boot = a["paired_bootstrap"]["delta_benign_fpr"]
        mc = a["mcnemar_midp"]
        lines += [
            f"## {a['arm']}  (`{a['model']}`)",
            "",
            f"- incidents: {a['n_incidents']} paired, {a['n_calls']} live calls, "
            f"{a['call_failures']} failed calls",
            f"- macro-F1 with baseline: {a['with_baseline']['macro_f1']:.4f}  "
            f"without: {a['without_baseline']['macro_f1']:.4f}",
            f"- delta macro-F1: {a['delta_macro_f1']:+.4f} "
            f"(95% CI [{boot['lo']:+.4f}, {boot['hi']:+.4f}], p={boot['p_two_sided']:.4f})",
            f"- delta benign FPR: {a['delta_benign_fpr']:+.4f} "
            f"(95% CI [{fpr_boot['lo']:+.4f}, {fpr_boot['hi']:+.4f}], "
            f"p={fpr_boot['p_two_sided']:.4f})",
            f"- delta accuracy: {a['delta_accuracy']:+.4f}",
            f"- mid-p McNemar on item correctness: b={mc['b']} c={mc['c']} p={mc['p_value']:.4f}",
            "- per-class McNemar (Holm adjusted): "
            + ", ".join(f"{k}={v:.4f}" for k, v in a["per_class_mcnemar_holm_p"].items()),
            f"- attacks misread as benign: "
            f"{a['attacks_called_benign']['with_baseline']} with baseline vs "
            f"{a['attacks_called_benign']['without_baseline']} without "
            f"(of {a['n_attacks']} attacks)",
            "- precision@K: " + ", ".join(f"@{k}={v:.3f}" for k, v in a["precision_at_k"].items()),
            "- FPR at TPR: " + ", ".join(f"tpr{t}={v:.3f}" for t, v in a["fpr_at_tpr"].items()),
            f"- latency ms: median {a['latency_ms']['median']}, "
            f"mean {a['latency_ms']['mean']:.0f}, "
            f"max {a['latency_ms']['max']:.0f}",
            "",
            "### per-class F1 (with baseline)",
            "",
            "| class | precision | recall | F1 | support |",
            "|---|---|---|---|---|",
        ]
        for cls, v in a["with_baseline"]["per_class"].items():
            lines.append(
                f"| {cls} | {v['precision']:.3f} | {v['recall']:.3f} | "
                f"{v['f1']:.3f} | {v['support']} |"
            )
        lines.append("")
    return "\n".join(lines)


def _load_rows() -> tuple[list[dict[str, Any]], str]:
    """Load the newest paired-A/B rows, preferring the incrementally written JSONL."""
    jsonl = sorted(RESULTS.glob("ab_rows_*.jsonl"))
    payload = sorted(RESULTS.glob("ab_rows_*.json"))
    if jsonl:
        rows = []
        with jsonl[-1].open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        if rows:
            return rows, jsonl[-1].name
    if payload:
        return json.loads(payload[-1].read_text()), payload[-1].name
    return [], ""


def main() -> int:
    rows, source = _load_rows()
    if not rows:
        print("no ab_rows found")
        return 1
    out = analyse(rows)
    out["source_rows"] = source
    (RESULTS / "live_analysis.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    md = markdown(out)
    (RESULTS / "live_analysis.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
