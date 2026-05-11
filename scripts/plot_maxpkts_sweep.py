#!/usr/bin/env python3
"""
plot_maxpkts_sweep.py — Plot FPR/Recall/F1 vs max_packets after Phase 3a sweep.

Reads:  results/xgboost/sweep_maxpkts/summary.csv
Writes: results/xgboost/sweep_maxpkts/curve.png
        results/xgboost/sweep_maxpkts/table.txt

If the CSV contains multiple threshold values (Phase 3b 2D sweep), also
produces results/xgboost/sweep_maxpkts/heatmap.png via seaborn.
"""

from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT    = Path(__file__).resolve().parent.parent
SWEEP   = ROOT / "results/xgboost/sweep_maxpkts"
CSV     = SWEEP / "summary.csv"
OUT_PNG = SWEEP / "curve.png"
OUT_HM  = SWEEP / "heatmap.png"
OUT_TXT = SWEEP / "table.txt"

FPR_TARGET   = 0.01
RECALL_FLOOR = 0.99
F1_FLOOR     = 0.96
PREC_FLOOR   = 0.92


def load(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df.sort_values(["threshold", "max_packets"]).reset_index(drop=True)
    for col in ("fpr", "recall", "f1", "precision"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def find_best(df: pd.DataFrame):
    mask = (
        (df["fpr"]       < FPR_TARGET)   &
        (df["recall"]    >= RECALL_FLOOR) &
        (df["precision"] >= PREC_FLOOR)   &
        (df["f1"]        >= F1_FLOOR)
    )
    candidates = df[mask]
    if candidates.empty:
        return None
    # prefer lowest FPR among candidates, then lowest max_packets (simpler model)
    return candidates.sort_values(["fpr", "max_packets"]).iloc[0]


def make_table(df: pd.DataFrame, best_row) -> str:
    lines = []
    header = (f"{'thresh':>7}  {'mp':>3}  {'TP':>7}  {'TN':>7}  {'FP':>7}  {'FN':>5}  "
              f"{'Prec':>6}  {'Recall':>7}  {'F1':>6}  {'FPR':>7}  {'OK?':>5}")
    lines.append(header)
    lines.append("─" * len(header))
    for _, row in df.iterrows():
        ok = (
            row["fpr"]       < FPR_TARGET   and
            row["recall"]    >= RECALL_FLOOR and
            row["precision"] >= PREC_FLOOR   and
            row["f1"]        >= F1_FLOOR
        )
        mark = "✓" if ok else "✗"
        lines.append(
            f"{row['threshold']:>7.2f}  {int(row['max_packets']):>3}  "
            f"{int(row['tp']):>7}  {int(row['tn']):>7}  {int(row['fp']):>7}  {int(row['fn']):>5}  "
            f"{row['precision']:>6.4f}  {row['recall']:>7.4f}  {row['f1']:>6.4f}  "
            f"{row['fpr']:>7.4f}  {mark:>5}"
        )
    lines.append("")
    if best_row is not None:
        lines.append(
            f"Best: threshold={best_row['threshold']:.2f}  max_packets={int(best_row['max_packets'])}  "
            f"FPR={best_row['fpr']:.4f}  Recall={best_row['recall']:.4f}  "
            f"Precision={best_row['precision']:.4f}  F1={best_row['f1']:.4f}"
        )
        lines.append("Decision: Target FPR < 0.01 HIT → proceed to task 05-final-eval.")
    else:
        lines.append("Decision: Target FPR < 0.01 NOT hit by threshold + max_packets alone.")
        sub = df[df["recall"] >= RECALL_FLOOR]
        if not sub.empty:
            row = sub.sort_values("fpr").iloc[0]
            lines.append(
                f"Best FPR with Recall≥0.99: {row['fpr']:.4f}  "
                f"threshold={row['threshold']:.2f}  max_packets={int(row['max_packets'])}"
            )
        lines.append("→ Proceed to task 04 (post-filter or calibration).")
    return "\n".join(lines)


def plot_curve(df: pd.DataFrame, best_row, out_path: Path):
    # If multiple thresholds, plot each as a separate line; otherwise single line.
    thresholds = sorted(df["threshold"].unique())

    fig, ax1 = plt.subplots(figsize=(11, 6))
    ax2 = ax1.twinx()

    colors_fpr  = ["#d62728", "#e07070", "#f0b0b0"]
    colors_rec  = ["#1f77b4", "#6ab0e0", "#b0d8f0"]
    colors_f1   = ["#2ca02c", "#7acc7a", "#b8e8b8"]

    for i, t in enumerate(thresholds):
        sub = df[df["threshold"] == t].sort_values("max_packets")
        ci  = min(i, 2)
        lbl = f"t={t:.2f}"
        ax1.plot(sub.max_packets, sub.fpr, "-o", color=colors_fpr[ci],
                 linewidth=2, markersize=7, label=f"FPR ({lbl})")
        ax2.plot(sub.max_packets, sub.recall, "-s", color=colors_rec[ci],
                 linewidth=2, markersize=7, label=f"Recall ({lbl})")
        ax2.plot(sub.max_packets, sub.f1, "-^", color=colors_f1[ci],
                 linewidth=2, markersize=7, label=f"F1 ({lbl})")

    ax1.axhline(FPR_TARGET,   color="#d62728", linestyle="--", alpha=0.4,
                linewidth=1.2, label=f"FPR target={FPR_TARGET}")
    ax2.axhline(RECALL_FLOOR, color="#1f77b4", linestyle="--", alpha=0.35, linewidth=1.0)
    ax2.axhline(F1_FLOOR,     color="#2ca02c", linestyle="--", alpha=0.35, linewidth=1.0)

    if best_row is not None:
        ax1.axvline(best_row["max_packets"], color="gray", linestyle=":",
                    linewidth=1.5, label=f"Best mp={int(best_row['max_packets'])}")

    ax1.set_xlabel("max_packets", fontsize=12)
    ax1.set_ylabel("FPR", color="#d62728", fontsize=12)
    ax1.tick_params(axis="y", labelcolor="#d62728")
    ax1.set_ylim(bottom=0)
    ax2.set_ylabel("Recall / F1", color="#333333", fontsize=12)
    ax2.set_ylim(0.88, 1.005)

    all_mp = sorted(df["max_packets"].unique())
    ax1.set_xticks(all_mp)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc="center left", fontsize=9)

    ax1.set_title(
        f"Wednesday PCAP — FPR / Recall / F1 vs max_packets (threshold={thresholds[0]:.2f})",
        fontsize=12, fontweight="bold"
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    print(f"Saved: {out_path}")


def plot_heatmap(df: pd.DataFrame, out_path: Path):
    try:
        import seaborn as sns
    except ImportError:
        print("seaborn not installed — skipping heatmap.")
        return
    if df["threshold"].nunique() < 2:
        return  # heatmap only meaningful for 2D sweep

    fpr_pivot = df.pivot(index="max_packets", columns="threshold", values="fpr")
    rec_pivot = df.pivot(index="max_packets", columns="threshold", values="recall")

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    sns.heatmap(fpr_pivot, annot=True, fmt=".4f", cmap="Reds_r", ax=axes[0])
    axes[0].set_title("FPR (lower = better)")
    sns.heatmap(rec_pivot, annot=True, fmt=".4f", cmap="Greens", ax=axes[1])
    axes[1].set_title("Recall (higher = better)")
    plt.tight_layout()
    fig.savefig(out_path, dpi=120)
    print(f"Saved: {out_path}")


def main():
    df = load(CSV)
    best = find_best(df)
    table = make_table(df, best)

    print(table)
    OUT_TXT.write_text(table, encoding="utf-8")
    print(f"Saved: {OUT_TXT}")

    plot_curve(df, best, OUT_PNG)
    plot_heatmap(df, OUT_HM)


if __name__ == "__main__":
    main()
