#!/usr/bin/env python3
"""
plot_threshold_sweep.py — Plot FPR/Recall/F1 vs threshold after sweep.

Reads:  results/xgboost/sweep_threshold/summary.csv
Writes: results/xgboost/sweep_threshold/curve.png
        results/xgboost/sweep_threshold/table.txt   (human-readable table)
"""

from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT    = Path(__file__).resolve().parent.parent
SWEEP   = ROOT / "results/xgboost/sweep_threshold"
CSV     = SWEEP / "summary.csv"
OUT_PNG = SWEEP / "curve.png"
OUT_TXT = SWEEP / "table.txt"

# Floor lines for visual reference
FPR_TARGET    = 0.01
RECALL_FLOOR  = 0.99
F1_FLOOR      = 0.96
PREC_FLOOR    = 0.92


def load_and_validate(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df.sort_values("threshold").reset_index(drop=True)
    for col in ("fpr", "recall", "f1", "precision"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def find_best(df: pd.DataFrame) -> pd.Series | None:
    """Return the lowest threshold row that meets all four floors, or None."""
    mask = (
        (df["fpr"]       < FPR_TARGET)   &
        (df["recall"]    >= RECALL_FLOOR) &
        (df["precision"] >= PREC_FLOOR)   &
        (df["f1"]        >= F1_FLOOR)
    )
    candidates = df[mask]
    if candidates.empty:
        return None
    return candidates.iloc[0]   # already sorted ascending by threshold


def make_table(df: pd.DataFrame, best_row) -> str:
    lines = []
    header = f"{'thresh':>7}  {'mp':>3}  {'TP':>7}  {'TN':>7}  {'FP':>7}  {'FN':>5}  " \
             f"{'Prec':>6}  {'Recall':>7}  {'F1':>6}  {'FPR':>7}  {'OK?':>5}"
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
        lines.append(f"Best threshold: {best_row['threshold']:.2f}  "
                     f"FPR={best_row['fpr']:.4f}  Recall={best_row['recall']:.4f}  "
                     f"Precision={best_row['precision']:.4f}  F1={best_row['f1']:.4f}")
        lines.append("Decision: Target FPR < 0.01 HIT → proceed to task 05-final-eval.")
    else:
        lines.append("Decision: Target FPR < 0.01 NOT hit by threshold alone.")
        # Find closest row
        sub = df[df["recall"] >= RECALL_FLOOR]
        if not sub.empty:
            best_fpr = sub.loc[sub["fpr"].idxmin()]
            lines.append(f"Best FPR with Recall≥0.99: {best_fpr['fpr']:.4f} at "
                         f"threshold={best_fpr['threshold']:.2f}")
    return "\n".join(lines)


def plot(df: pd.DataFrame, best_row, out_path: Path):
    fig, ax1 = plt.subplots(figsize=(11, 6))

    color_fpr    = "#d62728"
    color_recall = "#1f77b4"
    color_f1     = "#2ca02c"
    color_prec   = "#ff7f0e"

    ax1.plot(df.threshold, df.fpr, "-o", color=color_fpr,   linewidth=2, markersize=7, label="FPR")
    ax1.axhline(FPR_TARGET, color=color_fpr, linestyle="--", alpha=0.45, linewidth=1.2,
                label=f"FPR target = {FPR_TARGET}")
    ax1.set_xlabel("Threshold", fontsize=12)
    ax1.set_ylabel("FPR", color=color_fpr, fontsize=12)
    ax1.tick_params(axis="y", labelcolor=color_fpr)
    ax1.set_ylim(bottom=0)

    ax2 = ax1.twinx()
    ax2.plot(df.threshold, df.recall,    "-s", color=color_recall, linewidth=2, markersize=7, label="Recall")
    ax2.plot(df.threshold, df.f1,        "-^", color=color_f1,     linewidth=2, markersize=7, label="F1")
    ax2.plot(df.threshold, df.precision, "-D", color=color_prec,   linewidth=2, markersize=7, label="Precision")
    ax2.axhline(RECALL_FLOOR, color=color_recall, linestyle="--", alpha=0.40, linewidth=1.0)
    ax2.axhline(F1_FLOOR,     color=color_f1,     linestyle="--", alpha=0.40, linewidth=1.0)
    ax2.axhline(PREC_FLOOR,   color=color_prec,   linestyle="--", alpha=0.40, linewidth=1.0)
    ax2.set_ylabel("Recall / F1 / Precision", color="#333333", fontsize=12)
    ax2.set_ylim(0.88, 1.005)

    if best_row is not None:
        ax1.axvline(best_row["threshold"], color="gray", linestyle=":", linewidth=1.5,
                    label=f"Best t={best_row['threshold']:.2f}")

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc="center left", fontsize=9)

    ax1.set_title("Wednesday PCAP — FPR / Recall / F1 / Precision vs Threshold (max_packets=2)",
                  fontsize=12, fontweight="bold")
    ax1.set_xticks(df.threshold)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    print(f"Saved: {out_path}")


def main():
    df = load_and_validate(CSV)
    best = find_best(df)
    table = make_table(df, best)

    print(table)
    OUT_TXT.write_text(table, encoding="utf-8")
    print(f"Saved: {OUT_TXT}")

    plot(df, best, OUT_PNG)


if __name__ == "__main__":
    main()
