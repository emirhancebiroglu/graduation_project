"""
H1 Step 1 — Build Wednesday-aware fine-tune cohort.

Sources:
  - BENIGN swin cohort: Tuesday + Thursday CSVs, swin ∈ [200, 270], weight=3.0
  - DoS attacks:        Wednesday CSV, labels in DOS_LABELS, up to 55k rows, weight=1.0

Outputs:
  results/xgboost/fpr-v2/H1/cohort_stats.txt
  results/xgboost/fpr-v2/H1/cohort_X.npy   (log1p applied, pre-scaling)
  results/xgboost/fpr-v2/H1/cohort_y.npy
  results/xgboost/fpr-v2/H1/cohort_w.npy   (sample weights)
"""

import numpy as np
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CIC_DIR = ROOT / "data" / "raw" / "cicids2017"
OUT_DIR = ROOT / "results" / "xgboost" / "fpr-v2" / "H1"
OUT_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_MAP = {
    'Flow Duration':                'dur',
    'Total Fwd Packets':            'spkts',
    'Total Backward Packets':       'dpkts',
    'Total Length of Fwd Packets':  'sbytes',
    'Total Length of Bwd Packets':  'dbytes',
    'Fwd Packet Length Mean':       'smeansz',
    'Bwd Packet Length Mean':       'dmeansz',
    'Init_Win_bytes_forward':       'swin',
    'Init_Win_bytes_backward':      'dwin',
    'Fwd IAT Mean':                 'sintpkt',
    'Bwd IAT Mean':                 'dintpkt',
}
FEATURE_ORDER = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
                 'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt']
LOG_COLS = ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt', 'dintpkt']

SWIN_LO, SWIN_HI = 200, 270
MAX_ATTACK_ROWS = 55_000
SWIN_WEIGHT = 3.0
ATTACK_WEIGHT = 1.0

TUE_THU_FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
]
WED_FILE = "Wednesday-workingHours.pcap_ISCX.csv"

DOS_LABELS = {"DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "Heartbleed"}


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False, on_bad_lines='skip', encoding='latin-1')
    df.columns = df.columns.str.strip()
    required = list(FEATURE_MAP.keys()) + ['Label']
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{path.name}: missing columns {missing}")
    df = df[required].copy()
    df.rename(columns=FEATURE_MAP, inplace=True)
    df['label'] = df['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
    df['_raw_label'] = df['Label'].str.strip()
    df.drop(columns=['Label'], inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=FEATURE_ORDER, inplace=True)
    df['dur'] = df['dur'] / 1e6
    df['sintpkt'] = df['sintpkt'] / 1000.0
    df['dintpkt'] = df['dintpkt'] / 1000.0
    return df


def main():
    # ── BENIGN swin cohort from Tue+Thu ──────────────────────────────────────
    frames = []
    for fname in TUE_THU_FILES:
        p = CIC_DIR / fname
        if not p.exists():
            print(f"WARNING: {fname} not found, skipping")
            continue
        print(f"Loading {fname}...")
        frames.append(load_csv(p))

    if not frames:
        raise RuntimeError("No Tue/Thu source CSVs found")

    df_tuethu = pd.concat(frames, ignore_index=True)
    print(f"Total rows loaded (Tue+Thu): {len(df_tuethu):,}")

    swin_cohort = df_tuethu[
        (df_tuethu['label'] == 0) &
        (df_tuethu['swin'] >= SWIN_LO) &
        (df_tuethu['swin'] <= SWIN_HI)
    ].copy()
    swin_cohort['_weight'] = SWIN_WEIGHT

    swin_vals = swin_cohort['swin']
    print(f"\nswin cohort (BENIGN, swin∈[{SWIN_LO},{SWIN_HI}]): {len(swin_cohort):,} rows")

    # ── DoS attack rows from Wednesday ────────────────────────────────────────
    wed_path = CIC_DIR / WED_FILE
    print(f"\nLoading {WED_FILE}...")
    df_wed = load_csv(wed_path)
    print(f"Total rows loaded (Wednesday): {len(df_wed):,}")

    attack_all = df_wed[df_wed['_raw_label'].isin(DOS_LABELS)].copy()
    print(f"Wednesday DoS rows before sampling: {len(attack_all):,}")
    print(f"  Label breakdown:")
    for lbl, cnt in attack_all['_raw_label'].value_counts().items():
        print(f"    {lbl}: {cnt:,}")

    attack_cohort = attack_all.sample(
        n=min(MAX_ATTACK_ROWS, len(attack_all)), random_state=42
    ).copy()
    attack_cohort['_weight'] = ATTACK_WEIGHT

    # ── assemble final dataset ────────────────────────────────────────────────
    combined = pd.concat([swin_cohort, attack_cohort], ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # apply log1p before saving (same standard as fine_tune pipeline)
    for col in LOG_COLS:
        combined[col] = np.log1p(combined[col])

    X = combined[FEATURE_ORDER].values.astype(np.float32)
    y = combined['label'].values.astype(np.int32)
    w = combined['_weight'].values.astype(np.float32)

    # ── print final composition ───────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("FINAL DATASET COMPOSITION (before fit)")
    print("=" * 55)
    print(f"{'Segment':<40} {'Rows':>8}  {'Weight':>6}")
    print(f"  swin BENIGN cohort (Tue+Thu, swin 200-270)   {len(swin_cohort):>8,}   {SWIN_WEIGHT:>5.1f}x")
    print(f"  Wednesday DoS attacks (sampled)              {len(attack_cohort):>8,}   {ATTACK_WEIGHT:>5.1f}x")
    print(f"  {'TOTAL':<38} {len(combined):>8,}")
    print(f"\nLabel distribution:")
    print(f"  label=0 (BENIGN): {(y==0).sum():,}  ({100*(y==0).mean():.1f}%)")
    print(f"  label=1 (ATTACK): {(y==1).sum():,}  ({100*(y==1).mean():.1f}%)")
    print(f"\nWeight distribution:")
    print(f"  weight=3.0 rows: {(w==3.0).sum():,}")
    print(f"  weight=1.0 rows: {(w==1.0).sum():,}")
    print(f"\nswin distribution of BENIGN cohort (raw pre-log values):")
    print(f"  min={swin_vals.min():.0f}  p25={swin_vals.quantile(0.25):.0f}"
          f"  median={swin_vals.median():.0f}  p75={swin_vals.quantile(0.75):.0f}"
          f"  max={swin_vals.max():.0f}")

    value_counts = swin_vals.value_counts().sort_index()
    top10 = value_counts.head(10)
    print(f"\n  Top-10 swin values in BENIGN cohort:")
    for val, cnt in top10.items():
        print(f"    swin={val:>6.0f}: {cnt:>6,} flows")
    print("=" * 55)

    np.save(OUT_DIR / "cohort_X.npy", X)
    np.save(OUT_DIR / "cohort_y.npy", y)
    np.save(OUT_DIR / "cohort_w.npy", w)

    # ── write stats file ──────────────────────────────────────────────────────
    stats_lines = [
        "H1 Cohort Statistics (v2 — Wednesday DoS source)",
        "=" * 55,
        f"swin BENIGN cohort (Tue+Thu, swin [{SWIN_LO},{SWIN_HI}]): {len(swin_cohort):,}  weight={SWIN_WEIGHT}",
        f"Wednesday DoS attacks (sampled):                  {len(attack_cohort):,}  weight={ATTACK_WEIGHT}",
        f"Total rows:                                       {len(combined):,}",
        f"  label=0 (BENIGN): {(y==0).sum():,}  ({100*(y==0).mean():.1f}%)",
        f"  label=1 (ATTACK): {(y==1).sum():,}  ({100*(y==1).mean():.1f}%)",
        "",
        "swin distribution (BENIGN cohort, pre-log raw values):",
        f"  min={swin_vals.min():.0f}  p25={swin_vals.quantile(0.25):.0f}"
        f"  median={swin_vals.median():.0f}  p75={swin_vals.quantile(0.75):.0f}"
        f"  max={swin_vals.max():.0f}",
        "",
        "Wednesday DoS label breakdown:",
    ]
    for lbl, cnt in attack_all['_raw_label'].value_counts().items():
        stats_lines.append(f"  {lbl}: {cnt:,}")

    (OUT_DIR / "cohort_stats.txt").write_text("\n".join(stats_lines))
    print(f"\nSaved: cohort_X.npy {X.shape}, cohort_y.npy, cohort_w.npy")
    print("=== STEP 1 COMPLETE — awaiting approval before Step 2 fit() ===")


if __name__ == "__main__":
    main()
