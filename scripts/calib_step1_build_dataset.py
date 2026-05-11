#!/usr/bin/env python3
"""
calib_step1_build_dataset.py — Build calibration dataset from Tuesday + Thursday CSVs.

Applies the exact same preprocessing pipeline as xgb_inspector.cc / flow_tracker.h:
  1. Map CIC columns → 11 inspector features with unit conversions
  2. swin/dwin: clamp negatives to 0 (matching compute_features() in flow_tracker.h)
  3. log1p on: dur, spkts, dpkts, sbytes, dbytes, sintpkt, dintpkt
  4. RobustScaler with HARDCODED median/IQR from g_scaler_params in xgb_inspector.cc
     (NOT scaler.pkl — must match C++ exactly)

Output: results/xgboost/calibration/calib_dataset.csv  (raw_score, true_label)
"""

from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb

REPO       = Path(__file__).resolve().parent.parent
MODEL_FILE = REPO / "models/fine_tuned_xgb_model.json"
OUT_DIR    = REPO / "results/xgboost/calibration"
OUT_CSV    = OUT_DIR / "calib_dataset.csv"

CALIB_CSVS = [
    REPO / "data/raw/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv",
    REPO / "data/raw/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    REPO / "data/raw/cicids2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
]

# ── Exact g_scaler_params from xgb_inspector.cc ──────────────────────────────
#   Order: dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz, swin, dwin, sintpkt, dintpkt
MEDIAN = np.array([
    0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206, 7.5071410797,
    73.0, 89.0, 255.0, 255.0, 0.3841277437, 0.3471507323
])
IQR = np.array([
    0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192, 4.4213950593,
    72.0, 496.0, 255.0, 255.0, 2.1157851784, 1.9696133626
])

# Indices where log1p is applied (matching xgb_needs_log1p() in flow_tracker.h)
# XGB_FI_DUR=0, SPKTS=1, DPKTS=2, SBYTES=3, DBYTES=4, SINTPKT=9, DINTPKT=10
LOG1P_IDX = [0, 1, 2, 3, 4, 9, 10]

# ── CIC column → (inspector_name, scale_factor) ──────────────────────────────
# scale_factor: CIC units → inspector units before log1p/scaling
CIC_COL_MAP = {
    # CIC column name (stripped)  : (feat_idx, scale)
    'Flow Duration'               : (0,  1e-6),   # µs → s
    'Total Fwd Packets'           : (1,  1.0),
    'Total Backward Packets'      : (2,  1.0),
    'Total Length of Fwd Packets' : (3,  1.0),
    'Total Length of Bwd Packets' : (4,  1.0),
    'Fwd Packet Length Mean'      : (5,  1.0),
    'Bwd Packet Length Mean'      : (6,  1.0),
    'Init_Win_bytes_forward'      : (7,  1.0),    # swin
    'Init_Win_bytes_backward'     : (8,  1.0),    # dwin
    'Fwd IAT Mean'                : (9,  1e-3),   # µs → ms
    'Bwd IAT Mean'                : (10, 1e-3),   # µs → ms
}

FEAT_NAMES = ['dur','spkts','dpkts','sbytes','dbytes',
              'smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']


def extract_features(df: pd.DataFrame) -> np.ndarray:
    """Map CIC CSV rows to 11-feature array matching inspector preprocessing."""
    n = len(df)
    X = np.zeros((n, 11), dtype=np.float64)

    for col, (idx, scale) in CIC_COL_MAP.items():
        vals = pd.to_numeric(df[col], errors='coerce').fillna(0.0).values * scale
        X[:, idx] = vals

    # swin/dwin: negatives → 0 (matches compute_features() lines 97-98)
    X[:, 7] = np.where(X[:, 7] < 0, 0.0, X[:, 7])
    X[:, 8] = np.where(X[:, 8] < 0, 0.0, X[:, 8])

    # log1p on selected features
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(X[:, i])

    # RobustScaler with hardcoded params
    for i in range(11):
        if IQR[i] != 0.0:
            X[:, i] = (X[:, i] - MEDIAN[i]) / IQR[i]
        else:
            X[:, i] = 0.0

    return X


def load_csv(path: Path) -> pd.DataFrame:
    print(f"  Loading {path.name}...", flush=True)
    df = pd.read_csv(path, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    return df


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load model ────────────────────────────────────────────────────────────
    print("Loading XGBoost model...", flush=True)
    booster = xgb.Booster()
    booster.load_model(str(MODEL_FILE))

    all_scores  = []
    all_labels  = []
    all_sources = []

    for csv_path in CALIB_CSVS:
        df = load_csv(csv_path)

        label_bin = (df['Label'].str.strip() != 'BENIGN').astype(int).values
        X = extract_features(df)

        dmat   = xgb.DMatrix(X, feature_names=FEAT_NAMES)
        scores = booster.predict(dmat)

        all_scores.append(scores)
        all_labels.append(label_bin)
        all_sources.extend([csv_path.stem[:20]] * len(scores))

        n_attack = label_bin.sum()
        n_benign = len(label_bin) - n_attack
        print(f"  {csv_path.name[:50]}: {len(df):,} rows  "
              f"(attack={n_attack:,} benign={n_benign:,})", flush=True)

    scores = np.concatenate(all_scores)
    labels = np.concatenate(all_labels)

    # ── Save dataset ──────────────────────────────────────────────────────────
    out_df = pd.DataFrame({
        'raw_score':  scores,
        'true_label': labels,
        'source':     all_sources,
    })
    out_df.to_csv(OUT_CSV, index=False)
    print(f"\nSaved: {OUT_CSV}  ({len(out_df):,} rows)")

    # ── Report ────────────────────────────────────────────────────────────────
    total   = len(labels)
    n_att   = int(labels.sum())
    n_ben   = total - n_att

    print(f"\n{'='*60}")
    print(f"Calibration dataset statistics")
    print(f"{'='*60}")
    print(f"Total rows:   {total:,}")
    print(f"Attack (1):   {n_att:,}  ({n_att/total*100:.1f}%)")
    print(f"Benign (0):   {n_ben:,}  ({n_ben/total*100:.1f}%)")

    for lbl, lname in [(1, 'ATTACK'), (0, 'BENIGN')]:
        s = scores[labels == lbl]
        print(f"\nScore distribution — {lname} (n={len(s):,}):")
        print(f"  mean={s.mean():.4f}  median={np.median(s):.4f}  "
              f"p10={np.percentile(s,10):.4f}  p90={np.percentile(s,90):.4f}  "
              f"p99={np.percentile(s,99):.4f}")
        # Quick histogram
        for lo, hi in [(0,.1),(.1,.2),(.2,.3),(.3,.4),(.4,.5),
                       (.5,.6),(.6,.7),(.7,.8),(.8,.9),(.9,1.01)]:
            n = int(((s >= lo) & (s < hi)).sum())
            bar = '█' * (n * 40 // len(s)) if len(s) else ''
            print(f"  [{lo:.1f}-{hi:.1f}): {n:>7,}  {n/len(s)*100:5.1f}%  {bar}")


if __name__ == '__main__':
    main()
