#!/usr/bin/env python3
"""
calibrate_dos_threshold.py — Aşama 1: Prob Calibration + Threshold Optimization

1. Wednesday CIC CSV → 11 feature → v1 model ile score
2. Isotonic regression ile kalibre et
3. TunedThresholdClassifierCV → recall=0.9997 kısıtı altında precision maximize
4. Optimal threshold bul, calibration curve çiz
5. Sonucu rapor et

Kullanım:
    python3 scripts/calibrate_dos_threshold.py
"""

import json
import numpy as np
import pandas as pd
import xgboost as xgb
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import precision_recall_curve

BASE    = Path('/home/emirhan/bitirme')
MODEL   = BASE / 'models' / 'dos_model.json'
GT_CSV  = BASE / 'data' / 'raw' / 'cicids2017' / 'Wednesday-workingHours.pcap_ISCX.csv'
OUT_DIR = BASE / 'results' / 'fpr-opt-dos' / 'phase1'
OUT_DIR.mkdir(parents=True, exist_ok=True)

# CIC column names → 11 features (same as C++ extractor)
# CIC CSV has different column names than UNSW
CIC_TO_FEAT = {
    'Flow Duration':              'dur',       # microseconds → convert to seconds
    'Total Fwd Packets':          'spkts',
    'Total Backward Packets':     'dpkts',
    'Total Length of Fwd Packets':'sbytes',
    'Total Length of Bwd Packets':'dbytes',
    'Fwd Packet Length Mean':     'smeansz',
    'Bwd Packet Length Mean':     'dmeansz',
    'Init_Win_bytes_forward':     'swin',
    'Init_Win_bytes_backward':    'dwin',
    'Fwd IAT Mean':               'sintpkt',   # microseconds → ms
    'Bwd IAT Mean':               'dintpkt',   # microseconds → ms
}
FEAT_ORDER = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']
LOG_COLS   = ['sbytes','dbytes','spkts','dpkts','dur','sintpkt','dintpkt']

# RobustScaler from C++ (median, IQR)
SCALER_MEDIAN = np.array([0.0157, 2.5649, 2.5649, 7.2937, 7.5071, 73.0,   89.0,  255.0, 255.0, 0.3841, 0.3472])
SCALER_IQR    = np.array([0.1935, 2.7081, 2.6626, 2.7623, 4.4214, 72.0,  496.0,  255.0, 255.0, 2.1158, 1.9696])


def load_cic_features():
    print(f"Loading {GT_CSV.name} ...")
    df = pd.read_csv(GT_CSV, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    print(f"  Rows: {len(df):,}")

    # Check columns
    missing = [c for c in CIC_TO_FEAT if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    # Rename
    df = df.rename(columns=CIC_TO_FEAT)
    df['label'] = (df['Label'].str.strip() != 'BENIGN').astype(int)

    feat_df = df[FEAT_ORDER + ['label']].copy()
    for col in FEAT_ORDER:
        feat_df[col] = pd.to_numeric(feat_df[col], errors='coerce')
    feat_df.dropna(inplace=True)

    # Unit conversions to match C++ extractor:
    # Flow Duration: CIC = microseconds, C++ uses seconds
    feat_df['dur']     = feat_df['dur'] / 1_000_000.0
    # IAT: CIC = microseconds, C++ uses milliseconds
    feat_df['sintpkt'] = feat_df['sintpkt'] / 1_000.0
    feat_df['dintpkt'] = feat_df['dintpkt'] / 1_000.0
    # swin/dwin: clip negatives to 0
    feat_df['swin']    = feat_df['swin'].clip(lower=0)
    feat_df['dwin']    = feat_df['dwin'].clip(lower=0)

    # log1p (same as C++)
    for col in LOG_COLS:
        feat_df[col] = np.log1p(feat_df[col])

    # RobustScaler (same params as C++)
    X = feat_df[FEAT_ORDER].values.astype(np.float64)
    X = (X - SCALER_MEDIAN) / SCALER_IQR

    y = feat_df['label'].values.astype(int)
    print(f"  Features: {X.shape}  attack={y.sum():,}  benign={(y==0).sum():,}")
    return X, y


def load_model():
    model = xgb.XGBClassifier()
    model.load_model(str(MODEL))
    print(f"Model loaded: {MODEL.name}")
    return model


def score_model(model, X):
    return model.predict_proba(X)[:, 1]


def metrics_at_threshold(y, proba, t):
    yp = (proba >= t).astype(int)
    tp = int(((y==1)&(yp==1)).sum())
    fp = int(((y==0)&(yp==1)).sum())
    fn = int(((y==1)&(yp==0)).sum())
    tn = int(((y==0)&(yp==0)).sum())
    rec  = tp/(tp+fn) if (tp+fn)>0 else 0.0
    prec = tp/(tp+fp) if (tp+fp)>0 else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
    fpr  = fp/(fp+tn) if (fp+tn)>0 else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                recall=round(rec,6), precision=round(prec,6),
                f1=round(f1,6), fpr=round(fpr,6))


def calibrate_isotonic(proba, y):
    """Fit isotonic regression calibrator on full dataset."""
    ir = IsotonicRegression(out_of_bounds='clip')
    # Sort by probability for isotonic
    sort_idx = np.argsort(proba)
    ir.fit(proba[sort_idx], y[sort_idx])
    cal_proba = ir.predict(proba)
    print("Isotonic calibration fitted.")
    return cal_proba, ir


def find_optimal_threshold(y, proba, recall_floor=0.9997):
    """
    Find threshold that maximizes precision (minimizes FP)
    subject to recall >= recall_floor.
    Uses precision-recall curve for efficiency.
    """
    precisions, recalls, thresholds = precision_recall_curve(y, proba)
    # precision_recall_curve returns in decreasing recall order
    # thresholds has len = len(precisions) - 1
    best_t = None
    best_prec = 0.0
    best_metrics = None

    for i, (prec, rec) in enumerate(zip(precisions[:-1], recalls[:-1])):
        if rec >= recall_floor and prec > best_prec:
            best_prec = prec
            best_t = thresholds[i]
            best_metrics = metrics_at_threshold(y, proba, thresholds[i])

    return best_t, best_metrics


def plot_calibration(y, raw_proba, cal_proba, out_path):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Calibration curve
    ax = axes[0]
    frac_pos_raw, mean_pred_raw = calibration_curve(y, raw_proba, n_bins=20, strategy='quantile')
    frac_pos_cal, mean_pred_cal = calibration_curve(y, cal_proba, n_bins=20, strategy='quantile')
    ax.plot([0,1],[0,1],'k--', label='Perfect')
    ax.plot(mean_pred_raw, frac_pos_raw, 's-', label='Raw XGBoost')
    ax.plot(mean_pred_cal, frac_pos_cal, 'o-', label='Isotonic calibrated')
    ax.set_xlabel('Mean predicted probability')
    ax.set_ylabel('Fraction of positives')
    ax.set_title('Calibration Curve')
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Score histogram
    ax = axes[1]
    ax.hist(raw_proba[y==0], bins=50, alpha=0.5, label='Benign (raw)', density=True)
    ax.hist(raw_proba[y==1], bins=50, alpha=0.5, label='Attack (raw)', density=True)
    ax.set_xlabel('XGBoost score')
    ax.set_ylabel('Density')
    ax.set_title('Score Distribution: FP source visible at [0.9-1.0]')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    print(f"Plot saved: {out_path}")


def threshold_sweep(y, proba, label, recall_floor=0.9990):
    print(f"\n── Threshold Sweep ({label}) ──────────────────────")
    print(f"  {'t':>5}  {'FP':>6}  {'FPR':>7}  {'Recall':>8}  {'Prec':>8}  {'F1':>8}")
    results = []
    for t_int in range(85, 100):
        t = t_int / 100.0
        m = metrics_at_threshold(y, proba, t)
        mark = ' ← recall floor' if abs(m['recall'] - recall_floor) < 0.001 else ''
        print(f"  {t:.2f}  {m['fp']:>6,}  {m['fpr']:>7.4f}  {m['recall']:>8.4f}  "
              f"{m['precision']:>8.4f}  {m['f1']:>8.4f}{mark}")
        results.append({'threshold': t, **m})
    return results


def main():
    print("=" * 60)
    print("  Aşama 1: Prob Calibration + Threshold Optimization")
    print("=" * 60)

    X, y = load_cic_features()
    model = load_model()

    # Raw scores
    print("\nScoring with v1 model ...")
    raw_proba = score_model(model, X)

    # Baseline at 0.90
    base = metrics_at_threshold(y, raw_proba, 0.90)
    print(f"\nBaseline @ t=0.90:")
    print(f"  FP={base['fp']:,}  FPR={base['fpr']:.4f}  Recall={base['recall']:.4f}  "
          f"Prec={base['precision']:.4f}  F1={base['f1']:.4f}")

    # Raw threshold sweep
    raw_sweep = threshold_sweep(y, raw_proba, 'RAW (uncalibrated)')

    # Isotonic calibration
    print("\nCalibrating with isotonic regression ...")
    cal_proba, ir = calibrate_isotonic(raw_proba, y)

    # Calibrated threshold sweep
    cal_sweep = threshold_sweep(y, cal_proba, 'CALIBRATED (isotonic)')

    # Find optimal threshold under recall floor
    RECALL_FLOOR = 0.9997
    print(f"\n── Optimal Threshold Search (recall ≥ {RECALL_FLOOR}) ──────")

    raw_opt_t, raw_opt_m = find_optimal_threshold(y, raw_proba, RECALL_FLOOR)
    cal_opt_t, cal_opt_m = find_optimal_threshold(y, cal_proba, RECALL_FLOOR)

    print(f"\n  RAW optimal:        t={raw_opt_t:.4f}  FP={raw_opt_m['fp']:,}  "
          f"FPR={raw_opt_m['fpr']:.4f}  Recall={raw_opt_m['recall']:.4f}")
    print(f"  CALIBRATED optimal: t={cal_opt_t:.4f}  FP={cal_opt_m['fp']:,}  "
          f"FPR={cal_opt_m['fpr']:.4f}  Recall={cal_opt_m['recall']:.4f}")

    fp_reduction_raw = base['fp'] - raw_opt_m['fp']
    fp_reduction_cal = base['fp'] - cal_opt_m['fp']
    print(f"\n  FP reduction (raw):        {fp_reduction_raw:+,}  ({100*fp_reduction_raw/base['fp']:+.1f}%)")
    print(f"  FP reduction (calibrated): {fp_reduction_cal:+,}  ({100*fp_reduction_cal/base['fp']:+.1f}%)")

    # Score distribution stats for FP vs TP
    print(f"\n── Score Distribution Analysis ──────────────────────")
    fp_mask = (y == 0) & (raw_proba >= 0.90)
    tp_mask = (y == 1) & (raw_proba >= 0.90)
    fn_mask = (y == 1) & (raw_proba < 0.90)

    fp_scores = raw_proba[fp_mask]
    tp_scores = raw_proba[tp_mask]

    print(f"  FP scores (n={len(fp_scores):,}): p10={np.percentile(fp_scores,10):.4f}  "
          f"p25={np.percentile(fp_scores,25):.4f}  p50={np.percentile(fp_scores,50):.4f}  "
          f"p90={np.percentile(fp_scores,90):.4f}")
    print(f"  TP scores (n={len(tp_scores):,}): p10={np.percentile(tp_scores,10):.4f}  "
          f"p25={np.percentile(tp_scores,25):.4f}  p50={np.percentile(tp_scores,50):.4f}  "
          f"p90={np.percentile(tp_scores,90):.4f}")
    print(f"  FN (missed):  n={fn_mask.sum():,}")

    # Overlap analysis: what fraction of FPs score > 0.95?
    for cutoff in [0.90, 0.92, 0.94, 0.95, 0.97, 0.99]:
        fp_above = (fp_scores >= cutoff).sum()
        tp_above = (tp_scores >= cutoff).sum()
        fn_at = ((y==1) & (raw_proba < cutoff)).sum()
        print(f"  t={cutoff:.2f}: FP_above={fp_above:,}  TP_above={tp_above:,}  FN_total={fn_at:,}")

    # Plot
    plot_calibration(y, raw_proba, cal_proba, OUT_DIR / 'calibration_curve.png')

    # Save report
    report = {
        'baseline_t090': base,
        'raw_optimal': {'threshold': float(raw_opt_t) if raw_opt_t else None, **( raw_opt_m or {})},
        'cal_optimal': {'threshold': float(cal_opt_t) if cal_opt_t else None, **( cal_opt_m or {})},
        'recall_floor_used': RECALL_FLOOR,
        'fp_reduction_raw': int(fp_reduction_raw),
        'fp_reduction_cal': int(fp_reduction_cal),
        'score_distribution': {
            'fp_p50': float(np.percentile(fp_scores, 50)),
            'tp_p50': float(np.percentile(tp_scores, 50)),
            'fp_p10': float(np.percentile(fp_scores, 10)),
            'fp_p90': float(np.percentile(fp_scores, 90)),
        },
        'raw_sweep': raw_sweep,
        'cal_sweep': cal_sweep,
    }
    out_json = OUT_DIR / 'calibration_report.json'
    with open(out_json, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved: {out_json}")

    # Final recommendation
    print(f"\n{'='*60}")
    print(f"  SONUÇ")
    print(f"{'='*60}")
    best = cal_opt_m if cal_opt_m and (cal_opt_m['fp'] < raw_opt_m.get('fp', 99999)) else raw_opt_m
    best_t = cal_opt_t if cal_opt_m and (cal_opt_m['fp'] < raw_opt_m.get('fp', 99999)) else raw_opt_t
    if best and best_t:
        print(f"  Önerilen threshold: {best_t:.4f}")
        print(f"  FP: {base['fp']:,} → {best['fp']:,}  (Δ={best['fp']-base['fp']:+,})")
        print(f"  FPR: {base['fpr']:.4f} → {best['fpr']:.4f}")
        print(f"  Recall: {base['recall']:.4f} → {best['recall']:.4f}")
        pct = 100*(base['fp']-best['fp'])/base['fp']
        if pct >= 5:
            print(f"  Kazanım: {pct:.1f}% FP azalması — threshold güncellenebilir")
        else:
            print(f"  Kazanım: {pct:.1f}% — KÜÇÜK. Calibration yeterli değil.")
            print(f"  → Aşama 2 (feature schema) ana kazanım kaynağı olacak.")
    else:
        print(f"  Optimal threshold bulunamadı (recall floor çok yüksek?)")
        print(f"  → Aşama 2'ye geç.")


if __name__ == '__main__':
    main()
