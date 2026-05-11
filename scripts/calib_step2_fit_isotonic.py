#!/usr/bin/env python3
"""
calib_step2_fit_isotonic.py — Fit isotonic regression calibrator on Tue+Thu scores.

Reads:  results/xgboost/calibration/calib_dataset.csv
Saves:  models/xgb_calibrator.json  (X_thresholds_ and y_thresholds_ arrays)
Prints: calibration curve at 11 evenly spaced input points [0.0 .. 1.0]
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression

REPO      = Path(__file__).resolve().parent.parent
CALIB_CSV = REPO / "results/xgboost/calibration/calib_dataset.csv"
CAL_OUT   = REPO / "models/xgb_calibrator.json"


def main():
    print("Loading calibration dataset...", flush=True)
    df = pd.read_csv(CALIB_CSV)
    X  = df['raw_score'].values.astype(np.float64)
    y  = df['true_label'].values.astype(np.float64)

    print(f"  Rows: {len(df):,}  Attack: {int(y.sum()):,}  Benign: {int((y==0).sum()):,}")

    print("Fitting IsotonicRegression...", flush=True)
    iso = IsotonicRegression(out_of_bounds='clip')
    iso.fit(X, y)

    # Save X_thresholds_ and y_thresholds_ (the step-function knots)
    cal_data = {
        'X_thresholds_': iso.X_thresholds_.tolist(),
        'y_thresholds_': iso.y_thresholds_.tolist(),
    }
    CAL_OUT.write_text(json.dumps(cal_data, indent=2))
    print(f"Saved: {CAL_OUT}  ({len(iso.X_thresholds_)} knots)")

    # ── Calibration curve ─────────────────────────────────────────────────────
    probe_points = np.linspace(0.0, 1.0, 11)
    calibrated   = iso.predict(probe_points)

    print(f"\n{'='*55}")
    print(f"Calibration curve  (raw_score → calibrated_score)")
    print(f"{'='*55}")
    print(f"  {'raw':>6}  {'calibrated':>11}  {'delta':>8}  note")
    print(f"  {'------':>6}  {'-----------':>11}  {'--------':>8}  ----")
    for raw, cal in zip(probe_points, calibrated):
        delta = cal - raw
        note = ""
        if raw >= 0.90:
            note = "← Wednesday FP zone"
        elif abs(delta) < 0.001:
            note = "(no change)"
        print(f"  {raw:>6.2f}  {cal:>11.6f}  {delta:>+8.4f}  {note}")

    # Also probe the specific zone that matters for Wednesday FPs
    print(f"\nFine-grained probe of Wednesday FP zone (raw ≥ 0.85):")
    print(f"  {'raw':>6}  {'calibrated':>11}  {'delta':>8}")
    print(f"  {'------':>6}  {'-----------':>11}  {'--------':>8}")
    for raw in np.arange(0.85, 1.01, 0.01):
        raw = round(raw, 2)
        cal = float(iso.predict([raw])[0])
        delta = cal - raw
        print(f"  {raw:>6.2f}  {cal:>11.6f}  {delta:>+8.4f}")

    # Sanity: what fraction of high-scoring benign flows get pushed down?
    ben_mask  = df['true_label'] == 0
    high_ben  = df[ben_mask & (df['raw_score'] >= 0.90)]
    if len(high_ben):
        cal_high  = iso.predict(high_ben['raw_score'].values)
        pushed    = (cal_high < 0.90).sum()
        print(f"\nOf {len(high_ben):,} BENIGN flows in calib set with raw_score≥0.90:")
        print(f"  {pushed:,} ({pushed/len(high_ben)*100:.1f}%) get calibrated below 0.90")
        print(f"  Calibrated score stats: mean={cal_high.mean():.4f}  "
              f"median={np.median(cal_high):.4f}  "
              f"p10={np.percentile(cal_high,10):.4f}  "
              f"p90={np.percentile(cal_high,90):.4f}")

    att_mask  = df['true_label'] == 1
    high_att  = df[att_mask & (df['raw_score'] >= 0.90)]
    if len(high_att):
        cal_high_att = iso.predict(high_att['raw_score'].values)
        pushed_att   = (cal_high_att < 0.90).sum()
        print(f"\nOf {len(high_att):,} ATTACK flows in calib set with raw_score≥0.90:")
        print(f"  {pushed_att:,} ({pushed_att/len(high_att)*100:.1f}%) get calibrated below 0.90")
    else:
        print("\n(No attack flows in calib set score ≥0.90 — cannot estimate TP impact directly.)")


if __name__ == '__main__':
    main()
