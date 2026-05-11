#!/usr/bin/env python3
"""
calib_step3_simulate_wednesday.py — Simulate calibrated scores on Wednesday FP/TP rows.

Re-runs inference on the 8,500 Wednesday FP rows and 252,610 Wednesday TP rows
using the exact same preprocessing pipeline, then applies the isotonic calibrator.

Reports: FPs/TPs pushed below t=0.90, simulated FPR and Recall.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression

REPO       = Path(__file__).resolve().parent.parent
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
MODEL_FILE = REPO / "models/fine_tuned_xgb_model.json"
CAL_FILE   = REPO / "models/xgb_calibrator.json"
OUT_FILE   = REPO / "results/xgboost/calibration/step3_simulation.txt"

THRESHOLD   = 0.90
BASELINE_TN = 431_531
BASELINE_TP = 252_610
BASELINE_FP = 8_500
BASELINE_FN = 62

# Exact g_scaler_params from xgb_inspector.cc
MEDIAN = np.array([
    0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206, 7.5071410797,
    73.0, 89.0, 255.0, 255.0, 0.3841277437, 0.3471507323
])
IQR = np.array([
    0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192, 4.4213950593,
    72.0, 496.0, 255.0, 255.0, 2.1157851784, 1.9696133626
])
LOG1P_IDX = [0, 1, 2, 3, 4, 9, 10]

CIC_COL_MAP = {
    'Flow Duration'               : (0,  1e-6),
    'Total Fwd Packets'           : (1,  1.0),
    'Total Backward Packets'      : (2,  1.0),
    'Total Length of Fwd Packets' : (3,  1.0),
    'Total Length of Bwd Packets' : (4,  1.0),
    'Fwd Packet Length Mean'      : (5,  1.0),
    'Bwd Packet Length Mean'      : (6,  1.0),
    'Init_Win_bytes_forward'      : (7,  1.0),
    'Init_Win_bytes_backward'     : (8,  1.0),
    'Fwd IAT Mean'                : (9,  1e-3),
    'Bwd IAT Mean'                : (10, 1e-3),
}
FEAT_NAMES = ['dur','spkts','dpkts','sbytes','dbytes',
              'smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}


def parse_ip_port(field):
    field = field.strip()
    lc = field.rfind(':')
    if lc == -1:
        return field, 0
    try:
        return field[:lc], int(field[lc + 1:])
    except ValueError:
        return field[:lc], 0


def valid_ip(ip):
    if not ip:
        return False
    if ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
        return False
    return ':' not in ip


def build_alert_fids(alert_file):
    fid_set = set()
    with open(alert_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 8:
                continue
            try:
                proto_str = parts[2].strip()
                src_ip, src_port = parse_ip_port(parts[6].strip())
                dst_ip, dst_port = parse_ip_port(parts[7].strip())
                if not valid_ip(src_ip) or not valid_ip(dst_ip):
                    continue
                if src_port == 0 or dst_port == 0:
                    continue
                proto_num = PROTO_MAP.get(proto_str, 0)
                src_m = IP_MAP.get(src_ip, src_ip)
                dst_m = IP_MAP.get(dst_ip, dst_ip)
                for fid in [
                    f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}",
                    f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}",
                ]:
                    fid_set.add(fid)
            except (IndexError, ValueError):
                continue
    return fid_set


def extract_features(df):
    n = len(df)
    X = np.zeros((n, 11), dtype=np.float64)
    for col, (idx, scale) in CIC_COL_MAP.items():
        vals = pd.to_numeric(df[col], errors='coerce').fillna(0.0).values * scale
        X[:, idx] = vals
    X[:, 7] = np.where(X[:, 7] < 0, 0.0, X[:, 7])
    X[:, 8] = np.where(X[:, 8] < 0, 0.0, X[:, 8])
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(X[:, i])
    for i in range(11):
        if IQR[i] != 0.0:
            X[:, i] = (X[:, i] - MEDIAN[i]) / IQR[i]
        else:
            X[:, i] = 0.0
    return X


def load_calibrator(path):
    data = json.loads(path.read_text())
    iso = IsotonicRegression(out_of_bounds='clip')
    iso.X_thresholds_ = np.array(data['X_thresholds_'])
    iso.y_thresholds_ = np.array(data['y_thresholds_'])
    # Reconstruct internal state so predict() works
    iso.f_ = iso._build_f(iso.X_thresholds_, iso.y_thresholds_)
    return iso


def main():
    lines = []

    print("Building alert FID set...", flush=True)
    alert_fids = build_alert_fids(ALERT_FILE)

    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['label_bin'] = (df['Label'].str.strip() != 'BENIGN').astype(int)

    benign = df[df['label_bin'] == 0]
    attack = df[df['label_bin'] == 1]

    fp_rows = benign[benign['Flow ID'].isin(alert_fids)].copy()
    tp_rows = attack[attack['Flow ID'].isin(alert_fids)].copy()

    assert len(fp_rows) == BASELINE_FP, f"FP count mismatch: {len(fp_rows)} vs {BASELINE_FP}"
    assert len(tp_rows) == BASELINE_TP, f"TP count mismatch: {len(tp_rows)} vs {BASELINE_TP}"

    print("Loading XGBoost model...", flush=True)
    booster = xgb.Booster()
    booster.load_model(str(MODEL_FILE))

    print("Running inference on FP rows...", flush=True)
    X_fp = extract_features(fp_rows)
    scores_fp = booster.predict(xgb.DMatrix(X_fp, feature_names=FEAT_NAMES))

    print("Running inference on TP rows...", flush=True)
    X_tp = extract_features(tp_rows)
    scores_tp = booster.predict(xgb.DMatrix(X_tp, feature_names=FEAT_NAMES))

    print("Loading calibrator...", flush=True)
    # Load via sklearn directly (rebuild from knots)
    cal_data = json.loads(CAL_FILE.read_text())
    X_thresh = np.array(cal_data['X_thresholds_'])
    y_thresh = np.array(cal_data['y_thresholds_'])

    # Apply calibrator manually via np.interp (monotone step function)
    def apply_calibrator(scores):
        return np.interp(scores, X_thresh, y_thresh)

    cal_fp = apply_calibrator(scores_fp)
    cal_tp = apply_calibrator(scores_tp)

    # ── Raw score stats ───────────────────────────────────────────────────────
    lines.append("=" * 65)
    lines.append("Step 3: Calibration Simulation on Wednesday FP/TP rows")
    lines.append(f"Threshold: {THRESHOLD}")
    lines.append("=" * 65)

    lines.append(f"\nRaw score stats — FP rows (n={len(scores_fp):,}):")
    lines.append(f"  mean={scores_fp.mean():.4f}  median={np.median(scores_fp):.4f}  "
                 f"p10={np.percentile(scores_fp,10):.4f}  p90={np.percentile(scores_fp,90):.4f}")

    lines.append(f"\nRaw score stats — TP rows (n={len(scores_tp):,}):")
    lines.append(f"  mean={scores_tp.mean():.4f}  median={np.median(scores_tp):.4f}  "
                 f"p10={np.percentile(scores_tp,10):.4f}  p90={np.percentile(scores_tp,90):.4f}")

    lines.append(f"\nCalibrated score stats — FP rows:")
    lines.append(f"  mean={cal_fp.mean():.4f}  median={np.median(cal_fp):.4f}  "
                 f"p10={np.percentile(cal_fp,10):.4f}  p90={np.percentile(cal_fp,90):.4f}")

    lines.append(f"\nCalibrated score stats — TP rows:")
    lines.append(f"  mean={cal_tp.mean():.4f}  median={np.median(cal_tp):.4f}  "
                 f"p10={np.percentile(cal_tp,10):.4f}  p90={np.percentile(cal_tp,90):.4f}")

    # ── Impact at threshold=0.90 ──────────────────────────────────────────────
    fp_dropped = int((cal_fp < THRESHOLD).sum())
    tp_dropped = int((cal_tp < THRESHOLD).sum())

    rem_fp     = BASELINE_FP - fp_dropped
    rem_tn     = BASELINE_TN + fp_dropped
    rem_tp     = BASELINE_TP - tp_dropped
    rem_fn     = BASELINE_FN + tp_dropped
    rem_fpr    = rem_fp / (rem_fp + rem_tn)
    rem_recall = rem_tp / (rem_tp + rem_fn)

    lines.append(f"\n{'─'*65}")
    lines.append(f"Impact at threshold={THRESHOLD}")
    lines.append(f"{'─'*65}")
    lines.append(f"  FPs dropped below t={THRESHOLD}: {fp_dropped:,}  "
                 f"({fp_dropped/BASELINE_FP*100:.1f}% of FPs)")
    lines.append(f"  TPs dropped below t={THRESHOLD}: {tp_dropped:,}  "
                 f"({tp_dropped/BASELINE_TP*100:.4f}% of TPs)")
    lines.append(f"")
    lines.append(f"  Baseline:    FP={BASELINE_FP:,}  FPR={BASELINE_FP/(BASELINE_FP+BASELINE_TN):.4f}  "
                 f"Recall={BASELINE_TP/(BASELINE_TP+BASELINE_FN):.4f}")
    lines.append(f"  Calibrated:  FP={rem_fp:,}  FPR={rem_fpr:.4f}  "
                 f"Recall={rem_recall:.4f}")
    lines.append(f"  FPR target < 0.01: {'MET' if rem_fpr < 0.01 else 'NOT MET'}")

    lines.append(f"\n{'─'*65}")
    lines.append("Verdict")
    lines.append(f"{'─'*65}")
    if fp_dropped == 0:
        lines.append("  Calibrator maps ALL Wednesday FP scores to ≥0.90.")
        lines.append("  The Tue/Thu calibration distribution does not cover Wednesday DoS attacks.")
        lines.append("  Isotonic calibration with this dataset is INEFFECTIVE for Wednesday FPR.")
        lines.append("  Root cause: Tue/Thu attacks score ~0.30; Wed DoS attacks score ≥0.95.")
        lines.append("  The calibrator has no training signal in the [0.90,1.0] attack zone.")
        lines.append("  Recommendation: proceed to task 04c (targeted retraining) or")
        lines.append("  add Wednesday BENIGN examples with swin≈235 to fine-tune set.")

    report = "\n".join(lines)
    print("\n" + report)
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(report, encoding='utf-8')
    print(f"\nSaved: {OUT_FILE}")


if __name__ == '__main__':
    main()
