#!/usr/bin/env python3
"""
diag_flowid_collision.py — Diagnose whether FP/TP confusion matrix rows are
real model detections or flow-ID collision artifacts.

Prints only — writes nothing to disk.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb

REPO       = Path(__file__).resolve().parent.parent
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
MODEL_FILE = REPO / "models/fine_tuned_xgb_model.json"

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}

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


def build_alert_structures(alert_file):
    """
    Returns:
      fid_set       : set of all flow-ID strings generated from alerts
      fid_to_alert  : fid -> list of alert dicts (src_ip, src_port, dst_ip, dst_port, proto_str)
                      so we can show WHICH alert row matched a given CSV Flow ID
    """
    fid_set      = set()
    fid_to_alert = {}

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

                alert_info = {
                    'src_ip': src_ip, 'src_port': src_port,
                    'dst_ip': dst_ip, 'dst_port': dst_port,
                    'proto': proto_str,
                }
                fids = [
                    f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}",
                    f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}",
                ]
                for fid in fids:
                    fid_set.add(fid)
                    if fid not in fid_to_alert:
                        fid_to_alert[fid] = []
                    fid_to_alert[fid].append(alert_info)
            except (IndexError, ValueError):
                continue

    return fid_set, fid_to_alert


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


def score_rows(df, booster):
    X = extract_features(df)
    return booster.predict(xgb.DMatrix(X, feature_names=FEAT_NAMES))


def print_sample(rows, scores, fid_to_alert, label, n=20):
    sample = rows.sample(min(n, len(rows)), random_state=42).copy()
    sample_scores = scores[rows.index.isin(sample.index)]

    # Re-score just the sample rows in index order
    sample_scores = score_rows(sample, booster=None)  # handled below; pass booster in caller

    print(f"\n{'─'*70}")
    print(f"Sample: {n} random rows from {label} set  (total={len(rows):,})")
    print(f"{'─'*70}")

    for i, (idx, row) in enumerate(sample.iterrows()):
        csv_fid   = str(row['Flow ID']).strip()
        src_ip    = str(row.get(' Source IP', row.get('Source IP', '?'))).strip()
        dst_ip    = str(row.get(' Destination IP', row.get('Destination IP', '?'))).strip()
        src_port  = str(row.get(' Source Port', row.get('Source Port', '?'))).strip()
        dst_port  = str(row.get(' Destination Port', row.get('Destination Port', '?'))).strip()
        protocol  = str(row.get(' Protocol', row.get('Protocol', '?'))).strip()
        lbl       = str(row['Label']).strip()
        score     = float(sample_scores[i])

        # Find which FID variants hit this CSV Flow ID
        matched_alerts = fid_to_alert.get(csv_fid, [])
        if matched_alerts:
            alert_repr = matched_alerts[0]  # show first matching alert
            alert_str  = (f"{alert_repr['src_ip']}:{alert_repr['src_port']} → "
                          f"{alert_repr['dst_ip']}:{alert_repr['dst_port']} "
                          f"({alert_repr['proto']})")
            n_collisions = len(matched_alerts)
        else:
            alert_str    = "(no direct match — matched via bidirectional/mapped variant)"
            n_collisions = 0

        print(f"\n  [{i+1:02d}] CSV Flow ID: {csv_fid}")
        print(f"       Label:       {lbl}")
        print(f"       CSV tuple:   {src_ip}:{src_port} → {dst_ip}:{dst_port}  proto={protocol}")
        print(f"       XGB score:   {score:.6f}")
        print(f"       Alert match: {alert_str}  ({n_collisions} alert rows share this FID)")

        # Are the IPs/ports the same or different? (collision check)
        same_tuple = (
            src_ip == alert_repr.get('src_ip', '') and
            dst_ip == alert_repr.get('dst_ip', '') and
            src_port == str(alert_repr.get('src_port', '')) and
            dst_port == str(alert_repr.get('dst_port', ''))
        ) if matched_alerts else False
        if not same_tuple and matched_alerts:
            print(f"       *** TUPLE MISMATCH (possible collision) ***")

    return sample_scores


def main():
    print("Building alert structures...", flush=True)
    fid_set, fid_to_alert = build_alert_structures(ALERT_FILE)
    print(f"  FID set size: {len(fid_set):,}")
    print(f"  Distinct FIDs with alert mapping: {len(fid_to_alert):,}")

    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['label_bin'] = (df['Label'].str.strip() != 'BENIGN').astype(int)

    benign = df[df['label_bin'] == 0]
    attack = df[df['label_bin'] == 1]

    fp_rows = benign[benign['Flow ID'].isin(fid_set)].copy()
    tp_rows = attack[attack['Flow ID'].isin(fid_set)].copy()

    print(f"  FP rows (BENIGN+alerted): {len(fp_rows):,}")
    print(f"  TP rows (attack+alerted): {len(tp_rows):,}")

    print("Loading XGBoost model and scoring...", flush=True)
    booster = xgb.Booster()
    booster.load_model(str(MODEL_FILE))

    scores_fp = score_rows(fp_rows, booster)
    scores_tp = score_rows(tp_rows, booster)

    # ── Section 3: Score distribution of FP rows ─────────────────────────────
    print(f"\n{'='*70}")
    print("Section 3 — Score distribution of FP rows (n=8,500)")
    print(f"{'='*70}")
    bins = [
        ("<0.10",  scores_fp <  0.10),
        ("0.10–0.49", (scores_fp >= 0.10) & (scores_fp < 0.50)),
        ("<0.50 total", scores_fp < 0.50),
        ("0.50–0.89", (scores_fp >= 0.50) & (scores_fp < 0.90)),
        ("≥0.50",  scores_fp >= 0.50),
        ("≥0.90",  scores_fp >= 0.90),
    ]
    for label, mask in bins:
        n = int(mask.sum())
        print(f"  {label:<18}: {n:>7,}  ({n/len(scores_fp)*100:.2f}%)")
    print(f"  mean={scores_fp.mean():.6f}  median={np.median(scores_fp):.6f}  "
          f"p99={np.percentile(scores_fp,99):.6f}  max={scores_fp.max():.6f}")

    # ── Section 4: Score distribution of TP rows ─────────────────────────────
    print(f"\n{'='*70}")
    print("Section 4 — Score distribution of TP rows (n=252,610)")
    print(f"{'='*70}")
    bins_tp = [
        ("<0.50",  scores_tp < 0.50),
        ("0.50–0.89", (scores_tp >= 0.50) & (scores_tp < 0.90)),
        ("≥0.50",  scores_tp >= 0.50),
        ("≥0.90",  scores_tp >= 0.90),
    ]
    for label, mask in bins_tp:
        n = int(mask.sum())
        print(f"  {label:<18}: {n:>7,}  ({n/len(scores_tp)*100:.2f}%)")
    print(f"  mean={scores_tp.mean():.6f}  median={np.median(scores_tp):.6f}  "
          f"p1={np.percentile(scores_tp,1):.6f}  min={scores_tp.min():.6f}")

    # ── Section 1: 20 random FP rows ─────────────────────────────────────────
    print(f"\n{'='*70}")
    print("Section 1 — 20 random FP rows (BENIGN + alerted)")
    print(f"{'='*70}")
    sample_fp = fp_rows.sample(20, random_state=42).copy()
    s_fp = score_rows(sample_fp, booster)
    for i, (idx, row) in enumerate(sample_fp.iterrows()):
        csv_fid  = str(row['Flow ID']).strip()
        src_ip   = str(row.get('Source IP', '?')).strip()
        dst_ip   = str(row.get('Destination IP', '?')).strip()
        src_port = str(row.get('Source Port', '?')).strip()
        dst_port = str(row.get('Destination Port', '?')).strip()
        protocol = str(row.get('Protocol', '?')).strip()
        score    = float(s_fp[i])

        matched = fid_to_alert.get(csv_fid, [])
        if matched:
            a = matched[0]
            alert_str = (f"{a['src_ip']}:{a['src_port']} → "
                         f"{a['dst_ip']}:{a['dst_port']} ({a['proto']})")
            same = (src_ip == a['src_ip'] and dst_ip == a['dst_ip'] and
                    src_port == str(a['src_port']) and dst_port == str(a['dst_port']))
            collision_flag = "" if same else "  *** TUPLE MISMATCH ***"
        else:
            alert_str      = "(matched via bidirectional/mapped FID variant)"
            collision_flag = ""

        print(f"\n  [{i+1:02d}] Flow ID: {csv_fid}")
        print(f"       Label:       {str(row['Label']).strip()}")
        print(f"       CSV tuple:   {src_ip}:{src_port} → {dst_ip}:{dst_port}  proto={protocol}")
        print(f"       XGB score:   {score:.6f}")
        print(f"       Alert match: {alert_str}{collision_flag}")

    # ── Section 2: 20 random TP rows ─────────────────────────────────────────
    print(f"\n{'='*70}")
    print("Section 2 — 20 random TP rows (attack + alerted)")
    print(f"{'='*70}")
    sample_tp = tp_rows.sample(20, random_state=42).copy()
    s_tp = score_rows(sample_tp, booster)
    for i, (idx, row) in enumerate(sample_tp.iterrows()):
        csv_fid  = str(row['Flow ID']).strip()
        src_ip   = str(row.get('Source IP', '?')).strip()
        dst_ip   = str(row.get('Destination IP', '?')).strip()
        src_port = str(row.get('Source Port', '?')).strip()
        dst_port = str(row.get('Destination Port', '?')).strip()
        protocol = str(row.get('Protocol', '?')).strip()
        score    = float(s_tp[i])

        matched = fid_to_alert.get(csv_fid, [])
        if matched:
            a = matched[0]
            alert_str = (f"{a['src_ip']}:{a['src_port']} → "
                         f"{a['dst_ip']}:{a['dst_port']} ({a['proto']})")
            same = (src_ip == a['src_ip'] and dst_ip == a['dst_ip'] and
                    src_port == str(a['src_port']) and dst_port == str(a['dst_port']))
            collision_flag = "" if same else "  *** TUPLE MISMATCH ***"
        else:
            alert_str      = "(matched via bidirectional/mapped FID variant)"
            collision_flag = ""

        print(f"\n  [{i+1:02d}] Flow ID: {csv_fid}")
        print(f"       Label:       {str(row['Label']).strip()}")
        print(f"       CSV tuple:   {src_ip}:{src_port} → {dst_ip}:{dst_port}  proto={protocol}")
        print(f"       XGB score:   {score:.6f}")
        print(f"       Alert match: {alert_str}{collision_flag}")

    print(f"\n{'='*70}")
    print("Done.")
    print(f"{'='*70}")


if __name__ == '__main__':
    main()
