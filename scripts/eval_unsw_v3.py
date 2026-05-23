#!/usr/bin/env python3
"""Evaluate dos_fpr_opt_v3 on UNSW-NB15 with per-attack-category breakdown.

17-feature schema (matches dos_fpr_opt_v3_scaler.json feature_names):
  [0]  dur       [1]  spkts    [2]  dpkts    [3]  sbytes   [4]  dbytes
  [5]  smeansz   [6]  dmeansz  [7]  swin     [8]  dwin     [9]  sintpkt
  [10] dintpkt   [11] fwd_pkt_mean  [12] bwd_pkt_mean
  [13] fin_cnt=0 (not in UNSW)
  [14] ack_cnt=0 (not in UNSW)
  [15] syn_cnt=0 (not in UNSW)
  [16] bwd_iat≈dintpkt

Scaling: manual RobustScaler via v3 scaler JSON (median/IQR),
         log1p applied to indices listed in log1p_indices BEFORE scaling.

Saves results to:
  results/generalization/phase_v3/dos_fpr_opt_v3/unsw_per_category_v3.json
"""
import numpy as np
import pandas as pd
import xgboost as xgb
import json
from pathlib import Path
from sklearn.model_selection import train_test_split

BASE = Path('/home/emirhan/bitirme')

UNSW_COLS = [
    'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
    'sttl','dttl','sloss','dloss','service','sload','dload','spkts','dpkts',
    'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'sjit','djit','stime','ltime','sintpkt','dintpkt','tcprtt','synack','ackdat',
    'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
    'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label'
]

# 11 base features pulled directly from UNSW
BASE_COLS = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']

THRESHOLD = 0.90


def build_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Returns (N, 17) float64 array — pre-log1p, pre-scaling (raw values).

    swin (col 7) and dwin (col 8) are zeroed out: CIC trains them at ~29000
    while UNSW uses ~255, causing extreme scaled values (-58). Zeroing uses
    the same strategy as fin_cnt/ack_cnt/syn_cnt — treat as missing.
    """
    x = df[BASE_COLS].values.astype(np.float64)   # (N, 11)

    spkts = x[:, 1]
    dpkts = x[:, 2]
    sbytes = x[:, 3]
    dbytes = x[:, 4]
    dintpkt = x[:, 10]

    # Zero out swin/dwin — incompatible scale between CIC and UNSW
    x[:, 7] = 0.0  # swin
    x[:, 8] = 0.0  # dwin

    fwd_pkt_mean = sbytes / np.maximum(spkts, 1.0)  # col 11
    bwd_pkt_mean = dbytes / np.maximum(dpkts, 1.0)  # col 12
    fin_cnt      = np.zeros(len(x))                  # col 13 — not in UNSW
    ack_cnt      = np.zeros(len(x))                  # col 14 — not in UNSW
    syn_cnt      = np.zeros(len(x))                  # col 15 — not in UNSW
    bwd_iat      = dintpkt.copy()                    # col 16 — ≈Dintpkt

    return np.column_stack([x, fwd_pkt_mean, bwd_pkt_mean,
                             fin_cnt, ack_cnt, syn_cnt, bwd_iat])


def apply_scaler(X: np.ndarray, scaler: dict) -> np.ndarray:
    """Apply log1p then RobustScaler using v3 scaler JSON."""
    X = X.copy()
    log_idx = scaler['log1p_indices']
    X[:, log_idx] = np.log1p(X[:, log_idx])
    median = np.array(scaler['median'], dtype=np.float64)
    iqr    = np.array(scaler['iqr'],    dtype=np.float64)
    iqr    = np.where(iqr == 0, 1.0, iqr)
    return (X - median) / iqr


def metrics(yt, yp):
    tp = int(((yt == 1) & (yp == 1)).sum())
    fp = int(((yt == 0) & (yp == 1)).sum())
    fn = int(((yt == 1) & (yp == 0)).sum())
    tn = int(((yt == 0) & (yp == 0)).sum())
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                recall=round(rec, 4), precision=round(prec, 4),
                f1=round(f1, 4), fpr=round(fpr, 6))


def main():
    # Load scaler
    with open(BASE / 'models' / 'dos_fpr_opt_v3_scaler.json') as f:
        scaler = json.load(f)
    assert scaler['n_features'] == 17, "unexpected scaler feature count"
    print(f"Scaler loaded: {scaler['n_features']} features")
    print(f"Feature order: {scaler['feature_names']}")

    # Load model
    model = xgb.XGBClassifier()
    model.load_model(str(BASE / 'models' / 'dos_fpr_opt_v3.json'))
    print(f'Model loaded: {len(model.get_booster().get_dump())} trees')

    # Load UNSW-NB15
    print('\nLoading UNSW-NB15 (all 4 files)...')
    dfs = []
    for i in [1, 2, 3, 4]:
        path = BASE / 'data' / 'unsw' / f'UNSW-NB15_{i}.csv'
        df = pd.read_csv(path, header=None, names=UNSW_COLS, low_memory=False)
        if str(df.iloc[0, 0]).strip().lower() == 'srcip':
            df = df.iloc[1:]
        dfs.append(df)
    full = pd.concat(dfs, ignore_index=True)
    full['label']      = pd.to_numeric(full['label'], errors='coerce').fillna(0).astype(int)
    full['attack_cat'] = full['attack_cat'].astype(str).str.strip()

    # Numeric conversion + drop NaN
    df_f = full[BASE_COLS + ['label', 'attack_cat']].copy()
    df_f[BASE_COLS] = df_f[BASE_COLS].apply(pd.to_numeric, errors='coerce')
    df_f.dropna(subset=BASE_COLS + ['label'], inplace=True)

    y    = df_f['label'].values.astype(int)
    cats = df_f['attack_cat'].values

    print(f'Total samples: {len(y):,}  attack: {y.sum():,}  benign: {(y==0).sum():,}')

    # Build features (raw), same 80/20 split as prepare_dataset.py
    X = build_feature_matrix(df_f)
    idx = np.arange(len(y))
    idx_tr, idx_te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)

    X_te_s  = apply_scaler(X[idx_te], scaler)
    y_te    = y[idx_te]
    cats_te = cats[idx_te]

    # Inference
    proba = model.predict_proba(X_te_s)[:, 1]
    yp    = (proba >= THRESHOLD).astype(int)

    # Overall
    overall = metrics(y_te, yp)
    print()
    print(f'=== dos_fpr_opt_v3 UNSW-NB15 (threshold={THRESHOLD}) ===')
    print(f'TP={overall["tp"]:,}  FP={overall["fp"]:,}  FN={overall["fn"]:,}  '
          f'Rec={overall["recall"]:.4f}  Prec={overall["precision"]:.4f}  '
          f'F1={overall["f1"]:.4f}  FPR={overall["fpr"]:.6f}')
    print()
    print('ACCEPT CRITERIA: Overall Recall >= 0.81')
    status = "PASS" if overall["recall"] >= 0.81 else "FAIL"
    print(f'Status: {status}')

    # Per-category
    print()
    hdr = f'{"Category":<18} {"Total":>8} {"Attacks":>8} {"TP":>7} {"FN":>7} {"FP":>7} {"Recall":>8}'
    print(hdr)
    print('-' * len(hdr))
    per_cat = {}
    for cat in sorted(set(cats_te), key=str):
        mask = cats_te == cat
        yt_c = y_te[mask]; yp_c = yp[mask]
        m = metrics(yt_c, yp_c)
        per_cat[str(cat)] = m
        per_cat[str(cat)]['total']     = int(mask.sum())
        per_cat[str(cat)]['n_attacks'] = int(yt_c.sum())
        flag = ''
        if yt_c.sum() > 0 and m['recall'] < 0.81:
            flag = ' ❌'
        elif yt_c.sum() > 0:
            flag = ' ✅'
        print(f'{str(cat):<18} {mask.sum():>8,} {yt_c.sum():>8,} {m["tp"]:>7,} '
              f'{m["fn"]:>7,} {m["fp"]:>7,} {m["recall"]:>8.4f}{flag}')

    # Save
    out_dir = BASE / 'results' / 'generalization' / 'phase_v3' / 'dos_fpr_opt_v3'
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        'model': 'dos_fpr_opt_v3.json',
        'scaler': 'dos_fpr_opt_v3_scaler.json',
        'dataset': 'UNSW-NB15 (all 4 files, 20% test split)',
        'threshold': THRESHOLD,
        'n_test': int(len(y_te)),
        'unsw_notes': {
            'swin': 'zeroed (CIC~29000 vs UNSW~255 — incompatible scale)',
            'dwin': 'zeroed (CIC~29000 vs UNSW~255 — incompatible scale)',
            'fin_cnt': 'zeroed (not in UNSW)',
            'ack_cnt': 'zeroed (not in UNSW)',
            'syn_cnt': 'zeroed (not in UNSW)',
            'bwd_iat': 'approximated as dintpkt (mean bwd inter-arrival)',
            'fwd_pkt_mean': 'derived: sbytes/max(spkts,1)',
            'bwd_pkt_mean': 'derived: dbytes/max(dpkts,1)',
        },
        'overall': overall,
        'per_category': per_cat,
        'accept_status': status,
    }
    out_path = out_dir / 'unsw_per_category_v3.json'
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'\nSaved: {out_path}')
    return overall


if __name__ == '__main__':
    main()
