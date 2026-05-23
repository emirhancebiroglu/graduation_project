#!/usr/bin/env python3
"""dos_inspector IF generalization FPR on UNSW-NB15 benign flows.

UNSW column mapping (no header, 0-indexed):
  col 6  = dur
  col 16 = Spkts
  col 17 = Dpkts
  col 7  = sbytes
  col 8  = dbytes
  col 22 = smeansz
  col 23 = dmeansz
  col 30 = Sintpkt
  col 31 = Dintpkt
  col 47 = label  (0=benign, 1=attack)

Derived:
  fwd_pkt_mean = sbytes / Spkts  (0 if Spkts=0)
  bwd_pkt_mean = dbytes / Dpkts  (0 if Dpkts=0)
  fin_cnt, ack_cnt, syn_cnt, bwd_iat = 0 (not in UNSW)

Features: dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz,
          sintpkt, dintpkt, fwd_pkt_mean, bwd_pkt_mean,
          fin_cnt, ack_cnt, syn_cnt, bwd_iat
"""
import json, pickle
from pathlib import Path

import numpy as np
import pandas as pd

BASE        = Path('/home/emirhan/bitirme')
UNSW_DIR    = BASE / 'data' / 'unsw'
MODEL_PATH  = BASE / 'models' / 'dos_if_anomaly_v3b.pkl'
META_PATH   = BASE / 'models' / 'dos_if_anomaly_v3b_meta.json'
SCALER_PATH = BASE / 'models' / 'dos_fpr_opt_v3b_scaler.json'

UNSW_COLS = [
    'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
    'sttl','dttl','sloss','dloss','service','Sload','Dload','Spkts','Dpkts',
    'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat',
    'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
    'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label',
]

LOG1P_IDX = [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14]

NEEDED_COLS = ['dur', 'Spkts', 'Dpkts', 'sbytes', 'dbytes',
               'smeansz', 'dmeansz', 'Sintpkt', 'Dintpkt', 'label']


def load_unsw_benign(path: Path, cap: int = 200_000) -> pd.DataFrame:
    print(f'  Loading {path.name}...')
    df = pd.read_csv(path, header=None, names=UNSW_COLS, low_memory=False,
                     usecols=NEEDED_COLS, dtype=str)
    df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
    df = df[df['label'] == 0]
    for c in NEEDED_COLS[:-1]:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    if len(df) > cap:
        df = df.sample(cap, random_state=42)
    print(f'    {len(df)} benign rows')
    return df


def build_features(df: pd.DataFrame) -> np.ndarray:
    spkts = df['Spkts'].values.astype(np.float64)
    dpkts = df['Dpkts'].values.astype(np.float64)
    sbytes = df['sbytes'].values.astype(np.float64)
    dbytes = df['dbytes'].values.astype(np.float64)

    fwd_pkt_mean = np.where(spkts > 0, sbytes / spkts, 0.0)
    bwd_pkt_mean = np.where(dpkts > 0, dbytes / dpkts, 0.0)
    zeros = np.zeros(len(df))

    X = np.column_stack([
        df['dur'].values.astype(np.float64),   # 0  dur
        spkts,                                  # 1  spkts
        dpkts,                                  # 2  dpkts
        sbytes,                                 # 3  sbytes
        dbytes,                                 # 4  dbytes
        df['smeansz'].values.astype(np.float64),# 5  smeansz
        df['dmeansz'].values.astype(np.float64),# 6  dmeansz
        df['Sintpkt'].values.astype(np.float64),# 7  sintpkt
        df['Dintpkt'].values.astype(np.float64),# 8  dintpkt
        fwd_pkt_mean,                           # 9  fwd_pkt_mean
        bwd_pkt_mean,                           # 10 bwd_pkt_mean
        zeros,                                  # 11 fin_cnt
        zeros,                                  # 12 ack_cnt
        zeros,                                  # 13 syn_cnt
        df['Dintpkt'].values.astype(np.float64),# 14 bwd_iat ≈ dintpkt
    ])
    return X


def preprocess(X: np.ndarray, scaler: dict) -> np.ndarray:
    X = X.copy()
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    median = np.array(scaler['median'])
    iqr = np.array(scaler['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return (X - median) / iqr_safe


def main():
    print('=== dos_inspector IF — UNSW Generalization FPR Test ===\n')

    with open(MODEL_PATH, 'rb') as f:
        clf = pickle.load(f)
    with open(META_PATH) as f:
        meta = json.load(f)
    with open(SCALER_PATH) as f:
        scaler = json.load(f)

    threshold = meta['threshold_p5']
    print(f'IF model loaded. Threshold (p5): {threshold:.4f}')
    print(f'Training FPR (CIC val): {meta.get("anomaly_rate_train", "N/A")}')
    print()

    dfs = []
    for i in range(1, 5):
        path = UNSW_DIR / f'UNSW-NB15_{i}.csv'
        if path.exists():
            dfs.append(load_unsw_benign(path, cap=150_000))
        else:
            print(f'  SKIP: {path.name} not found')

    if not dfs:
        print('ERROR: No UNSW files found.')
        return

    df_all = pd.concat(dfs, ignore_index=True)
    print(f'\nTotal benign rows: {len(df_all)}')

    X_raw = build_features(df_all)
    X_scaled = preprocess(X_raw, scaler)
    print(f'Feature matrix: {X_scaled.shape}')

    BATCH = 50_000
    scores = []
    for start in range(0, len(X_scaled), BATCH):
        batch = X_scaled[start:start + BATCH]
        scores.append(clf.score_samples(batch))
        print(f'  Scored {min(start + BATCH, len(X_scaled))}/{len(X_scaled)}', end='\r')
    print()

    scores = np.concatenate(scores)
    fpr = float((scores < threshold).mean())
    n_fp = int((scores < threshold).sum())

    print(f'\n=== RESULTS ===')
    print(f'N benign flows scored:  {len(scores)}')
    print(f'Threshold:              {threshold:.4f}')
    print(f'FP count:               {n_fp}')
    print(f'FPR (UNSW benign):      {fpr:.4f}')
    print(f'Target:                 ≤ 0.10')
    print(f'PASS:                   {"✅ YES" if fpr <= 0.10 else "❌ NO"}')

    p_values = np.percentile(scores, [1, 5, 10, 25, 50])
    print(f'\nScore distribution (UNSW benign):')
    print(f'  p1={p_values[0]:.4f}  p5={p_values[1]:.4f}  p10={p_values[2]:.4f}  '
          f'p25={p_values[3]:.4f}  p50={p_values[4]:.4f}')

    result = {
        'n_scored': int(len(scores)),
        'threshold': threshold,
        'n_fp': n_fp,
        'fpr_unsw_benign': round(fpr, 4),
        'target': 0.10,
        'pass': fpr <= 0.10,
        'score_p1': round(float(p_values[0]), 4),
        'score_p5': round(float(p_values[1]), 4),
        'score_p10': round(float(p_values[2]), 4),
    }

    out_path = BASE / 'results' / 'generalization' / 'madde2_dos_inspector_if_unsw.json'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'\nSaved: {out_path}')


if __name__ == '__main__':
    main()
