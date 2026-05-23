#!/usr/bin/env python3
"""Train IsolationForest anomaly detector for dos_inspector zero-day layer.

Trains on benign-only flows (UNSW Normal + CIC Monday).
Exports via m2cgen to C header: plugins/dos_inspector/src/if_anomaly_model.h

Same 11 features + same preprocessing as dos_inspector:
  dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz, swin, dwin, sintpkt, dintpkt
  log1p on: sbytes, dbytes, spkts, dpkts, dur, sintpkt, dintpkt
  RobustScaler using dos_model.json scaler params (hardcoded v1)

Usage:
    python3 train/train_dos_if_anomaly.py
"""
import json
import logging
import pickle
from pathlib import Path

import m2cgen as m2c
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

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

SELECTED  = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']
LOG_COLS  = ['sbytes','dbytes','spkts','dpkts','dur','sintpkt','dintpkt']

# v1 scaler params (must match dos_inspector.cc g_scaler_params exactly)
V1_MEDIAN = [0.0157, 2.5649, 2.5649, 7.2937, 7.5071, 73.0, 89.0, 255.0, 255.0, 0.3841, 0.3472]
V1_IQR    = [0.1935, 2.7081, 2.6626, 2.7623, 4.4214, 72.0, 496.0, 255.0, 255.0, 2.1158, 1.9696]

CIC_COLS_MAP = {
    'Flow Duration':           'dur',
    'Total Fwd Packets':       'spkts',
    'Total Backward Packets':  'dpkts',
    'Total Length of Fwd Packets': 'sbytes',
    'Total Length of Bwd Packets': 'dbytes',
    'Average Packet Size':     'smeansz',
    'Avg Bwd Segment Size':    'dmeansz',
    'Init_Win_bytes_forward':  'swin',
    'Init_Win_bytes_backward': 'dwin',
    'Flow IAT Mean':           'sintpkt',
    'Bwd IAT Mean':            'dintpkt',
}


def preprocess(df: pd.DataFrame) -> np.ndarray:
    df = df[SELECTED].copy()
    df = df.apply(pd.to_numeric, errors='coerce')
    df.dropna(inplace=True)
    df = df[df >= 0].dropna()
    for col in LOG_COLS:
        if col in df.columns:
            df[col] = np.log1p(df[col])
    X = df.values.astype(np.float64)
    median = np.array(V1_MEDIAN)
    iqr    = np.array(V1_IQR)
    X = (X - median) / np.where(iqr != 0, iqr, 1.0)
    return X


def load_unsw_benign() -> pd.DataFrame:
    dfs = []
    for i in [1, 2, 3, 4]:
        path = BASE / 'data' / 'unsw' / f'UNSW-NB15_{i}.csv'
        df = pd.read_csv(path, header=None, names=UNSW_COLS, low_memory=False)
        if str(df.iloc[0, 0]).strip().lower() == 'srcip':
            df = df.iloc[1:]
        df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
        benign = df[df['label'] == 0][SELECTED]
        dfs.append(benign)
        logging.info(f'  UNSW_{i}: {len(benign):,} benign flows')
    return pd.concat(dfs, ignore_index=True)


def load_cic_monday_benign() -> pd.DataFrame:
    path = BASE / 'data' / 'raw' / 'cicids2017' / 'Monday-WorkingHours.pcap_ISCX.csv'
    df = pd.read_csv(path, low_memory=False, on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    df = df[df['Label'] == 'BENIGN']
    rename = {k: v for k, v in CIC_COLS_MAP.items() if k in df.columns}
    df = df.rename(columns=rename)
    available = [c for c in SELECTED if c in df.columns]
    missing   = [c for c in SELECTED if c not in df.columns]
    if missing:
        logging.warning(f'CIC Monday missing columns: {missing}')
    df = df[available]
    # CIC Flow Duration is in microseconds → convert to seconds
    if 'dur' in df.columns:
        df['dur'] = df['dur'] / 1e6
    # sintpkt/dintpkt also microseconds
    for col in ['sintpkt', 'dintpkt']:
        if col in df.columns:
            df[col] = df[col] / 1e6
    logging.info(f'  CIC Monday: {len(df):,} benign flows, cols={available}')
    return df


def main():
    logging.info('=== Isolation Forest Training — dos_inspector zero-day layer ===')

    logging.info('Loading UNSW benign...')
    unsw = load_unsw_benign()
    logging.info(f'UNSW total benign: {len(unsw):,}')

    logging.info('Loading CIC Monday benign...')
    cic = load_cic_monday_benign()

    combined = pd.concat([unsw, cic], ignore_index=True)
    logging.info(f'Combined: {len(combined):,} benign flows')

    logging.info('Preprocessing (log1p + v1 scaler)...')
    X = preprocess(combined)
    logging.info(f'After preprocessing: {X.shape}')

    # Sample cap — IF doesn't need >200K for good results, saves training time
    MAX_SAMPLES = 200_000
    if len(X) > MAX_SAMPLES:
        idx = np.random.RandomState(42).choice(len(X), MAX_SAMPLES, replace=False)
        X = X[idx]
        logging.info(f'Sampled down to {MAX_SAMPLES:,}')

    logging.info('Training IsolationForest (n_estimators=100, contamination=0.01)...')
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.01,
        max_samples='auto',
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X)
    logging.info('Training done.')

    # Evaluate on training data — expect ~99% labeled normal
    scores = clf.score_samples(X)
    preds  = clf.predict(X)  # 1=normal, -1=anomaly
    anomaly_rate = (preds == -1).mean()
    logging.info(f'Anomaly rate on benign train: {anomaly_rate:.4f} (target ~0.01)')
    logging.info(f'Score range: min={scores.min():.4f} max={scores.max():.4f} mean={scores.mean():.4f}')

    # Find threshold: score below which = anomaly flag
    # Use 1st percentile of benign scores → very low FPR on benign
    thresh_1pct  = float(np.percentile(scores, 1))
    thresh_5pct  = float(np.percentile(scores, 5))
    thresh_10pct = float(np.percentile(scores, 10))
    logging.info(f'Score percentiles: p1={thresh_1pct:.4f} p5={thresh_5pct:.4f} p10={thresh_10pct:.4f}')
    logging.info(f'Recommended IF threshold: {thresh_5pct:.4f} (5th percentile → ~5% FPR on benign)')

    # Save sklearn model
    model_path = BASE / 'models' / 'dos_if_anomaly.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
    logging.info(f'Sklearn model saved: {model_path}')

    # Save threshold metadata
    meta = {
        'threshold_p1':  thresh_1pct,
        'threshold_p5':  thresh_5pct,
        'threshold_p10': thresh_10pct,
        'anomaly_rate_train': float(anomaly_rate),
        'score_mean':  float(scores.mean()),
        'score_std':   float(scores.std()),
        'n_train':     int(len(X)),
        'features':    SELECTED,
        'preprocessing': 'log1p on sbytes,dbytes,spkts,dpkts,dur,sintpkt,dintpkt then v1 RobustScaler',
    }
    meta_path = BASE / 'models' / 'dos_if_anomaly_meta.json'
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    logging.info(f'Metadata saved: {meta_path}')

    # Export to C via m2cgen
    logging.info('Generating C code via m2cgen...')
    c_code = m2c.export_to_c(clf, function_name='if_score')

    header_path = BASE / 'plugins' / 'dos_inspector' / 'src' / 'if_anomaly_model.h'
    with open(header_path, 'w') as f:
        f.write('#pragma once\n')
        f.write('// AUTO-GENERATED by train_dos_if_anomaly.py — DO NOT EDIT\n')
        f.write('// IsolationForest anomaly scorer for dos_inspector zero-day layer\n')
        f.write('// Input: 11 features, preprocessed (log1p + v1 RobustScaler)\n')
        f.write('// Output: anomaly score (more negative = more anomalous)\n')
        f.write(f'// IF threshold: {thresh_5pct:.6f} (p5 of benign)\n\n')
        f.write(c_code)

    logging.info(f'C header saved: {header_path}')

    # Check header size
    lines = open(header_path).readlines()
    logging.info(f'C header: {len(lines)} lines')

    print(f'\n=== SONUÇ ===')
    print(f'Model:     {model_path}')
    print(f'C header:  {header_path} ({len(lines)} lines)')
    print(f'Threshold: {thresh_5pct:.6f} (p5) — use this in dos_inspector.cc')
    print(f'FPR on benign train: {anomaly_rate:.4f}')


if __name__ == '__main__':
    main()
