#!/usr/bin/env python3
"""Train IsolationForest anomaly model on benign-only data using v3b (15-feature) schema.

Outputs:
  models/dos_if_anomaly_v3b.pkl      — sklearn IsolationForest
  models/dos_if_anomaly_v3b_meta.json — threshold + feature metadata
"""
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE       = Path('/home/emirhan/bitirme')
DATA_DIR   = BASE / 'data'
MODEL_OUT  = BASE / 'models' / 'dos_if_anomaly_v3b.pkl'
META_OUT   = BASE / 'models' / 'dos_if_anomaly_v3b_meta.json'
SCALER_JSON = BASE / 'models' / 'dos_fpr_opt_v3b_scaler.json'

UNSW_FILES = [
    DATA_DIR / 'unsw' / 'UNSW-NB15_1.csv',
    DATA_DIR / 'unsw' / 'UNSW-NB15_2.csv',
    DATA_DIR / 'unsw' / 'UNSW-NB15_3.csv',
    DATA_DIR / 'unsw' / 'UNSW-NB15_4.csv',
]

UNSW_COLS = [
    'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
    'sttl','dttl','sloss','dloss','service','Sload','Dload','Spkts','Dpkts',
    'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat',
    'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
    'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label',
]

FEATURE_NAMES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'smeansz', 'dmeansz',
    'sintpkt', 'dintpkt', 'fwd_pkt_mean', 'bwd_pkt_mean',
    'fin_cnt', 'ack_cnt', 'syn_cnt', 'bwd_iat',
]

# load v3b scaler
with open(SCALER_JSON) as f:
    sc = json.load(f)
MEDIAN       = np.array(sc['median'])
IQR          = np.array(sc['iqr'])
LOG1P_IDX    = set(sc['log1p_indices'])  # {0,1,2,3,4,7,8,9,10,11,12,13,14}

MAX_BENIGN   = 400_000
CONTAMINATION = 0.01
N_ESTIMATORS  = 100
RANDOM_STATE  = 42


def build_features_unsw(df: pd.DataFrame) -> np.ndarray:
    """Map UNSW columns to v3b 15-feature schema. fin/ack/syn/bwd_iat not in UNSW → 0."""
    rename = {
        'dur': 'dur', 'Spkts': 'spkts', 'Dpkts': 'dpkts',
        'sbytes': 'sbytes', 'dbytes': 'dbytes',
        'smeansz': 'smeansz', 'dmeansz': 'dmeansz',
        'Sintpkt': 'sintpkt', 'Dintpkt': 'dintpkt',
    }
    out = pd.DataFrame(index=df.index)
    for src, dst in rename.items():
        out[dst] = pd.to_numeric(df[src], errors='coerce').fillna(0.0)

    # fwd_pkt_mean = sbytes/spkts, bwd_pkt_mean = dbytes/dpkts (same as CIC logic)
    out['fwd_pkt_mean'] = np.where(out['spkts'] > 0, out['sbytes'] / out['spkts'], 0.0)
    out['bwd_pkt_mean'] = np.where(out['dpkts'] > 0, out['dbytes'] / out['dpkts'], 0.0)
    # not available in UNSW
    out['fin_cnt'] = 0.0
    out['ack_cnt'] = 0.0
    out['syn_cnt'] = 0.0
    out['bwd_iat'] = out['dintpkt']  # best proxy

    return out[FEATURE_NAMES].values.astype(np.float64)


def apply_scaler(X: np.ndarray) -> np.ndarray:
    X = X.copy()
    for i in range(X.shape[1]):
        if i in LOG1P_IDX:
            X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    iqr_safe = np.where(IQR != 0, IQR, 1.0)
    return (X - MEDIAN) / iqr_safe


def load_unsw_benign() -> np.ndarray:
    dfs = []
    for p in UNSW_FILES:
        df = pd.read_csv(p, header=None, names=UNSW_COLS, low_memory=False)
        benign = df[pd.to_numeric(df['label'], errors='coerce') == 0]
        dfs.append(benign)
    combined = pd.concat(dfs, ignore_index=True)
    print(f"UNSW benign rows: {len(combined)}")
    return build_features_unsw(combined)


def load_cic_monday_benign() -> np.ndarray:
    """Load Monday CIC dump (all benign) from results dump CSVs."""
    dump_dir = BASE / 'results' / 'dos_inspector' / 'dump'
    monday = dump_dir / 'Monday-WorkingHours.pcap_ISCX.csv_dump.csv'
    if not monday.exists():
        # Try alternate locations
        for candidate in (BASE / 'results').rglob('Monday*dump.csv'):
            monday = candidate
            break
    if not monday.exists():
        print("Monday CIC dump not found, skipping CIC benign")
        return np.empty((0, 15))

    df = pd.read_csv(monday)
    print(f"CIC Monday rows: {len(df)}")
    # Map dump columns to feature names
    col_map = {
        'dur': 'dur', 'spkts': 'spkts', 'dpkts': 'dpkts',
        'sbytes': 'sbytes', 'dbytes': 'dbytes',
        'smeansz': 'smeansz', 'dmeansz': 'dmeansz',
        'sintpkt': 'sintpkt', 'dintpkt': 'dintpkt',
        'fwd_pkt_mean': 'fwd_pkt_mean', 'bwd_pkt_mean': 'bwd_pkt_mean',
        'fin_cnt': 'fin_cnt', 'ack_cnt': 'ack_cnt', 'syn_cnt': 'syn_cnt',
        'bwd_iat': 'bwd_iat',
    }
    out = pd.DataFrame(index=df.index)
    for src, dst in col_map.items():
        if src in df.columns:
            out[dst] = pd.to_numeric(df[src], errors='coerce').fillna(0.0)
        else:
            out[dst] = 0.0
    return out[FEATURE_NAMES].values.astype(np.float64)


def main():
    print("Loading benign data...")
    X_unsw = load_unsw_benign()
    X_cic  = load_cic_monday_benign()

    X_all = np.vstack([x for x in [X_unsw, X_cic] if len(x) > 0])
    print(f"Total benign rows before cap: {len(X_all)}")

    # cap and shuffle
    rng = np.random.default_rng(RANDOM_STATE)
    if len(X_all) > MAX_BENIGN:
        idx = rng.choice(len(X_all), MAX_BENIGN, replace=False)
        X_all = X_all[idx]
    print(f"Training on {len(X_all)} benign samples")

    X_scaled = apply_scaler(X_all)

    print("Training IsolationForest...")
    clf = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_scaled)

    scores = clf.score_samples(X_scaled)
    p1  = float(np.percentile(scores, 1))
    p5  = float(np.percentile(scores, 5))
    p10 = float(np.percentile(scores, 10))
    anomaly_rate = float(np.mean(scores < p5))

    print(f"Score stats: mean={scores.mean():.4f} std={scores.std():.4f}")
    print(f"Threshold p1={p1:.4f} p5={p5:.4f} p10={p10:.4f}")
    print(f"Anomaly rate @p5: {anomaly_rate:.4f}")

    with open(MODEL_OUT, 'wb') as f:
        pickle.dump(clf, f)
    print(f"Saved: {MODEL_OUT}")

    meta = {
        'threshold_p1':   p1,
        'threshold_p5':   p5,
        'threshold_p10':  p10,
        'anomaly_rate_train': anomaly_rate,
        'score_mean':     float(scores.mean()),
        'score_std':      float(scores.std()),
        'n_train':        len(X_all),
        'schema':         'v3b',
        'features':       FEATURE_NAMES,
        'log1p_indices':  sorted(LOG1P_IDX),
        'preprocessing':  'log1p on LOG1P_IDX then v3b RobustScaler (dos_fpr_opt_v3b_scaler.json)',
    }
    with open(META_OUT, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"Saved: {META_OUT}")


if __name__ == '__main__':
    main()
