#!/usr/bin/env python3
"""
train_dos_fpr_opt.py — DoS Inspector FPR Optimization (v2 model, 17 features)

Feature schema (indices match C++ DosFeatureIndex enum):
  0  dur          — flow duration (log1p)
  1  spkts        — src packet count (log1p)
  2  dpkts        — dst packet count (log1p)
  3  sbytes       — src byte count (log1p)
  4  dbytes       — dst byte count (log1p)
  5  smeansz      — mean src packet size
  6  dmeansz      — mean dst packet size
  7  swin         — src TCP window
  8  dwin         — dst TCP window
  9  sintpkt      — mean src inter-arrival time ms (log1p)
 10  dintpkt      — mean dst inter-arrival time ms (log1p)
 11  fwd_pkt_mean — Fwd Packet Length Mean (log1p) — FP separator
 12  bwd_pkt_mean — Bwd Packet Length Mean (log1p) — FP separator (strongest Cohen d=1.75)
 13  fin_cnt      — FIN flag count (log1p)
 14  ack_cnt      — ACK flag count (log1p)
 15  syn_cnt      — SYN flag count (log1p)
 16  bwd_iat      — mean bwd inter-arrival time ms (log1p)

Pipeline:
  1. Load UNSW base (500 trees, 17 features — 4 new set to 0)
  2. Load ALL CIC CSVs → keep only BENIGN + DoS + Heartbleed rows
  3. Map 17 features from CIC columns
  4. Compute RobustScaler from CIC training split
  5. Fine-tune XGBoost: 150 additional trees, lr=0.02
  6. Save model → models/dos_fpr_opt_v2.json
  7. Save scaler JSON → models/dos_fpr_opt_v2_scaler.json
  8. Evaluate on Wednesday held-out split
"""

import json
import glob
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path('/home/emirhan/bitirme')
UNSW_DATA  = BASE_DIR / 'data/processed'
CIC_DIR    = BASE_DIR / 'data/raw/cicids2017'
MODEL_OUT  = BASE_DIR / 'models/dos_fpr_opt_v2.json'
SCALER_OUT = BASE_DIR / 'models/dos_fpr_opt_v2_scaler.json'
RESULTS_DIR = BASE_DIR / 'results/fpr-opt-dos/phase2'

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Feature name lists ─────────────────────────────────────────────────────────
# 11 original features (indices 0-10) — UNSW column mapping
UNSW_FEAT_MAP = {
    'dur': 'dur', 'Spkts': 'spkts', 'Dpkts': 'dpkts',
    'sbytes': 'sbytes', 'dbytes': 'dbytes',
    'smeansz': 'smeansz', 'dmeansz': 'dmeansz',
    'swin': 'swin', 'dwin': 'dwin',
    'Sintpkt': 'sintpkt', 'Dintpkt': 'dintpkt',
}
UNSW_COLS = list(UNSW_FEAT_MAP.keys())  # original case

# CIC column mapping (stripped names)
CIC_FEAT_MAP = {
    'Flow Duration':         0,   # dur (us → s conversion needed)
    'Total Fwd Packets':     1,   # spkts
    'Total Backward Packets':2,   # dpkts
    'Total Length of Fwd Packets': 3,  # sbytes
    'Total Length of Bwd Packets': 4,  # dbytes
    'Fwd Packet Length Mean':  5,  # smeansz (also fwd_pkt_mean)
    'Bwd Packet Length Mean':  6,  # dmeansz (also bwd_pkt_mean)
    'Init_Win_bytes_forward':  7,  # swin
    'Init_Win_bytes_backward': 8,  # dwin
    'Fwd IAT Mean':            9,  # sintpkt (us → ms)
    'Bwd IAT Mean':           10,  # dintpkt (us → ms) AND bwd_iat [16]
    'Fwd Packet Length Mean': 11,  # fwd_pkt_mean (same as smeansz)
    'Bwd Packet Length Mean': 12,  # bwd_pkt_mean (same as dmeansz)
    'FIN Flag Count':         13,  # fin_cnt
    'ACK Flag Count':         14,  # ack_cnt
    'SYN Flag Count':         15,  # syn_cnt
    # bwd_iat [16] = same as Bwd IAT Mean [10] already covered
}

DOS_LABELS = {'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest',
              'Heartbleed', 'DoS attacks-Hulk', 'DoS attacks-GoldenEye',
              'DoS attacks-Slowloris', 'DoS attacks-Slowhttptest',
              'Web Attack  Brute Force', 'BENIGN'}
# Keep only BENIGN and DoS variants

LOG1P_IDX = {0,1,2,3,4,7,8,9,10,11,12,13,14,15,16}  # swin(7)+dwin(8) added for distribution normalization

N_FEATURES = 17

# ── UNSW loading ──────────────────────────────────────────────────────────────

def load_unsw():
    """Load pre-processed UNSW arrays, extend to 17 features (pad with 0)."""
    X_files = sorted(glob.glob(str(UNSW_DATA / 'X_*.npy')))
    y_files = sorted(glob.glob(str(UNSW_DATA / 'y_*.npy')))
    if not X_files:
        log.warning('No UNSW processed arrays found — loading from raw CSV')
        return load_unsw_from_raw()

    X_list, y_list = [], []
    for xf, yf in zip(X_files, y_files):
        X_list.append(np.load(xf))
        y_list.append(np.load(yf))
    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    log.info(f'UNSW loaded: {X.shape[0]} rows, {X.shape[1]} features')

    if X.shape[1] == 11:
        # Pad 6 new features with 0 (unknown for UNSW)
        zeros = np.zeros((X.shape[0], 6), dtype=X.dtype)
        X = np.concatenate([X, zeros], axis=1)
        log.info(f'UNSW extended to 17 features (new 6 = 0)')
    return X, y


def load_unsw_from_raw():
    """Fallback: load UNSW from raw CSVs."""
    UNSW_COLS_ALL = [
        'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
        'sttl','dttl','sloss','dloss','service','Sload','Dload','Spkts','Dpkts',
        'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
        'Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat',
        'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
        'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
        'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label'
    ]
    raw_files = sorted(glob.glob(str(BASE_DIR / 'data/unsw/UNSW-NB15_*.csv')))
    dfs = []
    for f in raw_files:
        df = pd.read_csv(f, header=None, names=UNSW_COLS_ALL, low_memory=False)
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)

    feat_cols = ['dur','Spkts','Dpkts','sbytes','dbytes','smeansz','dmeansz',
                 'swin','dwin','Sintpkt','Dintpkt']
    for c in feat_cols:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)

    X11 = df[feat_cols].values.astype(np.float32)
    y = (df['label'].astype(str).str.strip() != '0').astype(np.float32).values
    zeros = np.zeros((X11.shape[0], 6), dtype=X11.dtype)
    X = np.concatenate([X11, zeros], axis=1)
    log.info(f'UNSW raw loaded: {X.shape[0]} rows')
    return X, y


# ── CIC loading ───────────────────────────────────────────────────────────────

def load_cic_csv(path: Path, dos_only: bool = True):
    """
    Load one CIC CSV, extract 17 features.
    dos_only=True: keep BENIGN + DoS/Heartbleed rows only.
    Returns (X, y) or None if no usable rows.
    """
    try:
        df = pd.read_csv(path, low_memory=False, on_bad_lines='skip',
                         encoding='utf-8', encoding_errors='replace')
    except Exception as e:
        log.warning(f'Cannot read {path.name}: {e}')
        return None

    df.columns = df.columns.str.strip()
    if 'Label' not in df.columns:
        log.warning(f'No Label column in {path.name}')
        return None

    df['Label'] = df['Label'].str.strip()

    if dos_only:
        keep_mask = (df['Label'] == 'BENIGN') | df['Label'].str.startswith('DoS') | \
                    (df['Label'] == 'Heartbleed')
        df = df[keep_mask].copy()

    if len(df) == 0:
        return None

    y = (df['Label'] != 'BENIGN').astype(np.float32).values

    X = np.zeros((len(df), N_FEATURES), dtype=np.float32)

    def col(name):
        return pd.to_numeric(df[name], errors='coerce').fillna(0.0).clip(lower=0.0).values \
               if name in df.columns else np.zeros(len(df), dtype=np.float64)

    # Duration: CIC is in microseconds → convert to seconds
    dur_raw = pd.to_numeric(df.get('Flow Duration', pd.Series(0, index=df.index)),
                             errors='coerce').fillna(0.0).values
    X[:, 0]  = np.maximum(dur_raw / 1e6, 0.0)         # dur (seconds)
    X[:, 1]  = col('Total Fwd Packets')
    X[:, 2]  = col('Total Backward Packets')
    X[:, 3]  = col('Total Length of Fwd Packets')
    X[:, 4]  = col('Total Length of Bwd Packets')
    X[:, 5]  = col('Fwd Packet Length Mean')           # smeansz
    X[:, 6]  = col('Bwd Packet Length Mean')           # dmeansz
    # swin/dwin: CIC Init_Win_bytes can be -1 → clip to 0
    swin_raw = pd.to_numeric(df.get('Init_Win_bytes_forward',
                                     pd.Series(0, index=df.index)),
                              errors='coerce').fillna(0.0).values
    dwin_raw = pd.to_numeric(df.get('Init_Win_bytes_backward',
                                     pd.Series(0, index=df.index)),
                              errors='coerce').fillna(0.0).values
    X[:, 7]  = np.maximum(swin_raw, 0.0)
    X[:, 8]  = np.maximum(dwin_raw, 0.0)
    # IAT: CIC in microseconds → ms
    fwd_iat  = pd.to_numeric(df.get('Fwd IAT Mean', pd.Series(0, index=df.index)),
                              errors='coerce').fillna(0.0).values
    bwd_iat  = pd.to_numeric(df.get('Bwd IAT Mean', pd.Series(0, index=df.index)),
                              errors='coerce').fillna(0.0).values
    X[:, 9]  = np.maximum(fwd_iat / 1e3, 0.0)          # sintpkt (ms)
    X[:, 10] = np.maximum(bwd_iat / 1e3, 0.0)          # dintpkt (ms)
    X[:, 11] = X[:, 5]                                  # fwd_pkt_mean = smeansz
    X[:, 12] = X[:, 6]                                  # bwd_pkt_mean = dmeansz
    X[:, 13] = col('FIN Flag Count')
    X[:, 14] = col('ACK Flag Count')
    X[:, 15] = col('SYN Flag Count')
    X[:, 16] = X[:, 10]                                 # bwd_iat = dintpkt

    log.info(f'  {path.name}: {len(df)} rows (attack={y.sum():.0f}, benign={(1-y).sum():.0f})')
    return X, y


# ── Scaler ───────────────────────────────────────────────────────────────────

def compute_scaler_params(X: np.ndarray):
    """Compute median and IQR for each feature (RobustScaler)."""
    scaler = RobustScaler()
    scaler.fit(X)
    return scaler.center_, scaler.scale_  # median, IQR


def apply_log1p_scaler(X: np.ndarray, median: np.ndarray, iqr: np.ndarray) -> np.ndarray:
    """Apply log1p to designated features, then RobustScale."""
    X = X.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    for i in range(N_FEATURES):
        if iqr[i] > 0:
            X[:, i] = (X[:, i] - median[i]) / iqr[i]
        else:
            X[:, i] = 0.0
    return X.astype(np.float32)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    log.info('=' * 60)
    log.info('DoS FPR-Opt v2 Training — 17 features')
    log.info('=' * 60)

    # 1. Load UNSW
    log.info('[1/7] Loading UNSW data...')
    X_unsw, y_unsw = load_unsw()
    log.info(f'  UNSW: {X_unsw.shape[0]} rows, pos={y_unsw.sum():.0f}')

    # 2. Load CIC — all days, DoS+BENIGN only
    log.info('[2/7] Loading CIC-IDS2017 (DoS+BENIGN only)...')
    X_cic_list, y_cic_list = [], []
    for csv_path in sorted(CIC_DIR.glob('*.csv')):
        result = load_cic_csv(csv_path, dos_only=True)
        if result is not None:
            X_cic_list.append(result[0])
            y_cic_list.append(result[1])

    X_cic = np.concatenate(X_cic_list, axis=0)
    y_cic = np.concatenate(y_cic_list, axis=0)
    log.info(f'  CIC total: {X_cic.shape[0]} rows, pos={y_cic.sum():.0f}, neg={(1-y_cic).sum():.0f}')

    # Wednesday: 70% fine-tune train, 30% held-out eval
    # DoS attacks exist ONLY in Wednesday — must include in fine-tune
    wed_result = load_cic_csv(CIC_DIR / 'Wednesday-workingHours.pcap_ISCX.csv', dos_only=True)
    X_wed_all, y_wed_all = wed_result
    X_wed_tr, X_wed, y_wed_tr, y_wed = train_test_split(
        X_wed_all, y_wed_all, test_size=0.30, random_state=42, stratify=y_wed_all)
    log.info(f'  Wednesday train={len(y_wed_tr)} (pos={y_wed_tr.sum():.0f}) '
             f'eval={len(y_wed)} (pos={y_wed.sum():.0f})')

    # CIC fine-tune = Wednesday 70% train + all other days (benign only, for FP context)
    mask_not_wed = []
    for csv_path in sorted(CIC_DIR.glob('*.csv')):
        result = load_cic_csv(csv_path, dos_only=True)
        if result is None:
            continue
        n = len(result[1])
        is_wed = 'Wednesday' in csv_path.name
        mask_not_wed.extend([not is_wed] * n)
    mask_not_wed = np.array(mask_not_wed)
    X_other = X_cic[mask_not_wed]
    y_other = y_cic[mask_not_wed]
    X_cic_train = np.concatenate([X_wed_tr, X_other], axis=0)
    y_cic_train = np.concatenate([y_wed_tr, y_other], axis=0)
    log.info(f'  CIC fine-tune total: {X_cic_train.shape[0]} rows, pos={y_cic_train.sum():.0f}')

    # 3. Fit RobustScaler on CIC benign only (production domain = CIC)
    # UNSW swin/dwin max=255; CIC swin median=8192 — using CIC scaler prevents scale mismatch
    log.info('[3/7] Computing RobustScaler (CIC benign)...')
    X_for_scaler = X_cic_train[y_cic_train == 0][:100_000]  # cap at 100K benign rows

    # Apply log1p before fitting scaler (consistent with inference)
    X_for_scaler_log = X_for_scaler.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X_for_scaler_log[:, i] = np.log1p(np.maximum(X_for_scaler_log[:, i], 0.0))

    scaler = RobustScaler()
    scaler.fit(X_for_scaler_log)
    median = scaler.center_
    iqr    = scaler.scale_
    log.info('  Scaler fit complete')

    # 4. Scale all datasets
    log.info('[4/7] Scaling data...')
    X_unsw_s = apply_log1p_scaler(X_unsw, median, iqr)
    X_cic_tr_s = apply_log1p_scaler(X_cic_train, median, iqr)
    X_wed_s  = apply_log1p_scaler(X_wed, median, iqr)

    # 5. Train
    log.info('[5/7] Training XGBoost (UNSW base + CIC fine-tune)...')

    # Stage A: UNSW base (500 trees)
    log.info('  Stage A: UNSW base (500 trees)...')
    model_base = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        reg_alpha=0.1,
        gamma=0.3,
        use_label_encoder=False,
        eval_metric='logloss',
        tree_method='hist',
        nthread=4,
        random_state=42,
    )
    model_base.fit(X_unsw_s, y_unsw,
                   eval_set=[(X_unsw_s, y_unsw)],
                   verbose=100)

    # Stage B: CIC fine-tune — DoS-only labels, 150 extra trees
    log.info('  Stage B: CIC fine-tune (150 trees, DoS-only labels)...')
    # Save base to temp then load for fine-tune
    tmp_base = '/tmp/dos_fpr_opt_base.json'
    model_base.save_model(tmp_base)

    model_ft = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=4,
        learning_rate=0.02,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.5,
        reg_alpha=0.2,
        gamma=0.5,
        use_label_encoder=False,
        eval_metric='logloss',
        tree_method='hist',
        nthread=4,
        random_state=42,
    )
    model_ft.fit(X_cic_tr_s, y_cic_train,
                 xgb_model=tmp_base,
                 eval_set=[(X_cic_tr_s, y_cic_train)],
                 verbose=50)

    # 6. Save model + scaler
    log.info('[6/7] Saving model and scaler...')
    model_ft.save_model(str(MODEL_OUT))
    log.info(f'  Model saved: {MODEL_OUT}')

    scaler_data = {
        'n_features': N_FEATURES,
        'log1p_indices': sorted(LOG1P_IDX),
        'median': median.tolist(),
        'iqr': iqr.tolist(),
        'feature_names': [
            'dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz',
            'swin','dwin','sintpkt','dintpkt',
            'fwd_pkt_mean','bwd_pkt_mean','fin_cnt','ack_cnt','syn_cnt','bwd_iat'
        ]
    }
    with open(SCALER_OUT, 'w') as f:
        json.dump(scaler_data, f, indent=2)
    log.info(f'  Scaler saved: {SCALER_OUT}')

    # 7. Evaluate on Wednesday held-out
    log.info('[7/7] Wednesday evaluation...')
    thresholds = [0.50, 0.70, 0.80, 0.85, 0.90, 0.92, 0.95]

    y_prob = model_ft.predict_proba(X_wed_s)[:, 1]
    results = []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        cm = confusion_matrix(y_wed, y_pred)
        tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0
        rec  = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
        fpr  = fp/(fp+tn) if (fp+tn) > 0 else 0
        results.append({'t': t, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                         'prec': prec, 'rec': rec, 'f1': f1, 'fpr': fpr})

    log.info('')
    log.info('Wednesday CIC Eval (DoS only):')
    log.info(f"{'t':>6} {'TP':>7} {'FP':>7} {'FN':>5} {'Recall':>7} {'Prec':>7} {'F1':>7} {'FPR':>8}")
    log.info('-' * 60)
    for r in results:
        log.info(f"{r['t']:>6.2f} {r['tp']:>7} {r['fp']:>7} {r['fn']:>5} "
                 f"{r['rec']:>7.4f} {r['prec']:>7.4f} {r['f1']:>7.4f} {r['fpr']:>8.4f}")

    # Save results
    # Convert numpy types for JSON
    def to_py(v):
        if hasattr(v, 'item'): return v.item()
        return v
    results_clean = [{k: to_py(v) for k, v in r.items()} for r in results]

    out_path = RESULTS_DIR / 'wednesday_eval.json'
    with open(out_path, 'w') as f:
        json.dump({'results': results_clean, 'scaler': scaler_data}, f, indent=2)
    log.info(f'\nResults saved: {out_path}')

    # Print scaler params for C++ update
    log.info('')
    log.info('C++ scaler params (copy to dos_inspector.cc):')
    log.info('// median[17]')
    log.info('{ ' + ', '.join(f'{v:.4f}' for v in median) + ' },')
    log.info('// iqr[17]')
    log.info('{ ' + ', '.join(f'{v:.4f}' for v in iqr) + ' }')


if __name__ == '__main__':
    main()
