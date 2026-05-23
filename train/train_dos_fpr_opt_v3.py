#!/usr/bin/env python3
"""
train_dos_fpr_opt_v3.py — DoS FPR Optimization: Snort-native feature training

Uses Snort dump CSVs (17 features, 5-tuple labeled with CIC ground truth).
These features match EXACTLY what Snort extracts at inference time (2-packet).

Pipeline:
  1. Load labeled dump CSVs (Wednesday train 70%, test 30%; Monday+Tuesday benign)
  2. Compute RobustScaler from Snort-native benign flows
  3. Train XGBoost on Snort-native features
  4. Eval on Wednesday 30% held-out
  5. Save → models/dos_fpr_opt_v3.json + models/dos_fpr_opt_v3_scaler.json

Log1p applied to same indices as C++ dos_needs_log1p:
  0,1,2,3,4,7,8,9,10,11,12,13,14,15,16
  (dur, spkts, dpkts, sbytes, dbytes, swin, dwin,
   sintpkt, dintpkt, fwd_pkt_mean, bwd_pkt_mean,
   fin_cnt, ack_cnt, syn_cnt, bwd_iat)
"""

import json
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

BASE_DIR    = Path('/home/emirhan/bitirme')
LABELED_DIR = BASE_DIR / 'data/snort_dump/labeled'
MODEL_OUT   = BASE_DIR / 'models/dos_fpr_opt_v3.json'
SCALER_OUT  = BASE_DIR / 'models/dos_fpr_opt_v3_scaler.json'
RESULTS_DIR = BASE_DIR / 'results/fpr-opt-dos/phase2'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

N_FEATURES = 17
FEATURE_COLS = [
    'dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz',
    'swin','dwin','sintpkt','dintpkt',
    'fwd_pkt_mean','bwd_pkt_mean','fin_cnt','ack_cnt','syn_cnt','bwd_iat'
]
LOG1P_IDX = {0,1,2,3,4,7,8,9,10,11,12,13,14,15,16}


def apply_log1p_scale(X: np.ndarray, median: np.ndarray, iqr: np.ndarray) -> np.ndarray:
    X = X.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    for i in range(N_FEATURES):
        X[:, i] = (X[:, i] - median[i]) / iqr[i] if iqr[i] > 0 else 0.0
    return X.astype(np.float32)


def load_labeled(day: str):
    path = LABELED_DIR / f'{day}_labeled.csv'
    if not path.exists():
        log.warning(f'Not found: {path}')
        return None, None
    df = pd.read_csv(path, low_memory=False)
    for c in FEATURE_COLS:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df['label'].values.astype(np.float32)
    log.info(f'  [{day}] {len(df)} rows  attack={y.sum():.0f}  benign={(1-y).sum():.0f}')
    return X, y


def main():
    log.info('=' * 60)
    log.info('DoS FPR-Opt v3 — Snort-native features')
    log.info('=' * 60)

    # Load all days
    log.info('[1/6] Loading labeled dumps...')
    X_mon, y_mon = load_labeled('Monday')    # pure benign
    X_tue, y_tue = load_labeled('Tuesday')   # mostly benign + FTP-Patator/SSH-Patator
    X_wed, y_wed = load_labeled('Wednesday') # 63% attack (DoS)

    # Wednesday 70/30 split (stratified)
    X_wed_tr, X_wed_te, y_wed_tr, y_wed_te = train_test_split(
        X_wed, y_wed, test_size=0.30, random_state=42, stratify=y_wed)
    log.info(f'  Wednesday: train={len(y_wed_tr)} (att={y_wed_tr.sum():.0f}) '
             f'test={len(y_wed_te)} (att={y_wed_te.sum():.0f})')

    # Tuesday: keep only BENIGN for training context (FPR context)
    # Tuesday attacks are non-DoS (FTP-Patator, SSH-Patator) — exclude from positives
    # But include benign flows for broader FP context
    X_tue_ben = X_tue[y_tue == 0]
    y_tue_ben = y_tue[y_tue == 0]
    log.info(f'  Tuesday benign only: {len(y_tue_ben)} rows')

    # Train set: Wednesday 70% + Monday + Tuesday benign
    X_train = np.concatenate([X_wed_tr, X_mon, X_tue_ben], axis=0)
    y_train = np.concatenate([y_wed_tr, y_mon, y_tue_ben], axis=0)
    log.info(f'  Total train: {len(y_train)} rows  '
             f'attack={y_train.sum():.0f}  benign={(1-y_train).sum():.0f}')

    # Fit scaler on benign only (Snort-native benign distribution)
    log.info('[2/6] Fitting RobustScaler on benign flows...')
    X_benign = X_train[y_train == 0]
    X_ben_log = X_benign.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X_ben_log[:, i] = np.log1p(np.maximum(X_ben_log[:, i], 0.0))
    scaler = RobustScaler()
    scaler.fit(X_ben_log)
    median = scaler.center_
    iqr    = scaler.scale_
    log.info(f'  Scaler fit on {len(X_benign)} benign rows')
    log.info(f'  median[:6]: {median[:6]}')
    log.info(f'  iqr[:6]:    {iqr[:6]}')

    # Scale data
    log.info('[3/6] Scaling...')
    X_train_s = apply_log1p_scale(X_train, median, iqr)
    X_test_s  = apply_log1p_scale(X_wed_te, median, iqr)

    # Train
    log.info('[4/6] Training XGBoost (650 trees)...')
    model = xgb.XGBClassifier(
        n_estimators=650,
        max_depth=5,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.5,
        reg_alpha=0.2,
        gamma=0.5,
        min_child_weight=5,
        scale_pos_weight=float((y_train == 0).sum()) / float((y_train == 1).sum()),
        use_label_encoder=False,
        eval_metric='logloss',
        tree_method='hist',
        nthread=4,
        random_state=42,
    )
    model.fit(X_train_s, y_train,
              eval_set=[(X_train_s, y_train), (X_test_s, y_wed_te)],
              verbose=100)

    # Save
    log.info('[5/6] Saving...')
    model.save_model(str(MODEL_OUT))
    scaler_data = {
        'n_features': N_FEATURES,
        'log1p_indices': sorted(LOG1P_IDX),
        'median': median.tolist(),
        'iqr': iqr.tolist(),
        'feature_names': FEATURE_COLS
    }
    with open(SCALER_OUT, 'w') as f:
        json.dump(scaler_data, f, indent=2)
    log.info(f'  Model: {MODEL_OUT}')
    log.info(f'  Scaler: {SCALER_OUT}')

    # Evaluate
    log.info('[6/6] Wednesday 30% eval...')
    y_prob = model.predict_proba(X_test_s)[:, 1]
    thresholds = [0.50, 0.70, 0.80, 0.85, 0.90, 0.92, 0.95]

    log.info(f"{'t':>6} {'TP':>7} {'FP':>7} {'FN':>6} {'TN':>7} {'Rec':>7} {'Prec':>7} {'F1':>7} {'FPR':>8}")
    log.info('-' * 70)
    results = []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        cm = confusion_matrix(y_wed_te, y_pred)
        tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0
        rec  = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
        fpr  = fp/(fp+tn) if (fp+tn) > 0 else 0
        log.info(f"{t:>6.2f} {tp:>7} {fp:>7} {fn:>6} {tn:>7} "
                 f"{rec:>7.4f} {prec:>7.4f} {f1:>7.4f} {fpr:>8.4f}")
        results.append({'t': t, 'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'tn': int(tn),
                         'rec': rec, 'prec': prec, 'f1': f1, 'fpr': fpr})

    # Save results
    with open(RESULTS_DIR / 'wednesday_eval_v3.json', 'w') as f:
        json.dump({'results': results, 'scaler': scaler_data}, f, indent=2)
    log.info(f'\nResults: {RESULTS_DIR}/wednesday_eval_v3.json')

    # Print C++ scaler params
    log.info('')
    log.info('C++ scaler params → dos_inspector.cc:')
    log.info('// median[17]')
    log.info('{ ' + ', '.join(f'{v:.4f}' for v in median) + ' },')
    log.info('// iqr[17]')
    log.info('{ ' + ', '.join(f'{v:.4f}' for v in iqr) + ' }')


if __name__ == '__main__':
    main()
