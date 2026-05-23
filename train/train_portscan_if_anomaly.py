#!/usr/bin/env python3
"""Train IsolationForest anomaly detector on portscan benign windows.

Uses data/processed/portscan_v4d/ — already log1p+scaled (same preprocessing as XGBoost).
Benign = X_train[y_train==0] + X_val[y_val==0] + X_test[y_test==0].

Output:
    models/portscan_if_anomaly.pkl
    models/portscan_if_anomaly_meta.json
"""
import json, pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

BASE       = Path('/home/emirhan/bitirme')
DATA_DIR   = BASE / 'data' / 'processed' / 'portscan_v4d'
OUT_PKL    = BASE / 'models' / 'portscan_if_anomaly.pkl'
OUT_META   = BASE / 'models' / 'portscan_if_anomaly_meta.json'
SCALER_JSON = BASE / 'models' / 'portscan_aggregator_model_v4d_scaler.json'

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]


def main():
    print('=== portscan Isolation Forest Training ===')

    # Load pre-scaled data (log1p_all=true + RobustScaler already applied)
    X_tr = np.load(DATA_DIR / 'X_train.npy')
    y_tr = np.load(DATA_DIR / 'y_train.npy')
    X_va = np.load(DATA_DIR / 'X_val.npy')
    y_va = np.load(DATA_DIR / 'y_val.npy')
    X_te = np.load(DATA_DIR / 'X_test.npy')
    y_te = np.load(DATA_DIR / 'y_test.npy')

    # Combine all benign (y==0) for training
    X_all = np.vstack([X_tr, X_va, X_te])
    y_all = np.concatenate([y_tr, y_va, y_te])

    X_benign = X_all[y_all == 0]
    X_attack = X_all[y_all == 1]
    print(f'Total: {len(X_all)}, benign: {len(X_benign)}, attack: {len(X_attack)}')

    # 80/20 split for threshold validation
    idx = np.random.RandomState(42).permutation(len(X_benign))
    n_val = max(int(len(X_benign) * 0.2), 1)
    X_val_b   = X_benign[idx[:n_val]]
    X_train_b = X_benign[idx[n_val:]]
    print(f'Train benign: {len(X_train_b)}, Val benign: {len(X_val_b)}')

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.04,
        max_features=1.0,
        random_state=42,
        n_jobs=1,
    )
    clf.fit(X_train_b)
    print('IF trained.')

    # Threshold from percentile of training benign scores
    train_scores = clf.score_samples(X_train_b)
    threshold_p5  = float(np.percentile(train_scores, 5))
    threshold_p4  = float(np.percentile(train_scores, 4))
    threshold_p1  = float(np.percentile(train_scores, 1))
    threshold_p10 = float(np.percentile(train_scores, 10))
    print(f'Threshold p1={threshold_p1:.4f}, p4={threshold_p4:.4f}, p5={threshold_p5:.4f}, p10={threshold_p10:.4f}')

    val_scores = clf.score_samples(X_val_b)
    fpr_p5 = float((val_scores < threshold_p5).mean())
    fpr_p4 = float((val_scores < threshold_p4).mean())
    print(f'Val benign FPR @ p5: {fpr_p5:.4f}, @ p4: {fpr_p4:.4f} (target ≤ 0.05)')

    # Use p4 if p5 exceeds target FPR
    threshold_p5 = threshold_p4 if fpr_p5 > 0.05 else threshold_p5
    fpr_p5 = fpr_p4 if fpr_p5 > 0.05 else fpr_p5
    print(f'Active threshold: {threshold_p5:.4f}, FPR: {fpr_p5:.4f}')

    attack_scores = clf.score_samples(X_attack)
    attack_recall = float((attack_scores < threshold_p5).mean())
    print(f'Attack anomaly recall @ p5: {attack_recall:.4f}')

    with open(OUT_PKL, 'wb') as f:
        pickle.dump(clf, f)

    meta = {
        'threshold_p1':   threshold_p1,
        'threshold_p5':   threshold_p5,
        'threshold_p10':  threshold_p10,
        'val_benign_fpr': fpr_p5,
        'attack_recall':  attack_recall,
        'n_train':        int(len(X_train_b)),
        'schema':         'portscan',
        'features':       FEATURE_NAMES,
        'log1p_indices':  list(range(7)),
        'scaler':         'portscan_aggregator_model_v4d_scaler.json',
        'preprocessing':  'log1p(all 7) then RobustScaler (portscan_aggregator_model_v4d_scaler.json)',
        'note':           'Input to score() must be pre-scaled (same as XGBoost input)',
    }
    with open(OUT_META, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nSaved: {OUT_PKL}')
    print(f'Saved: {OUT_META}')
    print('\n=== PASS ✅' if fpr_p5 <= 0.05 else '\n=== WARNING: FPR > 0.05')


if __name__ == '__main__':
    main()
