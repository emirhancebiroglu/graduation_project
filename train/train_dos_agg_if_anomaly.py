#!/usr/bin/env python3
"""Train IsolationForest anomaly detector on dos_aggregator benign windows.

Uses the same dump files as train_dos_aggregator.py (results/dos_aggregator/dos_train_data_*.txt).
Benign = all non-attacker windows (y==0, weight==1 or 3 but not the flood attacker).
Applies same preprocessing as C++: log1p on cols [0,1,2,6] only, then RobustScaler.

Output:
    models/dos_agg_if_anomaly.pkl
    models/dos_agg_if_anomaly_meta.json
"""
import glob, json, os
import numpy as np
import pickle
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

BASE      = Path('/home/emirhan/bitirme')
DUMP_DIR  = BASE / 'results' / 'dos_aggregator'
OUT_PKL   = BASE / 'models' / 'dos_agg_if_anomaly.pkl'
OUT_META  = BASE / 'models' / 'dos_agg_if_anomaly_meta.json'
SCALER_JSON = BASE / 'models' / 'dos_aggregator_model_scaler.json'

SCANNER_IP   = 0xAC100001  # 172.16.0.1
DOS_ATTACK_DAYS = {'Wednesday', 'Friday'}

# log1p column indices — MUST match C++ dos_flow_tracker.h LOG1P_COLS
LOG1P_COLS = [0, 1, 2, 6]

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]


def load_benign_windows():
    """Load all benign (non-flood-attacker) windows from 5-day dumps."""
    all_X, all_y, all_src = [], [], []
    for fname in sorted(glob.glob(str(DUMP_DIR / 'dos_train_data_*.txt'))):
        day = os.path.basename(fname).replace('dos_train_data_', '').replace('.txt', '')
        data = np.loadtxt(fname, comments='#')
        if data.ndim == 1:
            data = data.reshape(1, -1)
        X_raw   = data[:, 1:8].astype(np.float64)
        src_ips = data[:, 9].astype(np.uint32)

        # label: attacker on flood days = positive (exclude from benign training)
        for i, ip in enumerate(src_ips):
            is_attacker_flood = (ip == SCANNER_IP) and (day in DOS_ATTACK_DAYS)
            all_X.append(X_raw[i])
            all_y.append(1 if is_attacker_flood else 0)
            all_src.append(ip)

        n_pos = sum(1 for i, ip in enumerate(src_ips)
                    if ip == SCANNER_IP and day in DOS_ATTACK_DAYS)
        print(f'{day}: {len(data)} windows, {n_pos} flood-attacker (excluded from benign)')

    X = np.vstack(all_X)
    y = np.array(all_y)
    return X, y


def preprocess(X_raw: np.ndarray) -> np.ndarray:
    """Apply log1p on cols [0,1,2,6] — matches C++ preprocess()."""
    X = X_raw.copy()
    for i in LOG1P_COLS:
        X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    return X


def main():
    print('=== dos_aggregator Isolation Forest Training ===')
    X_raw, y = load_benign_windows()

    X_benign_raw = X_raw[y == 0]
    X_attack_raw = X_raw[y == 1]
    print(f'\nBenign windows: {len(X_benign_raw)}')
    print(f'Attack windows: {len(X_attack_raw)}')

    # Load existing RobustScaler params from JSON (same as XGBoost uses)
    with open(SCALER_JSON) as f:
        sc = json.load(f)
    median = np.array(sc['median'])
    iqr    = np.array(sc['iqr'])

    def scale(X_raw):
        X = preprocess(X_raw)
        iqr_safe = np.where(iqr != 0, iqr, 1.0)
        return (X - median) / iqr_safe

    X_benign = scale(X_benign_raw)

    # 80/20 split for threshold validation
    n_val = max(int(len(X_benign) * 0.2), 1)
    idx = np.random.RandomState(42).permutation(len(X_benign))
    X_val_b   = X_benign[idx[:n_val]]
    X_train_b = X_benign[idx[n_val:]]
    print(f'Train benign: {len(X_train_b)}, Val benign: {len(X_val_b)}')

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_features=1.0,
        random_state=42,
        n_jobs=1,
    )
    clf.fit(X_train_b)
    print('IF trained.')

    # Threshold: p5 of score_samples on training benign
    train_scores = clf.score_samples(X_train_b)
    threshold_p5  = float(np.percentile(train_scores, 5))
    threshold_p1  = float(np.percentile(train_scores, 1))
    threshold_p10 = float(np.percentile(train_scores, 10))
    print(f'Threshold p1={threshold_p1:.4f}, p5={threshold_p5:.4f}, p10={threshold_p10:.4f}')

    # Validation: benign FPR
    val_scores = clf.score_samples(X_val_b)
    fpr_p5 = float((val_scores < threshold_p5).mean())
    print(f'Val benign FPR @ p5: {fpr_p5:.4f} (target ≤ 0.05)')

    # Attack recall (XGBoost already catches these — just measuring IF coverage)
    if len(X_attack_raw) > 0:
        X_attack = scale(X_attack_raw)
        attack_scores = clf.score_samples(X_attack)
        attack_recall = float((attack_scores < threshold_p5).mean())
        print(f'Attack anomaly recall @ p5: {attack_recall:.4f}')
    else:
        attack_recall = None
        print('No attack windows in dump (all benign days)')

    with open(OUT_PKL, 'wb') as f:
        pickle.dump(clf, f)

    meta = {
        'threshold_p1':    threshold_p1,
        'threshold_p5':    threshold_p5,
        'threshold_p10':   threshold_p10,
        'val_benign_fpr':  fpr_p5,
        'attack_recall':   attack_recall,
        'n_train':         int(len(X_train_b)),
        'schema':          'dos_aggregator',
        'features':        FEATURE_NAMES,
        'log1p_indices':   LOG1P_COLS,
        'scaler':          'dos_aggregator_model_scaler.json',
        'preprocessing':   'log1p on [0,1,2,6] then RobustScaler from dos_aggregator_model_scaler.json',
    }
    with open(OUT_META, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nSaved: {OUT_PKL}')
    print(f'Saved: {OUT_META}')
    print('\n=== PASS ✅' if fpr_p5 <= 0.05 else '\n=== WARNING: FPR > 0.05')


if __name__ == '__main__':
    main()
