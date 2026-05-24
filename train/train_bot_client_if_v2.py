#!/usr/bin/env python3
"""Train IsolationForest on bot_client Snort dump windows (all 22 features).

Uses /home/emirhan/bitirme/data/snort_dump/bot_client/ dump files.
Dump format: lb f0..f21 score src_ip (space-separated, header line starts with #)

Benign: label=0 from Mon/Tue/Thu (no bot traffic days)
Attack: label=0 from Friday (bot src IPs 192.168.10.5/8/9/12/14/15/17)

All 22 features present (tcp_win, fin_ratio, push_ratio etc. from real packets).
"""
import json, pickle
from pathlib import Path

import numpy as np

BASE       = Path('/home/emirhan/bitirme')
DUMP_DIR   = BASE / 'data' / 'snort_dump' / 'bot_client'
OUT_PKL    = BASE / 'models' / 'bot_client_if_anomaly_v2.pkl'
OUT_META   = BASE / 'models' / 'bot_client_if_anomaly_v2_meta.json'
SCALER_JSON = BASE / 'models' / 'bot_client_model_scaler.json'

FEATURE_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'iat_cv', 'port_entropy', 'port_ratio', 'rate',
    'ip_concentration', 'dst_ip_ratio', 'ip_entropy',
    'iat_q90_q10_ratio', 'time_density', 'port_to_ip_ratio',
    'handshake_ratio', 'incoming_ratio', 'data_density', 'rst_rate',
    'internal_ip_ratio', 'bytes_per_syn', 'fin_ratio', 'push_ratio', 'mean_window',
]
N_FEATURES = 22

# Friday bot src IPs (decimal: 192.168.10.x)
BOT_IPS = {
    3232238085,  # 192.168.10.5
    3232238088,  # 192.168.10.8
    3232238089,  # 192.168.10.9
    3232238092,  # 192.168.10.12 (0x0C)
    3232238094,  # 192.168.10.14
    3232238095,  # 192.168.10.15
    3232238097,  # 192.168.10.17
}


def load_dump(path: Path, label_filter=None, ip_filter=None, ip_exclude=None):
    """Load windows from dump file.

    label_filter: if set, only keep rows where col[0] == label_filter
    ip_filter:    if set (set of ints), only keep rows where src_ip in set
    ip_exclude:   if set (set of ints), exclude rows where src_ip in set
    """
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 24:
                continue
            try:
                lb = int(parts[0])
                features = [float(x) for x in parts[1:23]]
                src_ip = int(parts[24]) if len(parts) > 24 else int(parts[23])
            except (ValueError, IndexError):
                continue
            if label_filter is not None and lb != label_filter:
                continue
            if ip_filter is not None and src_ip not in ip_filter:
                continue
            if ip_exclude is not None and src_ip in ip_exclude:
                continue
            rows.append(features)
    return np.array(rows, dtype=np.float64) if rows else np.zeros((0, N_FEATURES))


def main():
    from sklearn.ensemble import IsolationForest

    print('=== bot_client IF v2 Training (Snort dump — full 22 features) ===\n')

    with open(SCALER_JSON) as f:
        sc = json.load(f)
    median   = np.array(sc['median'])
    iqr      = np.array(sc['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)

    # Benign: Mon/Tue/Thu — exclude bot IPs just in case
    benign_parts = []
    for day in ['monday', 'tuesday', 'thursday']:
        path = DUMP_DIR / f'{day}_dump.txt'
        X = load_dump(path, ip_exclude=BOT_IPS)
        print(f'  {day}: {len(X)} benign windows')
        benign_parts.append(X)

    X_benign_raw = np.vstack([x for x in benign_parts if len(x) > 0])
    print(f'Total benign windows: {len(X_benign_raw)}')

    # Check mean_window (f21) — was 0 in CSV, should be non-zero now
    win_vals = X_benign_raw[:, 21]
    print(f'mean_window (f21): min={win_vals.min():.1f} max={win_vals.max():.1f} mean={win_vals.mean():.1f}')

    # Scale
    X_benign = (X_benign_raw - median) / iqr_safe

    # 80/20 split
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(X_benign))
    n_val = max(int(len(X_benign) * 0.2), 1)
    X_val   = X_benign[idx[:n_val]]
    X_train = X_benign[idx[n_val:]]
    print(f'Train: {len(X_train)}, Val: {len(X_val)}\n')

    clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=1)
    clf.fit(X_train)
    print('IF trained.')

    train_scores  = clf.score_samples(X_train)
    threshold_p5  = float(np.percentile(train_scores, 5))
    threshold_p4  = float(np.percentile(train_scores, 4))
    threshold_p1  = float(np.percentile(train_scores, 1))
    threshold_p10 = float(np.percentile(train_scores, 10))
    print(f'Thresholds: p1={threshold_p1:.4f} p5={threshold_p5:.4f} p10={threshold_p10:.4f}')

    val_scores = clf.score_samples(X_val)
    fpr_p5 = float((val_scores < threshold_p5).mean())
    fpr_p4 = float((val_scores < threshold_p4).mean())
    print(f'Val FPR @ p5={fpr_p5:.4f}, @ p4={fpr_p4:.4f}')

    active_threshold = threshold_p4 if fpr_p5 > 0.05 else threshold_p5
    active_fpr       = fpr_p4       if fpr_p5 > 0.05 else fpr_p5
    print(f'Active threshold: {active_threshold:.4f}, FPR: {active_fpr:.4f}')

    # Attack recall: Friday bot IPs only
    friday_path = DUMP_DIR / 'friday_dump.txt'
    X_attack_raw = load_dump(friday_path, ip_filter=BOT_IPS)
    print(f'\nFriday bot windows: {len(X_attack_raw)}')

    attack_recall = None
    if len(X_attack_raw) > 0:
        X_attack = (X_attack_raw - median) / iqr_safe
        attack_scores  = clf.score_samples(X_attack)
        attack_recall  = float((attack_scores < active_threshold).mean())
        print(f'Attack recall @ threshold: {attack_recall:.4f}')
        print(f'Attack score: min={attack_scores.min():.4f} max={attack_scores.max():.4f} mean={attack_scores.mean():.4f}')
    else:
        print('No bot windows in Friday dump (check BOT_IPS set)')

    # Also show all Friday windows recall (includes non-bot IPs on Friday)
    X_friday_all = load_dump(friday_path)
    if len(X_friday_all) > 0:
        X_fri_scaled = (X_friday_all - median) / iqr_safe
        fri_scores = clf.score_samples(X_fri_scaled)
        recall_all = float((fri_scores < active_threshold).mean())
        print(f'Friday all windows recall: {recall_all:.4f} ({len(X_friday_all)} windows)')

    with open(OUT_PKL, 'wb') as f:
        pickle.dump(clf, f)

    meta = {
        'threshold_p1':   threshold_p1,
        'threshold_p5':   active_threshold,
        'threshold_p10':  threshold_p10,
        'val_benign_fpr': active_fpr,
        'attack_recall':  attack_recall,
        'n_train':        int(len(X_train)),
        'schema':         'bot_client',
        'features':       FEATURE_NAMES,
        'log1p_indices':  [],
        'scaler':         'bot_client_model_scaler.json',
        'preprocessing':  'raw RobustScaler (no log1p) — matches C++ bot_client_inspector.cc',
        'note':           'Trained on Snort dump (full 22 features from real PCAP replay)',
        'version':        'v2',
    }
    with open(OUT_META, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nSaved: {OUT_PKL}')
    print(f'Saved: {OUT_META}')
    if active_fpr <= 0.05 and (attack_recall or 0) >= 0.70:
        print('\n=== PASS ✅ (FPR ≤ 0.05, recall ≥ 0.70)')
    elif active_fpr <= 0.05:
        print(f'\n=== PARTIAL: FPR ✅ ({active_fpr:.4f}) but recall ⚠️ ({attack_recall:.4f})')
    else:
        print(f'\n=== WARNING: FPR {active_fpr:.4f} > 0.05')


if __name__ == '__main__':
    main()
