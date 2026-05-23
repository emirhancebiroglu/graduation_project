#!/usr/bin/env python3
"""Train IsolationForest anomaly detector on bot_client benign windows.

Generates benign windows from CICIDS Mon-Thu BENIGN flows using the same
22-feature computation as C++ bot_client_flow_tracker.h compute_features().
No log1p — raw RobustScaler (same as production model).

Output:
    models/bot_client_if_anomaly.pkl
    models/bot_client_if_anomaly_meta.json
"""
import json, math, os, pickle, random, warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

warnings.filterwarnings('ignore')

BASE         = Path('/home/emirhan/bitirme')
CICIDS_DIR   = BASE / 'data' / 'raw' / 'cicids2017'
OUT_PKL      = BASE / 'models' / 'bot_client_if_anomaly.pkl'
OUT_META     = BASE / 'models' / 'bot_client_if_anomaly_meta.json'
SCALER_JSON  = BASE / 'models' / 'bot_client_model_scaler.json'

WINDOW_SEC = 300
MIN_SYNS   = 3

FEATURE_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'iat_cv', 'port_entropy', 'port_ratio', 'rate',
    'ip_concentration', 'dst_ip_ratio', 'ip_entropy',
    'iat_q90_q10_ratio', 'time_density', 'port_to_ip_ratio',
    'handshake_ratio', 'incoming_ratio', 'data_density', 'rst_rate',
    'internal_ip_ratio', 'bytes_per_syn', 'fin_ratio', 'push_ratio', 'mean_window',
]
N_FEATURES = 22

BENIGN_SOURCES = [
    ('Monday-WorkingHours.pcap_ISCX.csv', 80000),
    ('Tuesday-WorkingHours.pcap_ISCX.csv', 60000),
    ('Wednesday-workingHours.pcap_ISCX.csv', 40000),
    ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 40000),
    ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 40000),
]
BOT_SRC_IPS = {
    '192.168.10.5', '192.168.10.8', '192.168.10.9',
    '192.168.10.14', '192.168.10.15', '192.168.10.12', '192.168.10.17',
}

def load_bot_flows(path, src_ips):
    """Load flows from known bot src IPs (any label) for attack recall measurement."""
    if not path.exists():
        print(f'  SKIP (not found): {path.name}')
        return []
    cols = [' Label', ' Source IP', ' Destination IP', ' Destination Port',
            ' Timestamp', ' Total Fwd Packets', ' Total Backward Packets',
            'Total Length of Fwd Packets']
    try:
        df = pd.read_csv(path, low_memory=False, encoding='cp1252',
                         usecols=cols, dtype=str)
    except Exception as e:
        print(f'  Error {path.name}: {e}')
        return []
    df = df[df[' Source IP'].str.strip().isin(src_ips)]
    flows = []
    for _, r in df.iterrows():
        try:
            ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except Exception:
            ts = 0.0
        try:
            dport = int(float(r[' Destination Port']))
        except Exception:
            dport = 0
        try:
            fwd_pkts = int(float(r[' Total Fwd Packets']))
        except Exception:
            fwd_pkts = 1
        try:
            bwd_pkts = int(float(r[' Total Backward Packets']))
        except Exception:
            bwd_pkts = 0
        try:
            fwd_bytes = int(float(r['Total Length of Fwd Packets']))
        except Exception:
            fwd_bytes = 0
        flows.append({
            'src_ip': r[' Source IP'].strip(),
            'dst_ip': r[' Destination IP'].strip(),
            'dst_port': dport,
            'timestamp': ts,
            'fwd_pkts': fwd_pkts,
            'bwd_pkts': bwd_pkts,
            'fwd_bytes': fwd_bytes,
        })
    print(f'  {path.name}: {len(flows)} flows from {len(src_ips)} bot IPs')
    return flows


RFC1918 = lambda ip: (
    ip.startswith('10.') or
    (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or
    ip.startswith('192.168.')
)


def load_benign_flows(path, cap):
    if not path.exists():
        print(f'  SKIP (not found): {path.name}')
        return []
    cols = [' Label', ' Source IP', ' Destination IP', ' Destination Port',
            ' Timestamp', ' Total Fwd Packets', ' Total Backward Packets',
            'Total Length of Fwd Packets']
    try:
        df = pd.read_csv(path, low_memory=False, encoding='cp1252',
                         usecols=cols, nrows=cap*2, dtype=str)
    except Exception as e:
        print(f'  Error {path.name}: {e}')
        return []
    df = df[df[' Label'].str.strip() == 'BENIGN']
    if len(df) > cap:
        df = df.sample(cap, random_state=42)
    flows = []
    for _, r in df.iterrows():
        try:
            ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except Exception:
            ts = 0.0
        try:
            dport = int(float(r[' Destination Port']))
        except Exception:
            dport = 0
        try:
            fwd_pkts = int(float(r[' Total Fwd Packets']))
        except Exception:
            fwd_pkts = 1
        try:
            bwd_pkts = int(float(r[' Total Backward Packets']))
        except Exception:
            bwd_pkts = 0
        try:
            fwd_bytes = int(float(r['Total Length of Fwd Packets']))
        except Exception:
            fwd_bytes = 0
        flows.append({
            'src_ip': r[' Source IP'].strip(),
            'dst_ip': r[' Destination IP'].strip(),
            'dst_port': dport,
            'timestamp': ts,
            'fwd_pkts': fwd_pkts,
            'bwd_pkts': bwd_pkts,
            'fwd_bytes': fwd_bytes,
        })
    print(f'  {path.name}: {len(flows)} BENIGN flows')
    return flows


def iat_cv(timestamps):
    if len(timestamps) < 3:
        return 0.0
    diffs = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    diffs = [d for d in diffs if d > 1e-6]
    if len(diffs) < 2:
        return 0.0
    m = np.mean(diffs)
    s = np.std(diffs)
    return s / m if m > 1e-6 else 0.0


def iat_q90_q10(timestamps):
    if len(timestamps) < 3:
        return 0.0
    diffs = sorted([timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))
                    if timestamps[i] - timestamps[i-1] > 1e-6])
    if len(diffs) < 4:
        return 0.0
    p10 = diffs[len(diffs) // 10]
    p90 = diffs[(9 * len(diffs)) // 10]
    return p90 / p10 if p10 > 1e-6 else 0.0


def ip_concentration(dst_ip_counts, syn_count):
    if syn_count == 0 or not dst_ip_counts:
        return 0.0
    return max(dst_ip_counts.values()) / syn_count


def shannon_entropy(counts, total):
    if total < 2 or not counts:
        return 0.0
    return -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)


def aggregate_windows(flows):
    """Aggregate flows into WINDOW_SEC non-overlapping windows per src IP.
    Returns (X, list of src_ips) where X.shape = (n_windows, N_FEATURES).
    """
    groups = defaultdict(lambda: defaultdict(list))
    for f in flows:
        win = int(f['timestamp'] / WINDOW_SEC) * WINDOW_SEC
        groups[f['src_ip']][win].append(f)

    samples = []
    for src_ip, windows in groups.items():
        for win_start, flist in sorted(windows.items()):
            n = len(flist)
            if n < MIN_SYNS:
                continue

            timestamps = sorted(f['timestamp'] for f in flist)
            dst_ips_set = set(f['dst_ip'] for f in flist)
            dst_ports_set = set(f['dst_port'] for f in flist)
            dst_ip_counts = defaultdict(int)
            dst_port_counts = defaultdict(int)
            for f in flist:
                dst_ip_counts[f['dst_ip']] += 1
                dst_port_counts[f['dst_port']] += 1

            internal_dsts = sum(1 for f in flist if RFC1918(f['dst_ip']))
            total_bwd = sum(f['bwd_pkts'] for f in flist)
            total_fwd_bytes = sum(f['fwd_bytes'] for f in flist)

            # Compute 22 features matching C++ compute_features()
            f0 = float(n)
            f1 = float(len(dst_ips_set))
            f2 = float(len(dst_ports_set))
            f3 = iat_cv(timestamps)

            port_ent = shannon_entropy(dst_port_counts, n)
            f4 = port_ent

            f5 = f2 / f0 if f0 > 0 else 0.0
            f6 = f0 / WINDOW_SEC
            f7 = ip_concentration(dst_ip_counts, n)
            f8 = f1 / f0 if f0 > 0 else 0.0
            f9 = shannon_entropy(dst_ip_counts, n)
            f10 = iat_q90_q10(timestamps)

            # time_density: unique 1s buckets / n_timestamps
            buckets = set(int(ts) for ts in timestamps)
            f11 = len(buckets) / len(timestamps)

            f12 = f2 / f1 if f1 > 0 else 0.0
            f13 = 0.0   # handshake_ratio — not in CSV, default 0
            f14 = total_bwd / (f0 + total_bwd) if (f0 + total_bwd) > 0 else 0.0
            f15 = total_bwd / f0 if f0 > 0 else 0.0
            f16 = 0.0   # rst_rate — not in CSV, default 0
            f17 = internal_dsts / f0 if f0 > 0 else 0.0
            f18 = total_fwd_bytes / f0 if f0 > 0 else 0.0
            f19 = 0.0   # fin_ratio — not in CSV, default 0
            f20 = 0.0   # push_ratio — not in CSV, default 0
            f21 = 0.0   # mean_window — not in CSV, default 0

            samples.append([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9,
                            f10, f11, f12, f13, f14, f15, f16, f17, f18, f19, f20, f21])
    return np.array(samples, dtype=np.float64) if samples else np.zeros((0, N_FEATURES))


def main():
    print('=== bot_client Isolation Forest Training ===')

    # Load scaler (same as XGBoost model uses)
    with open(SCALER_JSON) as f:
        sc = json.load(f)
    median = np.array(sc['median'])
    iqr    = np.array(sc['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)

    all_flows = []
    for fname, cap in BENIGN_SOURCES:
        path = CICIDS_DIR / fname
        all_flows.extend(load_benign_flows(path, cap))

    print(f'Total benign flows loaded: {len(all_flows)}')
    X_raw = aggregate_windows(all_flows)
    print(f'Total benign windows: {len(X_raw)}, features: {X_raw.shape[1]}')

    if len(X_raw) < 100:
        print('ERROR: Too few windows. Check CICIDS data paths.')
        return

    # Scale (raw, no log1p)
    X_scaled = (X_raw - median) / iqr_safe

    # 80/20 split for threshold validation
    idx = np.random.RandomState(42).permutation(len(X_scaled))
    n_val = max(int(len(X_scaled) * 0.2), 1)
    X_val_b   = X_scaled[idx[:n_val]]
    X_train_b = X_scaled[idx[n_val:]]
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

    train_scores = clf.score_samples(X_train_b)
    threshold_p5  = float(np.percentile(train_scores, 5))
    threshold_p4  = float(np.percentile(train_scores, 4))
    threshold_p1  = float(np.percentile(train_scores, 1))
    threshold_p10 = float(np.percentile(train_scores, 10))
    print(f'Threshold p1={threshold_p1:.4f}, p5={threshold_p5:.4f}, p10={threshold_p10:.4f}')

    val_scores = clf.score_samples(X_val_b)
    fpr_p5 = float((val_scores < threshold_p5).mean())
    fpr_p4 = float((val_scores < threshold_p4).mean())
    print(f'Val benign FPR @ p5: {fpr_p5:.4f}, @ p4: {fpr_p4:.4f} (target ≤ 0.05)')

    # Use p4 if p5 exceeds target
    active_threshold = threshold_p4 if fpr_p5 > 0.05 else threshold_p5
    active_fpr = fpr_p4 if fpr_p5 > 0.05 else fpr_p5
    print(f'Active threshold: {active_threshold:.4f}, FPR: {active_fpr:.4f}')

    # Attack recall: load Friday bot flows, build windows, score
    friday_path = CICIDS_DIR / 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
    bot_flows = load_bot_flows(friday_path, BOT_SRC_IPS)
    attack_recall = None
    if bot_flows:
        X_attack_raw = aggregate_windows(bot_flows)
        print(f'Attack windows (Friday bot IPs): {len(X_attack_raw)}')
        if len(X_attack_raw) > 0:
            X_attack = (X_attack_raw - median) / iqr_safe
            attack_scores = clf.score_samples(X_attack)
            attack_recall = float((attack_scores < active_threshold).mean())
            print(f'Attack anomaly recall @ threshold: {attack_recall:.4f}')
    else:
        print('Friday bot flows not found — attack recall skipped')

    with open(OUT_PKL, 'wb') as f:
        pickle.dump(clf, f)

    meta = {
        'threshold_p1':   threshold_p1,
        'threshold_p5':   active_threshold,
        'threshold_p10':  threshold_p10,
        'val_benign_fpr': active_fpr,
        'attack_recall':  attack_recall,
        'n_train':        int(len(X_train_b)),
        'schema':         'bot_client',
        'features':       FEATURE_NAMES,
        'log1p_indices':  [],
        'scaler':         'bot_client_model_scaler.json',
        'preprocessing':  'raw RobustScaler (no log1p) — matches C++ bot_client_inspector.cc',
        'note':           'Features f13,f16,f19,f20,f21 default to 0 (not in CSV); IF trained on observable features',
    }
    with open(OUT_META, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nSaved: {OUT_PKL}')
    print(f'Saved: {OUT_META}')
    print('\n=== PASS ✅' if active_fpr <= 0.05 else '\n=== WARNING: FPR > 0.05')


if __name__ == '__main__':
    main()
