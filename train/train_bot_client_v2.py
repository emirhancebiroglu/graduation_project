#!/usr/bin/env python3
"""train_bot_client_v2.py — Retrain bot client model with ALL flows from bot IPs.

Fixes:
1. Uses ALL flows from bot IPs (not just Bot-labeled), labels window by presence of Bot flows
2. Sliding windows (stride=60s) for more training samples
3. Includes CTU-13 data as positives
4. Down-samples negatives to balance classes
5. Exports C++ scaler params for embedding
"""

import json, random, warnings, os
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from sklearn.model_selection import train_test_split
import xgboost as xgb

warnings.filterwarnings('ignore')

WINDOW_SEC = 300
STRIDE_SEC = 60
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','iat_cv','port_entropy','port_ratio','rate',
              'ip_concentration','dst_ip_ratio','ip_entropy',
              'iat_q90_q10_ratio','time_density','port_to_ip_ratio',
              'handshake','incoming_ratio','data_density','rst_rate']

CICIDS_DIR = '/home/emirhan/bitirme/data/raw/cicids2017'
CTU13_FILE = '/home/emirhan/bitirme/data/raw/ctu13_binetflow/ctu13_botnet_only.csv'
BOT_IPS_CICIDS = ['192.168.10.5','192.168.10.8','192.168.10.9',
                  '192.168.10.14','192.168.10.15','192.168.10.12','192.168.10.17']

def log(m):
    print(m, flush=True)

def safe_int(v, default=0):
    try: return int(float(v))
    except: return default

def parse_cicids_all_from_ip(path, src_ips, max_rows=500000):
    """Load ALL flows (any label) from specified src IPs."""
    label_col = ' Label'
    cols = [label_col, ' Source IP', ' Destination IP', ' Destination Port', ' Timestamp']
    dtypes = {c: str for c in cols}
    df = pd.read_csv(path, low_memory=False, encoding='cp1252', usecols=cols, dtype=dtypes, nrows=max_rows)
    df = df[df[' Source IP'].str.strip().isin(src_ips)]
    log(f'  {os.path.basename(path)}: {len(df)} flows from bot IPs')
    flows = []
    for _, r in df.iterrows():
        try: ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except: ts = 0.0
        is_bot = str(r[label_col]).strip() == 'Bot'
        flows.append({
            'src_ip': r[' Source IP'].strip(),
            'dst_ip': r[' Destination IP'].strip(),
            'dst_port': safe_int(r[' Destination Port']),
            'timestamp': ts,
            'is_bot_flow': is_bot,
        })
    return flows

def parse_cicids_benign(path, label='BENIGN', exclude_ips=None, max_rows=200000):
    """Load benign flows from non-bot IPs."""
    label_col = ' Label'
    cols = [label_col, ' Source IP', ' Destination IP', ' Destination Port', ' Timestamp']
    dtypes = {c: str for c in cols}
    df = pd.read_csv(path, low_memory=False, encoding='cp1252', usecols=cols, dtype=dtypes, nrows=max_rows)
    df = df[df[label_col].str.strip() == label]
    if exclude_ips:
        df = df[~df[' Source IP'].str.strip().isin(exclude_ips)]
    log(f'  {os.path.basename(path)}: {len(df)} BENIGN flows')
    flows = []
    for _, r in df.iterrows():
        try: ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except: ts = 0.0
        flows.append({
            'src_ip': r[' Source IP'].strip(),
            'dst_ip': r[' Destination IP'].strip(),
            'dst_port': safe_int(r[' Destination Port']),
            'timestamp': ts,
            'is_bot_flow': False,
        })
    return flows

def parse_ctu_botnet(path, max_rows=400000):
    """Parse CTU-13 botnet flows. ALL flows from bot src IPs are bot."""
    df = pd.read_csv(path, low_memory=True, nrows=max_rows)
    bot_ips = set()
    for _, r in df.iterrows():
        if 'From-Botnet' in str(r['Label']):
            bot_ips.add(r['SrcAddr'])
    flows = []
    for _, r in df.iterrows():
        src = str(r['SrcAddr'])
        if src not in bot_ips:
            continue
        try: ts = pd.to_datetime(r['StartTime']).timestamp()
        except: ts = 0.0
        flows.append({
            'src_ip': src,
            'dst_ip': str(r['DstAddr']),
            'dst_port': safe_int(r['Dport']),
            'timestamp': ts,
            'is_bot_flow': True,
        })
    log(f'  CTU-13: {len(flows)} flows from {len(bot_ips)} bot IPs')
    return flows

def aggregate_sliding(flows, window_sec, stride_sec, bot_flow_srcs):
    """Aggregate by src IP in sliding windows using two-pointer for O(n) per IP.
    Also computes incoming_ratio from cross-referencing dst_ip against src_ip."""
    # Build per-source-IP flow list and per-destination-IP flow index
    by_src = defaultdict(list)
    by_dst = defaultdict(list)
    for f in flows:
        by_src[f['src_ip']].append(f)
        by_dst[f['dst_ip']].append(f)

    samples = []
    for src_ip, flist in by_src.items():
        is_bot_src = src_ip in bot_flow_srcs
        flist.sort(key=lambda x: x['timestamp'])
        if len(flist) < 2:
            continue

        # Incoming flows: flows whose dst_ip == src_ip (connections TO this IP)
        inflist = sorted(by_dst.get(src_ip, []), key=lambda x: x['timestamp'])
        n_inflows = len(inflist)

        ts_min = flist[0]['timestamp']
        ts_max = flist[-1]['timestamp']
        first_win = int((ts_min - window_sec + stride_sec) / stride_sec) * stride_sec
        if first_win < 0: first_win = 0
        last_win = int(ts_max / stride_sec) * stride_sec

        # Two-pointer for outgoing flows
        left = 0; right = 0
        # Two-pointer for incoming flows
        in_left = 0; in_right = 0

        for ws in range(int(first_win), int(last_win) + 1, stride_sec):
            we = ws + window_sec
            while right < len(flist) and flist[right]['timestamp'] < we: right += 1
            while left < right and flist[left]['timestamp'] < ws: left += 1
            if right - left < 2: continue

            # Advance incoming flow window
            while in_right < n_inflows and inflist[in_right]['timestamp'] < we: in_right += 1
            while in_left < in_right and inflist[in_left]['timestamp'] < ws: in_left += 1

            win = flist[left:right]
            n_in = in_right - in_left
            has_bot = any(f.get('is_bot_flow', False) for f in win)
            label = 1 if (is_bot_src and has_bot) else 0

            timestamps = [f['timestamp'] for f in win]
            dst_ips = len(set(f['dst_ip'] for f in win))
            dst_ports = len(set(f['dst_port'] for f in win))
            n = len(win)

            iat_cv = 0.0
            diffs = []
            if n >= 3:
                diffs = [timestamps[i] - timestamps[i-1] for i in range(1, n)]
                diffs = [d for d in diffs if d > 1e-6]
                if len(diffs) >= 2:
                    m = np.mean(diffs)
                    s = np.std(diffs)
                    iat_cv = s / m if m > 1e-6 else 0.0

            port_ratio = dst_ports / n if n > 0 else 0.0
            rate = n / window_sec
            port_counts = Counter(f['dst_port'] for f in win)
            entropy = 0.0
            if n > 1:
                for cnt in port_counts.values():
                    p = cnt / n
                    entropy -= p * np.log2(p) if p > 0 else 0.0

            ip_counts = Counter(f['dst_ip'] for f in win)
            ip_concentration = max(ip_counts.values()) / n if n > 0 and ip_counts else 0.0
            dst_ip_ratio = dst_ips / n if n > 0 else 0.0
            ip_entropy_val = 0.0
            if n > 1 and ip_counts:
                for cnt in ip_counts.values():
                    p = cnt / n
                    ip_entropy_val -= p * np.log2(p) if p > 0 else 0.0

            iat_q90_q10 = 0.0
            if len(diffs) >= 4:
                sdiffs = sorted(diffs)
                p10 = sdiffs[len(sdiffs) // 10]
                p90 = sdiffs[(9 * len(sdiffs)) // 10]
                iat_q90_q10 = p90 / p10 if p10 > 1e-6 else 0.0

            time_den = 0.0
            if n >= 2:
                buckets = set(int(ts) for ts in timestamps)
                time_den = len(buckets) / n

            port_ip_ratio = dst_ports / dst_ips if dst_ips > 0 else 0.0

            # TCP flag features (approximated from CSV)
            handshake = 0.95  # assume most connections complete handshake
            total_conn = n + n_in
            incoming_ratio = n_in / total_conn if total_conn > 0 else 0.0
            data_density = 1.0  # 1 data packet per direction per flow
            rst_rate = 0.01     # low RST rate in normal traffic

            samples.append({
                'syn_count': n, 'dst_ips': dst_ips, 'dst_ports': dst_ports,
                'iat_cv': iat_cv, 'port_entropy': entropy,
                'port_ratio': port_ratio, 'rate': rate,
                'ip_concentration': ip_concentration,
                'dst_ip_ratio': dst_ip_ratio,
                'ip_entropy': ip_entropy_val,
                'iat_q90_q10_ratio': iat_q90_q10,
                'time_density': time_den,
                'port_to_ip_ratio': port_ip_ratio,
                'handshake': handshake,
                'incoming_ratio': incoming_ratio,
                'data_density': data_density,
                'rst_rate': rst_rate,
                'label': label,
            })

    return samples

def main():
    log('='*60)
    log('  Bot Client Training v2 — Full-flow positives + sliding windows + CTU-13')
    log('='*60)

    all_pos_flows = []
    bot_src_ips = set()

    # ─── 1. CICIDS Friday — ALL flows from bot IPs ───────────
    log('\n[1] CICIDS Friday Bot IPs (ALL flows)...')
    fri_path = os.path.join(CICIDS_DIR, 'Friday-WorkingHours-Morning.pcap_ISCX.csv')
    cicid_pos = parse_cicids_all_from_ip(fri_path, BOT_IPS_CICIDS)
    all_pos_flows.extend(cicid_pos)
    bot_src_ips.update(BOT_IPS_CICIDS)
    log(f'  {len(cicid_pos)} total flows from {len(BOT_IPS_CICIDS)} bot IPs')

    # ─── 2. CTU-13 botnet flows ─────────────────────────────
    log('\n[2] CTU-13 botnet flows...')
    if os.path.exists(CTU13_FILE):
        ctu_pos = parse_ctu_botnet(CTU13_FILE)
        all_pos_flows.extend(ctu_pos)
        ctu_bot_ips = set(f['src_ip'] for f in ctu_pos)
        bot_src_ips.update(ctu_bot_ips)
        log(f'  CTU-13: {len(ctu_pos)} flows from {len(ctu_bot_ips)} bot IPs')

    log(f'\n  Total positive flows: {len(all_pos_flows)} from {len(bot_src_ips)} bot IPs')

    # ─── 3. CICIDS BENIGN flows (negatives) ─────────────────
    log('\n[3] CICIDS BENIGN flows...')
    all_neg_flows = []
    benign_sources = [
        ('Monday-WorkingHours.pcap_ISCX.csv', 200000),
        ('Tuesday-WorkingHours.pcap_ISCX.csv', 150000),
        ('Wednesday-workingHours.pcap_ISCX.csv', 100000),
        ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 80000),
        ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 80000),
        ('Friday-WorkingHours-Morning.pcap_ISCX.csv', 100000),
    ]
    for fname, cap in benign_sources:
        path = os.path.join(CICIDS_DIR, fname)
        if os.path.exists(path):
            neg = parse_cicids_benign(path, exclude_ips=bot_src_ips, max_rows=cap)
            all_neg_flows.extend(neg)

    # ─── 4. Aggregate into sliding windows ──────────────────
    log('\n[4] Aggregating into sliding windows...')
    all_flows = all_pos_flows + all_neg_flows
    random.shuffle(all_flows)

    samples = aggregate_sliding(all_flows, WINDOW_SEC, STRIDE_SEC, bot_src_ips)
    log(f'  Total windows: {len(samples)}')

    pos = [s for s in samples if s['label'] == 1]
    neg = [s for s in samples if s['label'] == 0]
    log(f'  Positive windows: {len(pos)}')
    log(f'  Negative windows: {len(neg)}')

    if len(pos) < 20:
        log('ERROR: Too few positive windows. Need more training data.')
        # Show distribution
        log('Stats from positive flows:')
        log(f'  Bot src IPs used: {len(bot_src_ips)}')
        log(f'  Total flows: {len(all_pos_flows)}')
        return

    # Balance: down-sample negatives
    max_neg = min(len(neg), len(pos) * 5)
    neg = random.sample(neg, max_neg)
    log(f'  After balancing: pos={len(pos)}, neg={len(neg)}')

    all_samples = pos + neg
    random.shuffle(all_samples)

    X = np.array([[s['syn_count'], s['dst_ips'], s['dst_ports'],
                   s['iat_cv'], s['port_entropy'], s['port_ratio'], s['rate'],
                   s['ip_concentration'], s['dst_ip_ratio'], s['ip_entropy'],
                   s['iat_q90_q10_ratio'], s['time_density'], s['port_to_ip_ratio'],
                   s['handshake'], s['incoming_ratio'], s['data_density'], s['rst_rate']]
                  for s in all_samples], dtype=np.float64)
    Y = np.array([s['label'] for s in all_samples], dtype=np.int32)
    log(f'\n  Training data: {len(X)} windows, pos={Y.sum()}, neg={len(Y)-Y.sum()}')

    # ─── 5. Train/validation split ──────────────────────────
    X_train, X_val, Y_train, Y_val = train_test_split(
        X, Y, test_size=0.20, random_state=42, stratify=Y)
    log(f'\n[5] Split: train={len(X_train)}, val={len(X_val)}')

    # ─── 6. Preprocessing ───────────────────────────────────
    X_train_log = np.log1p(X_train)
    median = np.median(X_train_log, axis=0)
    q1 = np.percentile(X_train_log, 25, axis=0)
    q3 = np.percentile(X_train_log, 75, axis=0)
    iqr = q3 - q1
    iqr[iqr == 0] = 1.0
    X_train_s = (X_train_log - median) / iqr
    X_val_s = (np.log1p(X_val) - median) / iqr

    # ─── 7. Train XGBoost ───────────────────────────────────
    ratio = (len(Y_train) - Y_train.sum()) / max(Y_train.sum(), 1)
    params = {
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'max_depth': 4,
        'eta': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 3,
        'scale_pos_weight': ratio,
        'seed': 42,
    }
    dtrain = xgb.DMatrix(X_train_s, label=Y_train)
    dval = xgb.DMatrix(X_val_s, label=Y_val)
    log(f'\n[7] Training XGBoost (scale_pos_weight={ratio:.2f})...')
    model = xgb.train(params, dtrain, num_boost_round=150,
                      evals=[(dtrain,'train'),(dval,'val')],
                      verbose_eval=20)

    # ─── 8. Evaluate ────────────────────────────────────────
    log('\n[8] Validation set evaluation:')
    preds = model.predict(dval)
    best_f1 = 0.0
    best_thr = 0.0
    for thr in np.arange(0.05, 0.96, 0.05):
        tp = ((preds >= thr) & (Y_val == 1)).sum()
        fp = ((preds >= thr) & (Y_val == 0)).sum()
        fn = ((preds < thr) & (Y_val == 1)).sum()
        tn = ((preds < thr) & (Y_val == 0)).sum()
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        if f1 > best_f1:
            best_f1 = f1
            best_thr = thr
        if thr in [0.50, 0.70, 0.90, 0.95]:
            log(f'  thr={thr:.2f} recall={recall:.4f} prec={prec:.4f} f1={f1:.4f} fpr={fpr:.4f} tp={tp} fp={fp} fn={fn} tn={tn}')
    log(f'\n  Best threshold: {best_thr:.2f} (F1={best_f1:.4f})')

    # Full train set eval
    log('\n  Training set evaluation:')
    train_preds = model.predict(dtrain)
    tp = ((train_preds >= best_thr) & (Y_train == 1)).sum()
    fp = ((train_preds >= best_thr) & (Y_train == 0)).sum()
    fn = ((train_preds < best_thr) & (Y_train == 1)).sum()
    tn = ((train_preds < best_thr) & (Y_train == 0)).sum()
    log(f'  thr={best_thr:.2f} recall={tp/(tp+fn):.4f} prec={tp/(tp+fp):.4f} fpr={fp/(fp+tn):.4f}')

    # ─── 9. Save model ──────────────────────────────────────
    model_path = '/home/emirhan/bitirme/models/bot_client_model.json'
    model.save_model(model_path)
    log(f'\n[9] Model saved: {model_path}')

    # ─── 10. Save scaler ────────────────────────────────────
    scaler = {
        'median': [float(f'{v:.6f}') for v in median],
        'iqr': [float(f'{v:.6f}') for v in iqr],
    }
    scaler_path = '/home/emirhan/bitirme/models/bot_client_model_scaler.json'
    with open(scaler_path, 'w') as f:
        json.dump(scaler, f, indent=2)
    log(f'[10] Scaler saved: {scaler_path}')

    # ─── 11. C++ scaler params ──────────────────────────────
    log('\n[11] C++ Scaler Params (copy to bot_client_inspector.cc):')
    med_str = ', '.join(f'{v:.6f}' for v in median)
    iqr_str = ', '.join(f'{v:.6f}' for v in iqr)
    log(f'  BclScalerParams g_scaler = {{')
    log(f'    {{ {med_str} }},')
    log(f'    {{ {iqr_str} }}')
    log(f'  }};')

    # ─── 12. Feature importance ─────────────────────────────
    imp = model.get_score(importance_type='weight')
    log('\n[12] Feature importance (weight):')
    for name, imp_val in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}',0) for i in range(len(FEAT_NAMES))]), key=lambda x: -x[1]):
        log(f'  {name}: {imp_val}')

    log('\n' + '='*60)
    log('  Done.')
    log('='*60)

if __name__ == '__main__':
    main()
