import os, sys, json, warnings, random
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.model_selection import train_test_split
import xgboost as xgb

warnings.filterwarnings('ignore')

def log(m):
    print(m, flush=True)

WINDOW_SEC = 300
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','iat_cv','port_entropy','port_ratio','rate',
              'ip_conc','ip_ratio','ip_entropy','iat_q90','time_density','port_ip_ratio',
              'handshake','inc_ratio','data_density','rst_rate','internal_ip_ratio']
NEG_SAMPLE_CAP = 400000

def safe_int(v, default=0):
    try:
        return int(float(v))
    except:
        return default

def is_internal_ip(ip_str):
    """Check if IP is RFC1918 private or loopback."""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        return False
    except:
        return False

def parse_cicids_csv_src(path, label_val, sample=None):
    """Parse CICIDS CSV and return flows."""
    try:
        df = pd.read_csv(path, low_memory=False, encoding='utf-8')
    except UnicodeDecodeError:
        df = pd.read_csv(path, low_memory=False, encoding='cp1252')
    lc = [c for c in df.columns if 'label' in c.lower()][0]
    df = df[df[lc].astype(str).str.strip() == label_val]
    s = f'  {os.path.basename(path)}: {len(df)} {label_val} flows'
    if sample and len(df) > sample:
        df = df.sample(sample, random_state=42)
        s += f' (sampled to {sample})'
    log(s)
    rows = df.to_dict('records')
    flows = []
    for r in rows:
        try:
            ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except:
            ts = 0.0
        flows.append({
            'src_ip': str(r[' Source IP']),
            'dst_ip': str(r[' Destination IP']),
            'dst_port': safe_int(r[' Destination Port']),
            'timestamp': ts,
        })
    return flows

def parse_ctu13_botnet(path):
    """Parse CTU-13 botnet-only binetflow CSV.
    Returns list of flows from bot clients (From-Botnet label)."""
    flows = []
    log(f'  Reading {os.path.basename(path)}...')
    df = pd.read_csv(path, low_memory=False, encoding='utf-8')
    # Filter for From-Botnet flows (bot client initiating connections)
    bot_df = df[df['Label'].str.contains('From-Botnet', na=False)]
    log(f'  Found {len(bot_df)} From-Botnet flows')
    
    for _, r in bot_df.iterrows():
        try:
            ts = pd.to_datetime(r['StartTime']).timestamp()
        except:
            ts = 0.0
        flows.append({
            'src_ip': str(r['SrcAddr']),
            'dst_ip': str(r['DstAddr']),
            'dst_port': safe_int(r['Dport']),
            'timestamp': ts,
        })
    log(f'  Extracted {len(flows)} bot client flows')
    return flows

def aggregate_src_windows_18feat(flows, window_sec, bot_src_ips=None):
    """Aggregate outgoing flows by src IP in non-overlapping time windows.
    Computes all 18 features including internal_ip_ratio.
    Label = 1 if src IP is a known bot client."""
    groups = defaultdict(lambda: defaultdict(list))
    for f in flows:
        src = f['src_ip']
        win = int(f['timestamp'] / window_sec) * window_sec
        groups[src][win].append(f)
    
    samples = []
    for src_ip, windows in groups.items():
        is_bot = bot_src_ips and src_ip in bot_src_ips
        for win_start, flist in windows.items():
            syn_ts = sorted([f['timestamp'] for f in flist])
            dst_ips_list = [f['dst_ip'] for f in flist]
            dst_ips = len(set(dst_ips_list))
            dst_ports = len(set(f['dst_port'] for f in flist))
            n = len(flist)
            
            # IAT CV
            iat_cv = 0.0
            if len(syn_ts) >= 3:
                diffs = [syn_ts[i] - syn_ts[i-1] for i in range(1, len(syn_ts))]
                diffs = [d for d in diffs if d > 1e-6]
                if len(diffs) >= 2:
                    m = np.mean(diffs)
                    s = np.std(diffs)
                    iat_cv = s / m if m > 1e-6 else 0.0
            
            # Port entropy
            port_counts = defaultdict(int)
            for f in flist:
                port_counts[f['dst_port']] += 1
            entropy = 0.0
            if n > 1:
                for cnt in port_counts.values():
                    p = cnt / n
                    entropy -= p * np.log2(p) if p > 0 else 0.0
            
            # IP concentration (max SYNs to any single dst IP / total SYNs)
            ip_counts = defaultdict(int)
            for f in flist:
                ip_counts[f['dst_ip']] += 1
            max_ip_n = max(ip_counts.values()) if ip_counts else 0
            ip_conc = max_ip_n / n if n > 0 else 0.0
            
            # IP ratio (unique dst IPs / total SYNs)
            ip_ratio = dst_ips / n if n > 0 else 0.0
            
            # IP entropy
            ip_entropy = 0.0
            if n > 1:
                for cnt in ip_counts.values():
                    p = cnt / n
                    ip_entropy -= p * np.log2(p) if p > 0 else 0.0
            
            # IAT q90/q10 ratio
            iat_q90_q10 = 0.0
            if len(syn_ts) >= 5:
                diffs = [syn_ts[i] - syn_ts[i-1] for i in range(1, len(syn_ts))]
                diffs = [d for d in diffs if d > 1e-6]
                if len(diffs) >= 4:
                    diffs_sorted = sorted(diffs)
                    p10_idx = len(diffs_sorted) // 10
                    p90_idx = (9 * len(diffs_sorted)) // 10
                    p10 = diffs_sorted[p10_idx] if p10_idx < len(diffs_sorted) else 0
                    p90 = diffs_sorted[p90_idx] if p90_idx < len(diffs_sorted) else 0
                    iat_q90_q10 = p90 / p10 if p10 > 1e-6 else 0.0
            
            # Time density (unique 1-second buckets / syn_count)
            time_buckets = set(int(ts) for ts in syn_ts)
            time_density = len(time_buckets) / n if n > 0 else 0.0
            
            # Port to IP ratio
            port_ip_ratio = dst_ports / dst_ips if dst_ips > 0 else 0.0
            
            # Port ratio
            port_ratio = dst_ports / n if n > 0 else 0.0
            
            # Rate
            rate = n / window_sec
            
            # Placeholder for handshake, inc_ratio, data_density, rst_rate (need TCP flags)
            # Set to 0 for CTU-13 (no TCP flag info in binetflow)
            handshake = 0.0
            inc_ratio = 0.0
            data_density = 0.0
            rst_rate = 0.0
            
            # Internal IP ratio (RFC1918 destinations)
            internal_count = sum(1 for dip in dst_ips_list if is_internal_ip(dip))
            internal_ip_ratio = internal_count / n if n > 0 else 0.0
            
            samples.append({
                'syn_count': n,
                'dst_ips': dst_ips,
                'dst_ports': dst_ports,
                'iat_cv': iat_cv,
                'port_entropy': entropy,
                'port_ratio': port_ratio,
                'rate': rate,
                'ip_conc': ip_conc,
                'ip_ratio': ip_ratio,
                'ip_entropy': ip_entropy,
                'iat_q90': iat_q90_q10,
                'time_density': time_density,
                'port_ip_ratio': port_ip_ratio,
                'handshake': handshake,
                'inc_ratio': inc_ratio,
                'data_density': data_density,
                'rst_rate': rst_rate,
                'internal_ip_ratio': internal_ip_ratio,
                'label': 1 if is_bot else 0,
                'win_start': win_start,
            })
    return samples

def main():
    log('='*60)
    log('  Bot Client Training Pipeline v3 (18 features + CTU-13 + CICIDS Bot)')
    log('='*60)
    log('')

    # ─── 1. Load CTU-13 botnet flows (external C2, low internal_ip_ratio) ──────────
    pos_flows = []
    bot_src_ips = set()
    ctu13_path = '/home/emirhan/bitirme/data/raw/ctu13_binetflow/ctu13_botnet_only.csv'
    log('[1] Loading CTU-13 Botnet flows (external C2 bots)...')
    if os.path.exists(ctu13_path):
        ctu_flows = parse_ctu13_botnet(ctu13_path)
        # Downsample CTU-13 to balance with CICIDS (avoid dominance)
        random.seed(42)
        random.shuffle(ctu_flows)
        ctu_flows = ctu_flows[:50000]  # Limit to 50k flows
        pos_flows = ctu_flows
        bot_src_ips.update(f['src_ip'] for f in pos_flows)
        log(f'  Downsampled to {len(ctu_flows)} flows for balance')
        log(f'  Found {len(bot_src_ips)} unique bot client IPs')

    # ─── 2. Load CICIDS Friday Bot flows (internal attack bots, high internal_ip_ratio) ──────────
    cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'
    friday_path = os.path.join(cicids_dir, 'Friday-WorkingHours-Morning.pcap_ISCX.csv')
    log('\n[2] Loading CICIDS Friday Bot flows (internal attack bots)...')
    cicids_bot_srcs = {'192.168.10.5','192.168.10.8','192.168.10.9',
                       '192.168.10.14','192.168.10.15','192.168.10.12','192.168.10.17'}
    if os.path.exists(friday_path):
        cicids_bot_flows = parse_cicids_csv_src(friday_path, 'Bot')
        # Filter for known bot src IPs
        cicids_bot_flows = [f for f in cicids_bot_flows if f['src_ip'] in cicids_bot_srcs]
        # Duplicate 192.168.10.5 flows 3x for better representation
        extra_5 = [f for f in cicids_bot_flows if f['src_ip'] == '192.168.10.5']
        cicids_bot_flows.extend(extra_5 * 2)
        pos_flows.extend(cicids_bot_flows)
        bot_src_ips.update(cicids_bot_srcs)
        log(f'  Added {len(cicids_bot_flows)} CICIDS bot flows')
        log(f'  Total bot src IPs: {len(bot_src_ips)}')

    log(f'\n  Total pos flows: {len(pos_flows)}')

    # ─── 2. Load CICIDS BENIGN flows as negative ─────────────
    log('[2] Loading CICIDS BENIGN flows (negatives)...')
    neg_flows = []
    cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'
    benign_sources = [
        ('Monday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 150000),
        ('Tuesday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 100000),
        ('Wednesday-workingHours.pcap_ISCX.csv', 'BENIGN', 50000),
        ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 'BENIGN', 50000),
        ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 'BENIGN', 50000),
    ]
    for fname, label, cap in benign_sources:
        path = os.path.join(cicids_dir, fname)
        if os.path.exists(path):
            neg_flows.extend(parse_cicids_csv_src(path, label, sample=cap))
    random.shuffle(neg_flows)
    if len(neg_flows) > NEG_SAMPLE_CAP:
        neg_flows = neg_flows[:NEG_SAMPLE_CAP]
    log(f'  Total BENIGN flows: {len(neg_flows)}')

    # ─── 3. Aggregate by src IP in windows ───────────────────
    log(f'\n[3] Aggregating into {WINDOW_SEC}s windows by src IP (18 features)...')
    pos_agg = aggregate_src_windows_18feat(pos_flows, WINDOW_SEC, bot_src_ips)
    pos_agg = [s for s in pos_agg if s['label'] == 1]
    log(f'  Positive windows: {len(pos_agg)}')
    log(f'  Positive internal_ip_ratio stats: min={min(s["internal_ip_ratio"] for s in pos_agg):.3f}, '
        f'max={max(s["internal_ip_ratio"] for s in pos_agg):.3f}, '
        f'mean={np.mean([s["internal_ip_ratio"] for s in pos_agg]):.3f}')

    neg_agg = aggregate_src_windows_18feat(neg_flows, WINDOW_SEC, set())
    log(f'  Negative windows: {len(neg_agg)}')
    log(f'  Negative internal_ip_ratio stats: min={min(s["internal_ip_ratio"] for s in neg_agg):.3f}, '
        f'max={max(s["internal_ip_ratio"] for s in neg_agg):.3f}, '
        f'mean={np.mean([s["internal_ip_ratio"] for s in neg_agg]):.3f}')

    all_samples = pos_agg + neg_agg
    random.shuffle(all_samples)

    X = np.array([[
        s['syn_count'], s['dst_ips'], s['dst_ports'], s['iat_cv'],
        s['port_entropy'], s['port_ratio'], s['rate'],
        s['ip_conc'], s['ip_ratio'], s['ip_entropy'],
        s['iat_q90'], s['time_density'], s['port_ip_ratio'],
        s['handshake'], s['inc_ratio'], s['data_density'], s['rst_rate'],
        s['internal_ip_ratio']
    ] for s in all_samples], dtype=np.float64)
    Y = np.array([s['label'] for s in all_samples], dtype=np.int32)
    log(f'\n  Total windows: {len(X)}, pos={Y.sum()}, neg={len(Y)-Y.sum()}')

    if Y.sum() < 10:
        log('ERROR: Too few positive samples.')
        sys.exit(1)

    # ─── 4. Train/validation split ───────────────────────────
    X_train, X_val, Y_train, Y_val = train_test_split(
        X, Y, test_size=0.20, random_state=42, stratify=Y)
    log(f'\n[4] Split: train={len(X_train)}, val={len(X_val)}')
    log(f'  Train: pos={Y_train.sum()}, neg={len(Y_train)-Y_train.sum()}')
    log(f'  Val:   pos={Y_val.sum()}, neg={len(Y_val)-Y_val.sum()}')

    # ─── 5. Preprocessing (log1p + robust scaler) ────────────
    X_train_log = np.log1p(X_train)
    median = np.median(X_train_log, axis=0)
    q1 = np.percentile(X_train_log, 25, axis=0)
    q3 = np.percentile(X_train_log, 75, axis=0)
    iqr = q3 - q1
    iqr[iqr == 0] = 1.0
    X_train_s = (X_train_log - median) / iqr
    X_val_s = (np.log1p(X_val) - median) / iqr

    # ─── 6. Train XGBoost ────────────────────────────────────
    ratio = (len(Y_train) - Y_train.sum()) / Y_train.sum()
    params = {
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'max_depth': 6,
        'eta': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 3,
        'scale_pos_weight': ratio,
        'seed': 42,
    }
    dtrain = xgb.DMatrix(X_train_s, label=Y_train)
    dval = xgb.DMatrix(X_val_s, label=Y_val)
    log(f'\n[6] Training XGBoost (scale_pos_weight={ratio:.2f})...')
    model = xgb.train(params, dtrain, num_boost_round=150,
                      evals=[(dtrain,'train'),(dval,'val')],
                      verbose_eval=20)

    # ─── 7. Evaluate ─────────────────────────────────────────
    log('\n[7] Validation set evaluation:')
    preds = model.predict(dval)
    best_f1 = 0.0
    best_thr = 0.50
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
        log(f'  thr={thr:.2f} recall={recall:.4f} prec={prec:.4f} f1={f1:.4f} fpr={fpr:.4f}')
    log(f'\n  Best threshold: {best_thr:.2f} (F1={best_f1:.4f})')

    log('\n  Full training set evaluation:')
    train_preds = model.predict(dtrain)
    tp = ((train_preds >= best_thr) & (Y_train == 1)).sum()
    fp = ((train_preds >= best_thr) & (Y_train == 0)).sum()
    fn = ((train_preds < best_thr) & (Y_train == 1)).sum()
    tn = ((train_preds < best_thr) & (Y_train == 0)).sum()
    log(f'  thr={best_thr:.2f} recall={tp/(tp+fn):.4f} prec={tp/(tp+fp):.4f} fpr={fp/(fp+tn):.4f}')

    # ─── 8. Save model ───────────────────────────────────────
    model_path = '/home/emirhan/bitirme/models/bot_client_v3.json'
    model.save_model(model_path)
    log(f'\n[8] Model saved: {model_path}')

    # ─── 9. Save scaler ─────────────────────────────────────
    scaler = {
        'median': [float(f'{v:.6f}') for v in median],
        'iqr': [float(f'{v:.6f}') for v in iqr],
    }
    scaler_path = '/home/emirhan/bitirme/models/bot_client_v3_scaler.json'
    with open(scaler_path, 'w') as f:
        json.dump(scaler, f, indent=2)
    log(f'[9] Scaler saved: {scaler_path}')

    # ─── 10. C++ scaler params ───────────────────────────────
    log('\n[10] C++ Scaler Params (copy to bot_client_inspector.cc):')
    med_str = ', '.join(f'{v:.6f}' for v in median)
    iqr_str = ', '.join(f'{v:.6f}' for v in iqr)
    log(f'  {{ {med_str} }},')
    log(f'  {{ {iqr_str} }}')

    # ─── 11. Feature importance ──────────────────────────────
    imp = model.get_score(importance_type='weight')
    log('\n[11] Feature importance (weight):')
    for name, imp_val in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}',0) for i in range(18)]), key=lambda x: -x[1]):
        log(f'  {name}: {imp_val}')

    log('\n' + '='*60)
    log('  Done.')
    log('='*60)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.exit(1)
