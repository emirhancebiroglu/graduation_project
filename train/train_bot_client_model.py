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
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','iat_cv','port_entropy','port_ratio','rate']
NEG_SAMPLE_CAP = 200000

def safe_int(v, default=0):
    try:
        return int(float(v))
    except:
        return default

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

CTU_COLS = ['StartTime','Proto','SrcAddr','Sport','DstAddr','Dport','Label']
CTU_DTYPES = {'StartTime': str, 'Proto': str, 'SrcAddr': str, 'Sport': str,
              'DstAddr': str, 'Dport': str, 'Label': str}

def parse_ctu_botnet_only(path):
    """Parse pre-filtered botnet-only CTU-13 CSV.
    Returns (pos_flows, bot_src_ips).
    pos_flows: all flows from bot client src IPs.
    bot_src_ips: set of unique bot client src IPs found."""
    pos = []
    bot_src_ips = set()
    log(f'  Reading {os.path.basename(path)}...')
    df = pd.read_csv(path, usecols=CTU_COLS, dtype=CTU_DTYPES, low_memory=True)
    lc = 'Label'
    # Collect bot client src IPs (From-Botnet means src is bot client)
    for _, r in df.iterrows():
        if 'From-Botnet' in str(r[lc]):
            bot_src_ips.add(str(r['SrcAddr']))
    log(f'  Found {len(bot_src_ips)} bot src IPs')
    # Extract all flows from bot src IPs
    for _, r in df.iterrows():
        src = str(r['SrcAddr'])
        if src not in bot_src_ips:
            continue
        try:
            ts = pd.to_datetime(r['StartTime']).timestamp()
        except:
            ts = 0.0
        pos.append({
            'src_ip': src,
            'dst_ip': str(r['DstAddr']),
            'dst_port': safe_int(r['Dport']),
            'timestamp': ts,
        })
    log(f'  Extracted {len(pos)} flows from bot src IPs')
    return pos, bot_src_ips

def aggregate_src_windows(flows, window_sec, bot_src_ips=None):
    """Aggregate outgoing flows by src IP in time windows.
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
            dst_ips = len(set(f['dst_ip'] for f in flist))
            dst_ports = len(set(f['dst_port'] for f in flist))
            n = len(flist)
            iat_cv = 0.0
            if len(syn_ts) >= 3:
                diffs = [syn_ts[i] - syn_ts[i-1] for i in range(1, len(syn_ts))]
                diffs = [d for d in diffs if d > 1e-6]
                if len(diffs) >= 2:
                    m = np.mean(diffs)
                    s = np.std(diffs)
                    iat_cv = s / m if m > 1e-6 else 0.0
            port_ratio = dst_ports / n if n > 0 else 0.0
            rate = n / window_sec
            port_counts = defaultdict(int)
            for f in flist:
                port_counts[f['dst_port']] += 1
            entropy = 0.0
            if n > 1:
                for cnt in port_counts.values():
                    p = cnt / n
                    entropy -= p * np.log2(p) if p > 0 else 0.0
            samples.append({
                'syn_count': n, 'dst_ips': dst_ips, 'dst_ports': dst_ports,
                'iat_cv': iat_cv, 'port_entropy': entropy,
                'port_ratio': port_ratio, 'rate': rate,
                'label': 1 if is_bot else 0
            })
    return samples

def main():
    log('='*60)
    log('  Bot Client Training Pipeline v1')
    log('='*60)
    log('')

    # ─── 1. Load CTU-13 data ─────────────────────────────────
    pos_flows = []
    neg_flows = []
    bot_src_ips = set()
    ctu_dir = '/home/emirhan/bitirme/data/raw/ctu13_binetflow'
    botnet_only = os.path.join(ctu_dir, 'ctu13_botnet_only.csv')
    if os.path.exists(botnet_only):
        log('[1] Loading CTU-13 botnet-only for bot client extraction...')
        p, b = parse_ctu_botnet_only(botnet_only)
        pos_flows.extend(p)
        bot_src_ips.update(b)
        log(f'  CTU bot src IPs: {sorted(bot_src_ips)[:10]}...')

    # ─── 2. Add CICIDS bot client flows ──────────────────────
    friday = '/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
    cicids_bot_srcs = {'192.168.10.5','192.168.10.8','192.168.10.9',
                       '192.168.10.14','192.168.10.15','192.168.10.12','192.168.10.17'}
    if os.path.exists(friday):
        log('[2] Loading CICIDS Friday-Morning Bot flows...')
        bot_flows = parse_cicids_csv_src(friday, 'Bot')
        for f in bot_flows:
            if f['src_ip'] in cicids_bot_srcs:
                pos_flows.append(f)
        log(f'  CICIDS bot src flows added: {sum(1 for f in bot_flows if f["src_ip"] in cicids_bot_srcs)}')
        bot_src_ips.update(cicids_bot_srcs)

    log(f'\n  Total pos flows: {len(pos_flows)}, Total neg flows: {len(neg_flows)}')

    # ─── 3. Load CICIDS BENIGN flows as negative ─────────────
    log('\n[3] Loading CICIDS BENIGN samples...')
    cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'
    benign_sources = [
        ('Monday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 100000),
        ('Tuesday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 50000),
        ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 'BENIGN', 25000),
        ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 'BENIGN', 25000),
    ]
    for fname, label, cap in benign_sources:
        path = os.path.join(cicids_dir, fname)
        if os.path.exists(path):
            neg_flows.extend(parse_cicids_csv_src(path, label, sample=cap))
    random.shuffle(neg_flows)
    if len(neg_flows) > NEG_SAMPLE_CAP:
        neg_flows = neg_flows[:NEG_SAMPLE_CAP]
    log(f'  Total BENIGN flows: {len(neg_flows)}')

    # ─── 4. Aggregate by src IP in windows ───────────────────
    log(f'\n[4] Aggregating into {WINDOW_SEC}s windows by src IP...')
    pos_agg = aggregate_src_windows(pos_flows, WINDOW_SEC, bot_src_ips)
    # Only take positive-labeled windows from pos_flows
    pos_agg = [s for s in pos_agg if s['label'] == 1]
    log(f'  Positive windows: {len(pos_agg)}')

    neg_agg = aggregate_src_windows(neg_flows, WINDOW_SEC, set())
    log(f'  Negative windows: {len(neg_agg)}')

    all_samples = pos_agg + neg_agg
    random.shuffle(all_samples)

    X = np.array([[s['syn_count'], s['dst_ips'], s['dst_ports'],
                   s['iat_cv'], s['port_entropy'], s['port_ratio'], s['rate']]
                  for s in all_samples], dtype=np.float64)
    Y = np.array([s['label'] for s in all_samples], dtype=np.int32)
    log(f'\n  Total windows: {len(X)}, pos={Y.sum()}, neg={len(Y)-Y.sum()}')

    if Y.sum() < 10:
        log('ERROR: Too few positive samples.')
        sys.exit(1)

    # ─── 5. Train/validation split ───────────────────────────
    X_train, X_val, Y_train, Y_val = train_test_split(
        X, Y, test_size=0.20, random_state=42, stratify=Y)
    log(f'\n[5] Split: train={len(X_train)}, val={len(X_val)}')
    log(f'  Train: pos={Y_train.sum()}, neg={len(Y_train)-Y_train.sum()}')
    log(f'  Val:   pos={Y_val.sum()}, neg={len(Y_val)-Y_val.sum()}')

    # ─── 6. Preprocessing ────────────────────────────────────
    X_train_log = np.log1p(X_train)
    median = np.median(X_train_log, axis=0)
    q1 = np.percentile(X_train_log, 25, axis=0)
    q3 = np.percentile(X_train_log, 75, axis=0)
    iqr = q3 - q1
    iqr[iqr == 0] = 1.0
    X_train_s = (X_train_log - median) / iqr
    X_val_s = (np.log1p(X_val) - median) / iqr

    # ─── 7. Train XGBoost ────────────────────────────────────
    ratio = (len(Y_train) - Y_train.sum()) / Y_train.sum()
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

    # ─── 8. Evaluate ─────────────────────────────────────────
    log('\n[8] Validation set evaluation:')
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
        log(f'  thr={thr:.2f} recall={recall:.4f} prec={prec:.4f} f1={f1:.4f} fpr={fpr:.4f} tp={tp} fp={fp} fn={fn} tn={tn}')
    log(f'\n  Best threshold: {best_thr:.2f} (F1={best_f1:.4f})')

    log('\n  Full training set evaluation:')
    train_preds = model.predict(dtrain)
    tp = ((train_preds >= best_thr) & (Y_train == 1)).sum()
    fp = ((train_preds >= best_thr) & (Y_train == 0)).sum()
    fn = ((train_preds < best_thr) & (Y_train == 1)).sum()
    tn = ((train_preds < best_thr) & (Y_train == 0)).sum()
    log(f'  thr={best_thr:.2f} recall={tp/(tp+fn):.4f} prec={tp/(tp+fp):.4f} fpr={fp/(fp+tn):.4f} tp={tp} fp={fp} fn={fn} tn={tn}')

    # ─── 9. Save model ───────────────────────────────────────
    model_path = '/home/emirhan/bitirme/models/bot_client_model.json'
    model.save_model(model_path)
    log(f'\n[9] Model saved: {model_path}')

    # ─── 10. Save scaler ─────────────────────────────────────
    scaler = {
        'median': [float(f'{v:.6f}') for v in median],
        'iqr': [float(f'{v:.6f}') for v in iqr],
    }
    scaler_path = '/home/emirhan/bitirme/models/bot_client_model_scaler.json'
    with open(scaler_path, 'w') as f:
        json.dump(scaler, f, indent=2)
    log(f'[10] Scaler saved: {scaler_path}')

    # ─── 11. C++ scaler params ───────────────────────────────
    log('\n[11] C++ Scaler Params:')
    med_str = ', '.join(f'{v:.6f}' for v in median)
    iqr_str = ', '.join(f'{v:.6f}' for v in iqr)
    log(f'  {{ {med_str} }},')
    log(f'  {{ {iqr_str} }}')

    # ─── 12. Feature importance ──────────────────────────────
    imp = model.get_score(importance_type='weight')
    log('\n[12] Feature importance (weight):')
    for name, imp_val in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}',0) for i in range(7)]), key=lambda x: -x[1]):
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
