import os, sys, json, warnings, random
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.model_selection import train_test_split
import xgboost as xgb

warnings.filterwarnings('ignore')

def log(m):
    print(m, flush=True)

WINDOW_SEC = 60
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','port_ratio','single_port_score','rate','iat_cv']
NEG_SAMPLE_CAP = 200000
POSITIVE_LABELS = ['SSH-Patator', 'FTP-Patator']

def safe_int(v, default=0):
    try:
        return int(float(v))
    except:
        return default

def parse_cicids_bruteforce(path, label_val, sample=None, pos_only=False):
    try:
        df = pd.read_csv(path, low_memory=False, encoding='utf-8')
    except UnicodeDecodeError:
        df = pd.read_csv(path, low_memory=False, encoding='cp1252')
    lc = [c for c in df.columns if 'label' in c.lower()][0]

    if pos_only:
        target = POSITIVE_LABELS
    else:
        target = [label_val]

    mask = df[lc].astype(str).str.strip().isin(target)
    df = df[mask]
    s = f'  {os.path.basename(path)}: {len(df)} flows'
    if sample and len(df) > sample:
        df = df.sample(sample, random_state=42)
        s += f' (sampled to {sample})'
    log(s)

    flows = []
    rows = df.to_dict('records')
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
            'label': 1 if str(r[lc]).strip() in POSITIVE_LABELS else 0,
        })
    return flows

def aggregate_src_windows(flows, window_sec):
    groups = defaultdict(lambda: defaultdict(list))
    for f in flows:
        src = f['src_ip']
        win = int(f['timestamp'] / window_sec) * window_sec
        groups[src][win].append(f)
    samples = []
    for src_ip, windows in groups.items():
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
            max_port_count = max(port_counts.values()) if port_counts else 0
            single_port_score = max_port_count / n if n > 0 else 0.0
            label = 1 if any(f['label'] == 1 for f in flist) else 0
            samples.append({
                'syn_count': n, 'dst_ips': dst_ips, 'dst_ports': dst_ports,
                'port_ratio': port_ratio, 'single_port_score': single_port_score,
                'rate': rate, 'iat_cv': iat_cv, 'label': label
            })
    return samples

def main():
    log('='*60)
    log('  Brute Force SSH/FTP Training Pipeline v1')
    log('='*60)
    log('')

    # ─── 1. Positive samples ───────────────────────────────────
    tuesday = '/home/emirhan/bitirme/data/raw/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv'
    log('[1] Loading Tuesday brute force flows (SSH-Patator + FTP-Patator)...')
    pos_flows = parse_cicids_bruteforce(tuesday, None, pos_only=True)
    log(f'  Positive flows: {len(pos_flows)}')

    # ─── 2. Negative samples ───────────────────────────────────
    neg_flows = []
    log('\n[2] Loading BENIGN samples...')
    cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'
    benign_sources = [
        ('Tuesday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 150000),
        ('Monday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 50000),
    ]
    for fname, label, cap in benign_sources:
        path = os.path.join(cicids_dir, fname)
        if os.path.exists(path):
            neg_flows.extend(parse_cicids_bruteforce(path, label, sample=cap))
    random.shuffle(neg_flows)
    if len(neg_flows) > NEG_SAMPLE_CAP:
        neg_flows = neg_flows[:NEG_SAMPLE_CAP]
    log(f'  Total BENIGN flows: {len(neg_flows)}')

    all_flows = pos_flows + neg_flows
    log(f'\n  Total flows: {len(all_flows)}')

    # ─── 3. Aggregate by src IP in windows ─────────────────────
    log(f'\n[3] Aggregating into {WINDOW_SEC}s windows by src IP...')
    samples = aggregate_src_windows(all_flows, WINDOW_SEC)
    random.shuffle(samples)
    log(f'  Total windows: {len(samples)}')

    X = np.array([[s['syn_count'], s['dst_ips'], s['dst_ports'],
                   s['port_ratio'], s['single_port_score'], s['rate'], s['iat_cv']]
                  for s in samples], dtype=np.float64)
    Y = np.array([s['label'] for s in samples], dtype=np.int32)
    log(f'  pos={Y.sum()}, neg={len(Y)-Y.sum()}')

    if Y.sum() < 5:
        log('ERROR: Too few positive samples.')
        sys.exit(1)

    # ─── 4. Train/validation split ─────────────────────────────
    X_train, X_val, Y_train, Y_val = train_test_split(
        X, Y, test_size=0.20, random_state=42, stratify=Y)
    log(f'\n[4] Split: train={len(X_train)}, val={len(X_val)}')
    log(f'  Train: pos={Y_train.sum()}, neg={len(Y_train)-Y_train.sum()}')
    log(f'  Val:   pos={Y_val.sum()}, neg={len(Y_val)-Y_val.sum()}')

    # ─── 5. Preprocessing ────────────────────────────────────
    X_train_log = np.log1p(X_train)
    median = np.median(X_train_log, axis=0)
    q1 = np.percentile(X_train_log, 25, axis=0)
    q3 = np.percentile(X_train_log, 75, axis=0)
    iqr = q3 - q1
    iqr[iqr == 0] = 1.0
    X_train_s = (X_train_log - median) / iqr
    X_val_s = (np.log1p(X_val) - median) / iqr

    # ─── 6. Train XGBoost ──────────────────────────────────────
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
    log(f'\n[6] Training XGBoost (scale_pos_weight={ratio:.2f})...')
    model = xgb.train(params, dtrain, num_boost_round=150,
                      evals=[(dtrain,'train'),(dval,'val')],
                      verbose_eval=20)

    # ─── 7. Evaluate ───────────────────────────────────────────
    log('\n[7] Validation set evaluation:')
    preds = model.predict(dval)
    best_f1 = 0.0
    best_thr = 0.50
    for thr in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45,
                0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
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

    # ─── 8. Save model ─────────────────────────────────────────
    model_path = '/home/emirhan/bitirme/models/bruteforce_model.json'
    model.save_model(model_path)
    log(f'\n[8] Model saved: {model_path}')

    # ─── 9. Save scaler ────────────────────────────────────────
    scaler = {
        'median': [float(f'{v:.6f}') for v in median],
        'iqr': [float(f'{v:.6f}') for v in iqr],
    }
    scaler_path = '/home/emirhan/bitirme/models/bruteforce_model_scaler.json'
    with open(scaler_path, 'w') as f:
        json.dump(scaler, f, indent=2)
    log(f'[9] Scaler saved: {scaler_path}')

    # ─── 10. C++ scaler params ─────────────────────────────────
    log('\n[10] C++ Scaler Params:')
    med_str = ', '.join(f'{v:.6f}' for v in median)
    iqr_str = ', '.join(f'{v:.6f}' for v in iqr)
    log(f'  {{ {med_str} }},')
    log(f'  {{ {iqr_str} }}')

    # ─── 11. Feature importance ────────────────────────────────
    imp = model.get_score(importance_type='weight')
    log('\n[11] Feature importance (weight):')
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
