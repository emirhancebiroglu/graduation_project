import os, sys, json, warnings, random
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.model_selection import train_test_split
import xgboost as xgb

warnings.filterwarnings('ignore')

def log(m):
    print(m, flush=True)

WINDOW_SEC = 120
FEAT_NAMES = ['syn_count','src_ips','iat_cv','dst_ports','src_ports','port_ratio','rate','port_entropy']
NEG_SAMPLE_CAP = 200000

def parse_cicids_csv(path, label_val, sample=None):
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
    flows = []
    for _, r in df.iterrows():
        try:
            ts = pd.to_datetime(r[' Timestamp']).timestamp()
        except:
            ts = 0.0
        flows.append({
            'src_ip': str(r[' Source IP']),
            'dst_ip': str(r[' Destination IP']),
            'src_port': safe_int(r[' Source Port']),
            'dst_port': safe_int(r[' Destination Port']),
            'timestamp': ts,
        })
    return flows

CTU_COLS = ['StartTime','Proto','SrcAddr','Sport','DstAddr','Dport','Label']
CTU_DTYPES = {'StartTime': str, 'Proto': str, 'SrcAddr': str, 'Sport': str,
              'DstAddr': str, 'Dport': str, 'Label': str}

def safe_int(v, default=0):
    try:
        return int(float(v))
    except:
        return default

def parse_ctu_binetflow(path):
    pos = []
    bg_buf = []
    total = 0
    botnet = 0
    log(f'  Reading {os.path.basename(path)} in chunks...')
    for chunk in pd.read_csv(path, usecols=CTU_COLS, dtype=CTU_DTYPES,
                              low_memory=True, chunksize=500000):
        lc = 'Label'
        bot_mask = chunk[lc].astype(str).str.contains('Botnet', na=False)
        bot_chunk = chunk[bot_mask]
        bg_chunk = chunk[~bot_mask]
        total += len(chunk)
        botnet += len(bot_chunk)
        for _, r in bot_chunk.iterrows():
            try:
                ts = pd.to_datetime(r['StartTime']).timestamp()
            except:
                ts = 0.0
            pos.append({
                'src_ip': str(r['SrcAddr']),
                'dst_ip': str(r['DstAddr']),
                'src_port': safe_int(r['Sport']),
                'dst_port': safe_int(r['Dport']),
                'timestamp': ts,
            })
        bg_buf.append(bg_chunk)
        if len(pos) >= 500000:
            log(f'  Reached 500K pos, stopping early...')
            break
    log(f'  Scanned {total} rows, found {botnet} botnet')
    neg = []
    if bg_buf:
        bg_all = pd.concat(bg_buf, ignore_index=True)
        bg_sample = bg_all.sample(min(len(bg_all), 100000), random_state=42)
        for _, r in bg_sample.iterrows():
            try:
                ts = pd.to_datetime(r['StartTime']).timestamp()
            except:
                ts = 0.0
            neg.append({
                'src_ip': str(r['SrcAddr']),
                'dst_ip': str(r['DstAddr']),
                'src_port': safe_int(r['Sport']),
                'dst_port': safe_int(r['Dport']),
                'timestamp': ts,
            })
    log(f'  Extracted {len(pos)} pos, {len(neg)} neg')
    return pos, neg

def aggregate_window(flows, window_sec):
    groups = defaultdict(lambda: defaultdict(list))
    for f in flows:
        dst = f['dst_ip']
        win = int(f['timestamp'] / window_sec) * window_sec
        groups[dst][win].append(f)
    samples = []
    for dst_ip, windows in groups.items():
        for win_start, flist in windows.items():
            syn_ts = sorted([f['timestamp'] for f in flist])
            src_ips = len(set(f['src_ip'] for f in flist))
            dst_ports = len(set(f['dst_port'] for f in flist))
            src_ports = len(set(f['src_port'] for f in flist))
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
                'syn_count': n, 'src_ips': src_ips, 'iat_cv': iat_cv,
                'dst_ports': dst_ports, 'src_ports': src_ports,
                'port_ratio': port_ratio, 'rate': rate,
                'port_entropy': entropy,
                'dst_ip': dst_ip, 'label': 0
            })
    return samples

def main():
    log('='*60)
    log('  Botnet C2 Training Pipeline v2')
    log('='*60)
    log('')

    pos_samples = []

    ctu_dir = '/home/emirhan/bitirme/data/raw/ctu13_binetflow'
    if os.path.exists(ctu_dir):
        log('[1a] Loading CTU-13 merged binetflow...')
        merged = os.path.join(ctu_dir, 'ctu13_all_merged.binetflow.csv')
        if os.path.exists(merged):
            pos, _neg_from_ctu = parse_ctu_binetflow(merged)
            pos_samples.extend(pos)
        else:
            for fname in sorted(os.listdir(ctu_dir)):
                if fname.endswith('.binetflow') or fname.endswith('.csv'):
                    pos, _ = parse_ctu_binetflow(os.path.join(ctu_dir, fname))
                    pos_samples.extend(pos)
        log(f'  CTU-13 botnet flows: {len(pos_samples)}')

    friday_bot_path = '/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
    if os.path.exists(friday_bot_path):
        log('[1b] Loading CICIDS Friday-Morning Bot...')
        bot = parse_cicids_csv(friday_bot_path, 'Bot')
        pos_samples.extend(bot)
        log(f'  CICIDS Bot flows: {len(bot)}')

    log(f'\n  Total positive flows: {len(pos_samples)}')

    neg_samples = []
    log('\n[2] Loading BENIGN samples from CICIDS2017...')

    cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'
    benign_sources = [
        ('Monday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 100000),
        ('Tuesday-WorkingHours.pcap_ISCX.csv', 'BENIGN', 50000),
        ('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 'BENIGN', 25000),
        ('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 'BENIGN', 25000),
    ]
    total_neg = 0
    for fname, label, cap in benign_sources:
        path = os.path.join(cicids_dir, fname)
        if os.path.exists(path):
            flows = parse_cicids_csv(path, label, sample=cap)
            neg_samples.extend(flows)
            total_neg += len(flows)
    random.shuffle(neg_samples)
    if len(neg_samples) > NEG_SAMPLE_CAP:
        neg_samples = neg_samples[:NEG_SAMPLE_CAP]
    log(f'  Total BENIGN flows: {len(neg_samples)}')

    if len(pos_samples) < 10:
        log('ERROR: Too few positive samples.')
        sys.exit(1)

    log(f'\n[3] Aggregating into {WINDOW_SEC}s windows...')
    pos_agg = aggregate_window(pos_samples, WINDOW_SEC)
    for s in pos_agg:
        s['label'] = 1
    log(f'  Positive windows: {len(pos_agg)}')

    neg_agg = aggregate_window(neg_samples, WINDOW_SEC)
    for s in neg_agg:
        s['label'] = 0
    log(f'  Negative windows: {len(neg_agg)}')

    all_samples = pos_agg + neg_agg
    random.shuffle(all_samples)

    X = np.array([[s['syn_count'], s['src_ips'], s['iat_cv'],
                   s['dst_ports'], s['src_ports'], s['port_ratio'], s['rate'],
                   s['port_entropy']]
                  for s in all_samples], dtype=np.float64)
    Y = np.array([s['label'] for s in all_samples], dtype=np.int32)

    log(f'\n  Total windows: {len(X)}, pos={Y.sum()}, neg={len(Y)-Y.sum()}')

    X_train, X_val, Y_train, Y_val = train_test_split(
        X, Y, test_size=0.20, random_state=42, stratify=Y)
    log(f'\n[5] Split: train={len(X_train)}, val={len(X_val)}')
    log(f'  Train: pos={Y_train.sum()}, neg={len(Y_train)-Y_train.sum()}')
    log(f'  Val:   pos={Y_val.sum()}, neg={len(Y_val)-Y_val.sum()}')

    X_train_log = np.log1p(X_train)
    median = np.median(X_train_log, axis=0)
    q1 = np.percentile(X_train_log, 25, axis=0)
    q3 = np.percentile(X_train_log, 75, axis=0)
    iqr = q3 - q1
    iqr[iqr == 0] = 1.0

    X_train_s = (X_train_log - median) / iqr
    X_val_s = (np.log1p(X_val) - median) / iqr

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

    model_path = '/home/emirhan/bitirme/models/botnet_c2_model.json'
    model.save_model(model_path)
    log(f'\n[9] Model saved: {model_path}')

    scaler = {
        'median': [float(f'{v:.6f}') for v in median],
        'iqr': [float(f'{v:.6f}') for v in iqr],
    }
    scaler_path = '/home/emirhan/bitirme/models/botnet_c2_model_scaler.json'
    with open(scaler_path, 'w') as f:
        json.dump(scaler, f, indent=2)
    log(f'[10] Scaler saved: {scaler_path}')

    log('\n[11] C++ Scaler Params (paste into botnet_c2_inspector.cc):')
    med_str = ', '.join(f'{v:.6f}' for v in median)
    iqr_str = ', '.join(f'{v:.6f}' for v in iqr)
    log(f'  {{ {med_str} }},')
    log(f'  {{ {iqr_str} }}')

    imp = model.get_score(importance_type='weight')
    log('\n[12] Feature importance (weight):')
    for name, imp_val in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}',0) for i in range(8)]), key=lambda x: -x[1]):
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
