#!/usr/bin/env python3
"""Train ddos_aggregator_v2 model.
- 7 features (match C++ AGG_FEATURE_COUNT=7)
- log1p applied to ALL 7 cols (matches C++ preprocess() which applies log1p to all)
- Attack target: 192.168.10.50 (CIC-IDS2017 Friday DDoS destination)
- Attacker: 172.16.0.1
"""
import numpy as np
import xgboost as xgb
import json
from pathlib import Path
from sklearn.model_selection import train_test_split

# 192.168.10.50:80 — exact DDoS target (HTTP flood, port 80 confirmed by CIC ground truth)
# Key = (dst_ip << 32) | dst_port
DDOS_DST_IP = 0xC0A80A32  # 192.168.10.50
DDOS_DST_PORT = 80
DDOS_KEY = (DDOS_DST_IP << 32) | DDOS_DST_PORT

FEAT_NAMES = ['total_pkts', 'unique_src', 'unique_src_ports', 'ports_per_src', 'reserved', 'src_ratio', 'rate']
N_FEATURES = 7
FEAT_COLS = slice(1, 8)   # columns 1-7
KEY_COL = 9               # column 9 (after label + 7 features + score)

def load_dump(path, label_arg=None, min_rate=None):
    """Load dump. Returns (X, y).
    label_arg: if int and < 2^32 → label by dst_ip (key>>32 == label_arg)
               if int and >= 2^32 → label by exact key
               if None → all zeros
    min_rate: if set, only label as attack if rate (feat[6]) >= min_rate
    Key stored as large uint64 — use string parsing to avoid float64 precision loss.
    """
    try:
        rows_X, keys = [], []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 10:
                    continue
                feat = [float(p) for p in parts[1:8]]
                key = int(parts[9])
                rows_X.append(feat)
                keys.append(key)
        if not rows_X:
            print(f"  WARN: {path} has no rows")
            return None, None
        X = np.array(rows_X, dtype=np.float64)
        if label_arg is not None:
            if label_arg < (1 << 32):
                # Label by dst_ip (key >> 32), optionally requiring min_rate
                if min_rate is not None:
                    y = np.array([1 if (k >> 32) == label_arg and X[i, 6] >= min_rate else 0
                                  for i, k in enumerate(keys)], dtype=np.int32)
                else:
                    y = np.array([1 if (k >> 32) == label_arg else 0 for k in keys], dtype=np.int32)
            else:
                # Label by exact key
                y = np.array([1 if k == label_arg else 0 for k in keys], dtype=np.int32)
        else:
            y = np.zeros(len(X), dtype=np.int32)
    except Exception as e:
        print(f"  WARN: skip {path}: {e}")
        return None, None
    return X, y

print("=== DDoS Aggregator Model v2 Training ===")
print(f"Features ({N_FEATURES}): {FEAT_NAMES}")
print(f"DDoS target: 192.168.10.50:80 (key=0x{DDOS_KEY:016X})\n")

all_X, all_y = [], []

# Friday — label by dst_ip
DUMP_DIR = Path('/tmp')
path = DUMP_DIR / 'ddos_Friday_dump_v3.txt'
# Label by dst_ip=.50 (any port) — SYN dump
X, y = load_dump(str(path), DDOS_DST_IP, min_rate=10.0)
if X is not None:
    pos, neg = y.sum(), (y==0).sum()
    print(f"  friday_dump: {len(X)} rows, pos={pos} (DDoS rate>=10), neg={neg}")
    all_X.append(X); all_y.append(y)

# Benign days — all negative
for fname in ['ddos_Monday_dump_v3.txt', 'ddos_Tuesday_dump_v3.txt', 'ddos_Thursday_dump_v3.txt']:
    path = DUMP_DIR / fname
    if not path.exists():
        print(f"  SKIP: {fname}")
        continue
    X, _ = load_dump(str(path), label_arg=None)
    if X is None:
        continue
    y = np.zeros(len(X), dtype=np.int32)
    print(f"  {fname}: {len(X)} rows, all benign")
    all_X.append(X); all_y.append(y)

X_all = np.vstack(all_X)
y_all = np.concatenate(all_y)
total_pos = y_all.sum()
total_neg = len(y_all) - total_pos
print(f"\nTotal: {len(X_all)} windows, pos={total_pos}, neg={total_neg}")

# Apply log1p to ALL 7 columns — match C++ preprocess() which applies log1p to all
X_log = np.log1p(np.maximum(X_all, 0))

X_tr, X_te, y_tr, y_te = train_test_split(
    X_log, y_all, test_size=0.20, random_state=42, stratify=y_all
)

# Scaler (for C++ hardcoded params)
median = np.median(X_log, axis=0)
q1 = np.percentile(X_log, 25, axis=0)
q3 = np.percentile(X_log, 75, axis=0)
iqr = q3 - q1
iqr[iqr == 0] = 1.0

ratio = (len(y_tr) - y_tr.sum()) / max(y_tr.sum(), 1)
print(f"Train: {len(X_tr)}, pos={y_tr.sum()} | Val: {len(X_te)}, pos={y_te.sum()}")
print(f"scale_pos_weight={ratio:.2f}\n")

params = {
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'max_depth': 5,
    'eta': 0.05,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 3,
    'scale_pos_weight': ratio,
    'seed': 42,
}
dtrain = xgb.DMatrix(X_tr, label=y_tr)
dval = xgb.DMatrix(X_te, label=y_te)
model = xgb.train(params, dtrain, num_boost_round=300,
                  evals=[(dtrain, 'train'), (dval, 'val')], verbose_eval=50)

preds = model.predict(dval)
print('\nThreshold sweep:')
best_f1, best_thr = 0.0, 0.50
for thr in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95]:
    tp = ((preds >= thr) & (y_te == 1)).sum()
    fp = ((preds >= thr) & (y_te == 0)).sum()
    fn = ((preds < thr) & (y_te == 1)).sum()
    tn = ((preds < thr) & (y_te == 0)).sum()
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    mark = ' <--' if f1 > best_f1 else ''
    if f1 > best_f1:
        best_f1, best_thr = f1, thr
    print(f'  thr={thr:.2f} recall={recall:.4f} prec={prec:.4f} f1={f1:.4f} fpr={fpr:.4f} '
          f'tp={tp} fp={fp} fn={fn} tn={tn}{mark}')

print(f'\nBest val: thr={best_thr:.2f}, F1={best_f1:.4f}')

MODEL_OUT = '/home/emirhan/bitirme/models/ddos_aggregator_model_v3.json'
SCALER_OUT = '/home/emirhan/bitirme/models/ddos_aggregator_model_v3_scaler.json'
model.save_model(MODEL_OUT)
print(f'Model saved: {MODEL_OUT}')

scaler = {
    'median': [float(f'{v:.10f}') for v in median],
    'iqr': [float(f'{v:.10f}') for v in iqr],
    'n_features': N_FEATURES
}
with open(SCALER_OUT, 'w') as f:
    json.dump(scaler, f, indent=2)
print(f'Scaler saved: {SCALER_OUT}')

print('\nC++ scaler params (paste into ddos_inspector.cc):')
print(f'  median: {{ {", ".join(f"{v:.10f}" for v in median)} }},')
print(f'  iqr:    {{ {", ".join(f"{v:.10f}" for v in iqr)} }}')

print('\nFeature importance:')
imp = model.get_score(importance_type='weight')
feats_imp = sorted(zip(FEAT_NAMES, [imp.get(f'f{i}', 0) for i in range(N_FEATURES)]), key=lambda x: -x[1])
for name, v in feats_imp:
    print(f'  {name}: {v}')
