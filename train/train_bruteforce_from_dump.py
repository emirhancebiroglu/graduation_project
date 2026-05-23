#!/usr/bin/env python3
"""Train bruteforce model from C++ dump data (PCAP-precision features)."""
import numpy as np, xgboost as xgb, json, warnings
warnings.filterwarnings('ignore')

ATTACKER_IP = 0xAC100001  # 172.16.0.1
WINDOW_SEC = 60.0
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','port_ratio','single_port_score','rate','iat_cv']

data = np.loadtxt('/tmp/bfc_train_data.txt', comments='#')
X_raw = data[:, 1:8].astype(np.float64)
src_ips = data[:, 9].astype(np.uint32)

y = (src_ips == ATTACKER_IP).astype(np.int32)
pos = y.sum()
neg = len(y) - pos
print(f'Total: {len(data)} windows, pos={pos}, neg={neg}')
print(f'Unique IPs: {len(np.unique(src_ips))}')

# Log1p all features (matching C++ preprocess)
X_log = np.log1p(X_raw)

# Median/IQR scaling
median = np.median(X_log, axis=0)
q1 = np.percentile(X_log, 25, axis=0)
q3 = np.percentile(X_log, 75, axis=0)
iqr = q3 - q1
iqr[iqr == 0] = 1.0
X_s = (X_log - median) / iqr

# Stratified random split
from sklearn.model_selection import train_test_split
X_tr, X_te, y_tr, y_te = train_test_split(X_s, y, test_size=0.20, random_state=42, stratify=y)

ratio = (len(y_tr) - y_tr.sum()) / y_tr.sum()
print(f'Train: {len(X_tr)}, pos={y_tr.sum()} | Val: {len(X_te)}, pos={y_te.sum()}')
print(f'scale_pos_weight={ratio:.2f}')

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
dtrain = xgb.DMatrix(X_tr, label=y_tr)
dval = xgb.DMatrix(X_te, label=y_te)
model = xgb.train(params, dtrain, num_boost_round=150,
                  evals=[(dtrain,'train'),(dval,'val')], verbose_eval=20)

preds = model.predict(dval)
print('\nThreshold sweep:')
best_f1, best_thr = 0.0, 0.50
for thr in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45,
            0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
    tp = ((preds >= thr) & (y_te == 1)).sum()
    fp = ((preds >= thr) & (y_te == 0)).sum()
    fn = ((preds < thr) & (y_te == 1)).sum()
    tn = ((preds < thr) & (y_te == 0)).sum()
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    mark = ' <--' if f1 > best_f1 else ''
    if f1 > best_f1: best_f1, best_thr = f1, thr
    print(f'  thr={thr:.2f} recall={recall:.4f} prec={prec:.4f} f1={f1:.4f} fpr={fpr:.4f} tp={tp} fp={fp} fn={fn} tn={tn}{mark}')

print(f'\nBest: thr={best_thr:.2f}, F1={best_f1:.4f}')

model.save_model('/home/emirhan/bitirme/models/bruteforce_model.json')
print('Model saved: bruteforce_model.json')

scaler = {'median': [float(f'{v:.6f}') for v in median],
          'iqr': [float(f'{v:.6f}') for v in iqr]}
with open('/home/emirhan/bitirme/models/bruteforce_model_scaler.json', 'w') as f:
    json.dump(scaler, f, indent=2)
print('Scaler saved.')

print(f'\nC++ params:')
print(f'  {{ {", ".join(f"{v:.6f}" for v in median)} }},')
print(f'  {{ {", ".join(f"{v:.6f}" for v in iqr)} }}')

# Feature importance
imp = model.get_score(importance_type='weight')
for name, v in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}',0) for i in range(7)]), key=lambda x: -x[1]):
    print(f'  {name}: {v}')
