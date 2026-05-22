#!/usr/bin/env python3
"""Read combined C++ dump files, label attacker + hard negs, train XGBoost."""
import numpy as np, xgboost as xgb, json, os, glob
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

DUMP_DIR = '/home/emirhan/bitirme/results/dos_aggregator'
MODEL_PATH = '/home/emirhan/bitirme/models/dos_aggregator_model.json'

SCANNER_IP = 0xAC100001
HARD_NEG_IPS = [
    0xC0A80A08, 0xC0A80A09, 0xC0A80A0C, 0xC0A80A0F,
    0xC0A80A10, 0xC0A80A11,
]

all_data = []
for fname in sorted(glob.glob(os.path.join(DUMP_DIR, 'dos_train_data_*.txt'))):
    day = os.path.basename(fname).replace('dos_train_data_', '').replace('.txt', '')
    data = np.loadtxt(fname, comments='#')
    print(f'{day}: {len(data)} windows')
    all_data.append(data)
data = np.vstack(all_data)
print(f'Total: {len(data)} windows')

X_raw = data[:, 1:8].astype(np.float64)
src_ips = data[:, 9].astype(np.uint32)

y = np.zeros(len(data), dtype=np.int32)
y[src_ips == SCANNER_IP] = 1
sample_weight = np.ones(len(data))
for hip in HARD_NEG_IPS:
    sample_weight[src_ips == hip] = 3.0

pos = y.sum()
hard_neg = ((sample_weight == 3.0) & (y == 0)).sum()
easy_neg = ((sample_weight == 1.0) & (y == 0)).sum()
print(f'Positives (attacker):    {pos}')
print(f'Hard negatives (FP IPs): {hard_neg}')
print(f'Easy negatives:          {easy_neg}')

log1p_cols = [0, 1, 2, 6]
X = X_raw.copy()
for i in log1p_cols:
    X[:, i] = np.log1p(X[:, i])

X_tr, X_te, y_tr, y_te, sw_tr, sw_te = train_test_split(
    X, y, sample_weight, test_size=0.2, random_state=42, stratify=y
)

scaler = RobustScaler()
X_tr_s = scaler.fit_transform(X_tr)
X_te_s = scaler.transform(X_te)

print(f'\nTrain: {X_tr_s.shape}, pos={y_tr.sum()}/{len(y_tr)}')
print(f'Test:  {X_te_s.shape}, pos={y_te.sum()}/{len(y_te)}')

model = xgb.XGBClassifier(
    n_estimators=200, max_depth=4, learning_rate=0.1,
    objective='binary:logistic', tree_method='hist',
    random_state=42, n_jobs=-1
)
model.fit(X_tr_s, y_tr, sample_weight=sw_tr,
          eval_set=[(X_te_s, y_te)], verbose=False)

proba = model.predict_proba(X_te_s)[:, 1]

print('\nThreshold sweep:')
best_f1 = 0
best_t = 0.30
for t in [x/100 for x in range(5, 96, 5)]:
    yp = (proba >= t).astype(int)
    tp = ((y_te==1)&(yp==1)).sum()
    fp = ((y_te==0)&(yp==1)).sum()
    fn = ((y_te==1)&(yp==0)).sum()
    tn = ((y_te==0)&(yp==0)).sum()
    rec = tp/(tp+fn) if (tp+fn)>0 else 0
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0
    mark = ' <--' if f1 > best_f1 else ''
    if f1 > best_f1: best_f1, best_t = f1, t
    print(f't={t:.2f}: TP={tp} FP={fp} FN={fn} TN={tn} Rec={rec:.4f} Pre={prec:.4f} F1={f1:.4f} FPR={fpr:.6f}{mark}')

model.save_model(MODEL_PATH)
print(f'\nModel saved: {MODEL_PATH}')
print(f'Best threshold: {best_t:.2f} (F1={best_f1:.4f})')

median = scaler.center_
iqr = scaler.scale_
print(f'\nC++ Scaler Params:')
print(f'  {{ {", ".join(f"{v:.10f}" for v in median)} }},')
print(f'  {{ {", ".join(f"{v:.10f}" for v in iqr)} }}')

sp = {'median': [round(v,10) for v in median],
      'iqr': [round(v,10) for v in iqr]}
with open('/home/emirhan/bitirme/models/dos_aggregator_model_scaler.json', 'w') as f:
    json.dump(sp, f, indent=2)
