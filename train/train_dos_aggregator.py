#!/usr/bin/env python3
"""Label dos_train_data.txt using known attacker IP, train XGBoost model."""
import numpy as np, xgboost as xgb, json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

data = np.loadtxt('/tmp/dos_train_data.txt', comments='#')
X_raw = data[:, 1:8]   # 7 features
scores = data[:, 8]     # score column
src_ips = data[:, 9].astype(np.uint32)  # src_ip in network byte order

# Label: attacker IP = 172.16.0.1 = 0xAC100001
SCANNER_IP = 0xAC100001
y = (src_ips == SCANNER_IP).astype(int)

print(f'Total windows: {len(X_raw)}')
print(f'Scanner IP windows: {y.sum()}')
print(f'Benign windows: {(1-y).sum()}')

X = X_raw.astype(np.float64)
log1p_cols = [0, 1, 2, 6]  # syn_cnt, syn_uports, syn_uips, srate
for i in log1p_cols:
    X[:, i] = np.log1p(X[:, i])

X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = RobustScaler()
X_tr_s = scaler.fit_transform(X_tr)
X_te_s = scaler.transform(X_te)

print(f'Train: {X_tr_s.shape}, pos={y_tr.sum()}/{len(y_tr)}')
print(f'Test:  {X_te_s.shape}, pos={y_te.sum()}/{len(y_te)}')

model = xgb.XGBClassifier(
    n_estimators=200, max_depth=4, learning_rate=0.1,
    objective='binary:logistic', tree_method='hist',
    random_state=42, n_jobs=-1
)
model.fit(X_tr_s, y_tr, eval_set=[(X_te_s, y_te)], verbose=False)

proba = model.predict_proba(X_te_s)[:, 1]

print('\nThreshold sweep:')
best_f1 = 0
best_t = 0.50
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

model.save_model('/home/emirhan/bitirme/models/dos_aggregator_model.json')
print(f'\nBest threshold: {best_t:.2f} (F1={best_f1:.4f})')
print(f'Scaler median: {[round(v,10) for v in scaler.center_.tolist()]}')
print(f'Scaler iqr:    {[round(v,10) for v in scaler.scale_.tolist()]}')

sp = {'median': [round(v,10) for v in scaler.center_.tolist()],
      'iqr': [round(v,10) for v in scaler.scale_.tolist()]}
with open('/home/emirhan/bitirme/models/dos_aggregator_scaler_params.json', 'w') as f:
    json.dump(sp, f, indent=2)
