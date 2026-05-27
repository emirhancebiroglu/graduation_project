#!/usr/bin/env python3
"""train_bot_client_v4.py — Retrain bot client model from Snort dump files.
- 22 features (match C++ AGG_FEATURE_COUNT=22)
- Correct bot IP set: CICIDS Friday ground truth (.5 .8 .9 .12 .14 .15 .17)
- Labels by src_ip column in dump files
"""
import numpy as np
import xgboost as xgb
import json
import warnings
from pathlib import Path
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')

DUMP_DIR = Path('/tmp/botcl_dump')
# Dump column order (25 cols total):
# lb  syn_cnt dst_ips dst_ports iat_cv entropy port_ratio rate ip_conc ip_ratio
# ip_ent iat_q90 time_den p_ip_r hshake inc_r data_d rst_r int_ratio in_bytes
# fin_ratio push_ratio tcp_win score src_ip
# Index: 0   1       2       3        4     5       6         7    8       9
#        10     11      12       13      14     15     16      17     18      19
#        20        21        22     23    24

FEAT_COLS = slice(1, 23)   # columns 1–22 (22 features)
SRC_IP_COL = 24
SCORE_COL = 23

N_FEATURES = 22

FEAT_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'iat_cv', 'entropy', 'port_ratio', 'rate',
    'ip_conc', 'ip_ratio', 'ip_entropy', 'iat_q90', 'time_density', 'port_ip_ratio',
    'handshake', 'inc_ratio', 'data_density', 'rst_rate', 'internal_ip_ratio',
    'bytes_per_syn', 'fin_ratio', 'push_ratio', 'mean_window'
]

# Correct CICIDS Friday bot IPs (decimal) — standard 7 bot IPs from CIC-IDS2017
BOT_IPS_CICIDS = {
    3232238085,  # 192.168.10.5
    3232238088,  # 192.168.10.8
    3232238089,  # 192.168.10.9
    3232238092,  # 192.168.10.12
    3232238094,  # 192.168.10.14
    3232238095,  # 192.168.10.15
    3232238097,  # 192.168.10.17
}

def load_dump(path, bot_ips=None):
    """Load dump. Returns (X, y).
    If bot_ips given, label 1 for matching src_ip, else all 0.
    """
    try:
        data = np.loadtxt(path, comments='#')
    except Exception as e:
        print(f"  WARN: skip {path.name}: {e}")
        return None, None
    if data.ndim == 1:
        data = data.reshape(1, -1)
    if data.shape[1] < 25:
        if data.shape[1] < 24:
            print(f"  WARN: {path.name} has only {data.shape[1]} cols, expected >=25")
            return None, None
        X = data[:, 1:23].astype(np.float64)
        src_ips = data[:, 23].astype(np.uint64)
    else:
        X = data[:, FEAT_COLS].astype(np.float64)
        src_ips = data[:, SRC_IP_COL].astype(np.uint64)

    if bot_ips is not None:
        y = np.array([1 if int(ip) in bot_ips else 0 for ip in src_ips], dtype=np.int32)
    else:
        y = np.zeros(len(X), dtype=np.int32)
    return X, y

print("=== Bot Client Model v4 Correction Training ===")
print(f"Features ({N_FEATURES}): {FEAT_NAMES}\n")
print(f"Bot IPs: {sorted(BOT_IPS_CICIDS)}\n")

all_X, all_y = [], []

# CIC Friday — labeled by correct bot IPs
path = DUMP_DIR / 'cicids_Friday.txt'
X, y = load_dump(path, BOT_IPS_CICIDS)
if X is not None:
    pos, neg = y.sum(), (y==0).sum()
    print(f"  cicids_Friday.txt: {len(X)} rows, pos={pos}, neg={neg}")
    all_X.append(X); all_y.append(y)

# CIC Mon-Thu — all benign
for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday']:
    path = DUMP_DIR / f'cicids_{day}.txt'
    X, _ = load_dump(path, bot_ips=None)
    if X is None:
        continue
    y = np.zeros(len(X), dtype=np.int32)
    print(f"  cicids_{day}.txt: {len(X)} rows, all benign")
    all_X.append(X); all_y.append(y)

# MTA Xworm — external C2 bot (all positive)
path = DUMP_DIR / 'mta_xworm.txt'
if path.exists():
    X, _ = load_dump(path, bot_ips=None)
    if X is not None:
        y = np.ones(len(X), dtype=np.int32)
        print(f"  mta_xworm.txt: {len(X)} rows, all positive (Xworm C2)")
        all_X.append(X); all_y.append(y)

# MTA 31-Jan — malware C2 (all positive)
path = DUMP_DIR / 'mta_31jan.txt'
if path.exists():
    X, _ = load_dump(path, bot_ips=None)
    if X is not None:
        y = np.ones(len(X), dtype=np.int32)
        print(f"  mta_31jan.txt: {len(X)} rows, all positive (malware C2)")
        all_X.append(X); all_y.append(y)

# MTA 28-Feb — benign
path = DUMP_DIR / 'mta_28feb.txt'
if path.exists():
    X, _ = load_dump(path, bot_ips=None)
    if X is not None:
        y = np.zeros(len(X), dtype=np.int32)
        print(f"  mta_28feb.txt: {len(X)} rows, all benign")
        all_X.append(X); all_y.append(y)

X_all = np.vstack(all_X)
y_all = np.concatenate(all_y)
total_pos = y_all.sum()
total_neg = len(y_all) - total_pos
print(f"\nTotal: {len(X_all)} windows, pos={total_pos}, neg={total_neg}")

# No preprocessing — match C++ raw feature pass-through
# C++ infer() sends raw features to XGBoost without log1p or scaling
X_s = X_all

X_tr, X_te, y_tr, y_te = train_test_split(
    X_s, y_all, test_size=0.20, random_state=42, stratify=y_all
)

# Compute scaler for reference (not used at inference, just for documentation)
median = np.median(X_all, axis=0)
q1 = np.percentile(X_all, 25, axis=0)
q3 = np.percentile(X_all, 75, axis=0)
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
model = xgb.train(params, dtrain, num_boost_round=400,
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

# Save model + scaler
MODEL_OUT = '/home/emirhan/bitirme/models/bot_client_v4.json'
SCALER_OUT = '/home/emirhan/bitirme/models/bot_client_v4_scaler.json'
model.save_model(MODEL_OUT)
print(f'Model saved: {MODEL_OUT}')

scaler = {
    'median': [float(f'{v:.10f}') for v in median],
    'iqr': [float(f'{v:.10f}') for v in iqr],
    'log1p_all': True,
    'n_features': N_FEATURES
}
with open(SCALER_OUT, 'w') as f:
    json.dump(scaler, f, indent=2)
print(f'Scaler saved: {SCALER_OUT}')

print('\nC++ scaler params (paste into bot_client_inspector.cc):')
print(f'  median: {{ {", ".join(f"{v:.10f}" for v in median)} }},')
print(f'  iqr:    {{ {", ".join(f"{v:.10f}" for v in iqr)} }}')

print('\nFeature importance (top 10):')
imp = model.get_score(importance_type='weight')
feats_imp = sorted(zip(FEAT_NAMES, [imp.get(f'f{i}', 0) for i in range(N_FEATURES)]), key=lambda x: -x[1])
for name, v in feats_imp[:10]:
    print(f'  {name}: {v}')
