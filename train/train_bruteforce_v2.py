#!/usr/bin/env python3
"""Train bruteforce model v2 — 10 features matching C++ AGG_FEATURE_COUNT=10."""
import numpy as np
import xgboost as xgb
import json
import warnings
from pathlib import Path
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')

DUMP_DIR = Path('/home/emirhan/bitirme/data/snort_dump/bruteforce')
# Dump column order: lb syn_cnt dst_ips dst_ports port_ratio sps rate iat_cv hshake rst_ah bytes score src_ip
# Indices:           0  1       2       3         4          5   6    7      8     9       10    11    12
FEAT_COLS = slice(1, 11)   # columns 1–10 (10 features)
SRC_IP_COL = 12
ATTACKER_IP_CIC   = 0xAC100001  # 172.16.0.1 — CIC Tuesday
ATTACKER_IP_SYNTH = 0x0A000001  # 10.0.0.1   — synthetic PCAPs
ATTACKER_IP_SYNTH_D = [0x0A000002, 0x0A000003, 0x0A000004]  # distributed brute

FEAT_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'port_ratio', 'single_port_score',
    'rate', 'iat_cv', 'handshake_ratio', 'rst_after_handshake', 'bytes_per_syn'
]

ATTACK_DUMPS = [
    'tuesday_attack_dump.txt',
    'synth_hydra_fast_dump.txt',
    'synth_hydra_moderate_dump.txt',
    'synth_medusa_slow_dump.txt',
    'synth_patator_fast_dump.txt',
    'synth_patator_slow_dump.txt',
    'synth_custom_erratic_dump.txt',
    'synth_distributed_brute_dump.txt',
    'synth_ncrack_burst_dump.txt',
    'synth_very_slow_dump.txt',
    'synth_extra_fast_dump.txt',
]

BENIGN_DUMPS = [
    'monday_dump.txt',
    'wednesday_dump.txt',
    'thursday_dump.txt',
]

def load_dump(path):
    """Load dump file, return (X_raw, src_ips)."""
    try:
        data = np.loadtxt(path, comments='#')
    except Exception as e:
        print(f"  WARN: skip {path.name}: {e}")
        return None, None
    if data.ndim == 1:
        data = data.reshape(1, -1)
    if data.shape[1] < 13:
        print(f"  WARN: {path.name} has only {data.shape[1]} cols, expected ≥13")
        return None, None
    return data[:, FEAT_COLS].astype(np.float64), data[:, SRC_IP_COL].astype(np.uint64)

print("=== BruteForce Model v2 Training ===")
print(f"Features ({len(FEAT_NAMES)}): {FEAT_NAMES}\n")

all_X, all_y = [], []

SYNTH_ATTACKER_IPS = {ATTACKER_IP_SYNTH} | set(ATTACKER_IP_SYNTH_D)

# Load attack dumps — CIC dump labels by ATTACKER_IP_CIC, synth by SYNTH_ATTACKER_IPS
for fname in ATTACK_DUMPS:
    path = DUMP_DIR / fname
    if not path.exists():
        print(f"  SKIP (not found): {fname}")
        continue
    X, ips = load_dump(path)
    if X is None:
        continue
    is_synth = fname.startswith('synth_')
    if is_synth:
        y = np.isin(ips, list(SYNTH_ATTACKER_IPS)).astype(np.int32)
    else:
        y = (ips == ATTACKER_IP_CIC).astype(np.int32)
    pos, neg = y.sum(), (y == 0).sum()
    print(f"  {fname}: {len(X)} rows, pos={pos}, neg={neg}")
    all_X.append(X)
    all_y.append(y)

# Load benign dumps — all negative
for fname in BENIGN_DUMPS:
    path = DUMP_DIR / fname
    if not path.exists():
        print(f"  SKIP (not found): {fname}")
        continue
    X, ips = load_dump(path)
    if X is None:
        continue
    y = np.zeros(len(X), dtype=np.int32)
    print(f"  {fname}: {len(X)} rows, all benign")
    all_X.append(X)
    all_y.append(y)

X_all = np.vstack(all_X)
y_all = np.concatenate(all_y)
total_pos = y_all.sum()
total_neg = len(y_all) - total_pos
print(f"\nTotal: {len(X_all)} windows, pos={total_pos}, neg={total_neg}")

# Log1p + RobustScaler (must match C++ preprocess order)
X_log = np.log1p(X_all)
median = np.median(X_log, axis=0)
q1 = np.percentile(X_log, 25, axis=0)
q3 = np.percentile(X_log, 75, axis=0)
iqr = q3 - q1
iqr[iqr == 0] = 1.0
X_s = (X_log - median) / iqr

X_tr, X_te, y_tr, y_te = train_test_split(
    X_s, y_all, test_size=0.20, random_state=42, stratify=y_all
)

ratio = (len(y_tr) - y_tr.sum()) / max(y_tr.sum(), 1)
print(f"Train: {len(X_tr)}, pos={y_tr.sum()} | Val: {len(X_te)}, pos={y_te.sum()}")
print(f"scale_pos_weight={ratio:.2f}\n")

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
model = xgb.train(params, dtrain, num_boost_round=300,
                  evals=[(dtrain, 'train'), (dval, 'val')], verbose_eval=25)

preds = model.predict(dval)
print('\nThreshold sweep:')
best_f1, best_thr = 0.0, 0.50
for thr in [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90]:
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

print(f'\nBest: thr={best_thr:.2f}, F1={best_f1:.4f}')

# Save model + scaler
MODEL_OUT = '/home/emirhan/bitirme/models/bruteforce_model_v2.json'
SCALER_OUT = '/home/emirhan/bitirme/models/bruteforce_model_v2_scaler.json'
model.save_model(MODEL_OUT)
print(f'Model saved: {MODEL_OUT}')

scaler = {
    'median': [float(f'{v:.10f}') for v in median],
    'iqr': [float(f'{v:.10f}') for v in iqr],
    'log1p_all': True,
    'n_features': len(FEAT_NAMES)
}
with open(SCALER_OUT, 'w') as f:
    json.dump(scaler, f, indent=2)
print(f'Scaler saved: {SCALER_OUT}')

print('\nC++ scaler params (paste into bruteforce_inspector.cc):')
print(f'  median: {{ {", ".join(f"{v:.10f}" for v in median)} }},')
print(f'  iqr:    {{ {", ".join(f"{v:.10f}" for v in iqr)} }}')

print('\nFeature importance (weight):')
imp = model.get_score(importance_type='weight')
for name, v in sorted(zip(FEAT_NAMES, [imp.get(f'f{i}', 0) for i in range(10)]), key=lambda x: -x[1]):
    print(f'  {name}: {v}')
