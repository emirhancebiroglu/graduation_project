#!/usr/bin/env python3
"""dos_aggregator: Leave-one-day-out cross-validation.

Trains on 4 days, tests on the held-out day. Reports IP-level TP/FP for the
attacker (172.16.0.1) on Wednesday/Friday (known DoS days).
"""
import numpy as np, xgboost as xgb, json, os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

DUMP_DIR = '/home/emirhan/bitirme/results/dos_aggregator'
SCANNER_IP = 0xAC100001
HARD_NEG_IPS = [0xC0A80A08, 0xC0A80A09, 0xC0A80A0C, 0xC0A80A0F, 0xC0A80A10, 0xC0A80A11]

days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']

# Load all dumps
all_data = {}
for day in days:
    fname = os.path.join(DUMP_DIR, f'dos_train_data_{day}.txt')
    data = np.loadtxt(fname, comments='#')
    all_data[day] = data
    print(f'{day}: {len(data)} windows')

print()
print('Leave-one-day-out cross-validation:')
print(f'  {"Held-out":>12}  {"TP(Wed)":>8}  {"FP(Wed)":>8}  {"TP(Fri)":>8}  {"FP(Fri)":>8}  {"Prec(Wed)":>10}  {"Rec(Wed)":>10}  {"Prec(Fri)":>10}  {"Rec(Fri)":>10}')
print(f'  {"-"*90}')

for held_out in days:
    train_data = []
    for day in days:
        if day != held_out:
            train_data.append(all_data[day])
    train = np.vstack(train_data)

    X_raw = train[:, 1:8].astype(np.float64)
    src_ips = train[:, 9].astype(np.uint32)
    y = np.zeros(len(train), dtype=np.int32)
    y[src_ips == SCANNER_IP] = 1
    sw = np.ones(len(train))
    for hip in HARD_NEG_IPS:
        sw[src_ips == hip] = 3.0

    log1p_cols = [0, 1, 2, 6]
    X = X_raw.copy()
    for i in log1p_cols:
        X[:, i] = np.log1p(X[:, i])

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    neg_pos_ratio = (len(y) - y.sum()) / max(y.sum(), 1)
    model = xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                              objective='binary:logistic', tree_method='hist',
                              scale_pos_weight=neg_pos_ratio, random_state=42)
    model.fit(X_scaled, y, sample_weight=sw)

    # Test on held-out day
    test = all_data[held_out]
    Xt_raw = test[:, 1:8].astype(np.float64)
    src_t = test[:, 9].astype(np.uint32)
    yt = np.zeros(len(test), dtype=np.int32)
    yt[src_t == SCANNER_IP] = 1

    Xt = Xt_raw.copy()
    for i in log1p_cols:
        Xt[:, i] = np.log1p(Xt[:, i])
    Xt_scaled = scaler.transform(Xt)

    y_prob = model.predict_proba(Xt_scaled)[:, 1]

    # For each day, evaluate Wednesday-attacker and Friday-attacker scenarios
    for test_day_type, thr in [('Wed', 0.30), ('Fri', 0.30)]:
        y_pred = (y_prob >= thr).astype(np.int32)

        # Find unique alerted IPs
        alerted_mask = y_pred == 1
        alerted_ips = set(src_t[alerted_mask])

        # Known attacker on target day
        if held_out == 'Wednesday':
            known_attacker = {SCANNER_IP}
        elif held_out == 'Friday':
            known_attacker = {SCANNER_IP}
        else:
            known_attacker = set()

        tp_ip = alerted_ips & known_attacker
        fp_ip = alerted_ips - known_attacker
        fn_ip = known_attacker - alerted_ips

        tp = len(tp_ip)
        fp = len(fp_ip)
        fn = len(fn_ip)

        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp > 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        if test_day_type == 'Wed':
            tp_w, fp_w, prec_w, rec_w = tp, fp, prec, rec
        else:
            tp_f, fp_f, prec_f, rec_f = tp, fp, prec, rec

    print(f'  {held_out:>12}  {tp_w:>8}  {fp_w:>8}  {tp_f:>8}  {fp_f:>8}  {prec_w:>10.4f}  {rec_w:>10.4f}  {prec_f:>10.4f}  {rec_f:>10.4f}')

# Also train on ALL days and report final metrics
print()
print('Final model (trained on all 5 days):')
all_train = np.vstack([all_data[d] for d in days])
X_raw = all_train[:, 1:8].astype(np.float64)
src_ips = all_train[:, 9].astype(np.uint32)
y = np.zeros(len(all_train), dtype=np.int32)
y[src_ips == SCANNER_IP] = 1
sw = np.ones(len(all_train))
for hip in HARD_NEG_IPS:
    sw[src_ips == hip] = 3.0

log1p_cols = [0, 1, 2, 6]
X = X_raw.copy()
for i in log1p_cols:
    X[:, i] = np.log1p(X[:, i])
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
neg_pos_ratio = (len(y) - y.sum()) / max(y.sum(), 1)
model = xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                          objective='binary:logistic', tree_method='hist',
                          scale_pos_weight=neg_pos_ratio, random_state=42)
model.fit(X_scaled, y, sample_weight=sw)

print(f'  Trees: {len(model.get_booster().get_dump())}')
print(f'  Scaler median: {np.array2string(scaler.center_, precision=4)}')
print(f'  Scaler iqr:    {np.array2string(scaler.scale_, precision=4)}')

# Per-day eval
for day in days:
    test = all_data[day]
    Xt_raw = test[:, 1:8].astype(np.float64)
    src_t = test[:, 9].astype(np.uint32)
    Xt = Xt_raw.copy()
    for i in log1p_cols:
        Xt[:, i] = np.log1p(Xt[:, i])
    Xt_scaled = scaler.transform(Xt)
    y_prob = model.predict_proba(Xt_scaled)[:, 1]
    y_pred = (y_prob >= 0.30).astype(np.int32)

    alerted_ips = set(src_t[y_pred == 1])
    attacker_present = SCANNER_IP in src_t
    attacker_detected = SCANNER_IP in alerted_ips
    fPs = alerted_ips - {SCANNER_IP}

    print(f'  {day:>12}: alerts={len(alerted_ips):>3} IPs  attacker={attacker_detected}  FP={sorted(fPs)}')
