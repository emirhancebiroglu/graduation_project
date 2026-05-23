#!/usr/bin/env python3
"""Train dos_model_v2 with per-category upweighting for Grup A categories.

Grup A (retrain fixable): DoS, Exploits, Reconnaissance, Analysis, Backdoor, Backdoors
Grup B (scope boundary): Fuzzers, Shellcode, Worms — NOT penalized but not upweighted

Strategy:
- Same 11 features, same log1p cols, same RobustScaler as prepare_dataset.py
- Use full UNSW dataset (all 4 files) with 80/20 stratified split
- sample_weight: upweight Grup A minorities so model boundary expands to cover them
- More estimators (500) + slightly stronger regularization
- Save as models/dos_model_v2.json + models/scaler_v2.pkl
"""
import json, logging, pickle
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

BASE = Path('/home/emirhan/bitirme')
UNSW_COLS = [
    'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
    'sttl','dttl','sloss','dloss','service','sload','dload','spkts','dpkts',
    'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'sjit','djit','stime','ltime','sintpkt','dintpkt','tcprtt','synack','ackdat',
    'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
    'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label'
]
SELECTED = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']
LOG_COLS  = ['sbytes','dbytes','spkts','dpkts','dur','sintpkt','dintpkt']

# Per-category sample weights for attack flows
# Grup A low-recall categories get higher weight → model boundary expands
# Benign always weight=1.0
CATEGORY_WEIGHTS = {
    'Generic':        1.0,   # already 0.98 recall — don't overfit
    'DoS':            4.0,   # 0.67 recall
    'Exploits':       6.0,   # 0.33 recall — highest priority
    'Reconnaissance': 6.0,   # 0.13 recall — highest priority
    'Analysis':       4.0,   # 0.68 recall
    'Backdoor':       4.0,   # 0.69 recall
    'Backdoors':      2.0,   # 0.86 recall — already decent
    # Grup B: Fuzzers, Shellcode, Worms — weight 1.0 (no penalization)
    'Fuzzers':        1.0,
    'Shellcode':      1.0,
    'Worms':          1.0,
}

def metrics(yt, yp):
    tp = int(((yt==1)&(yp==1)).sum())
    fp = int(((yt==0)&(yp==1)).sum())
    fn = int(((yt==1)&(yp==0)).sum())
    tn = int(((yt==0)&(yp==0)).sum())
    rec  = tp/(tp+fn)  if (tp+fn)>0  else 0.0
    prec = tp/(tp+fp)  if (tp+fp)>0  else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
    fpr  = fp/(fp+tn)  if (fp+tn)>0  else 0.0
    return dict(tp=tp,fp=fp,fn=fn,tn=tn,
                recall=round(rec,4), precision=round(prec,4),
                f1=round(f1,4), fpr=round(fpr,6))

def main():
    logging.info('Loading UNSW-NB15 (all 4 files)...')
    dfs = []
    for i in [1,2,3,4]:
        path = BASE / 'data' / 'unsw' / f'UNSW-NB15_{i}.csv'
        df = pd.read_csv(path, header=None, names=UNSW_COLS, low_memory=False)
        if str(df.iloc[0,0]).strip().lower() == 'srcip':
            df = df.iloc[1:]
        dfs.append(df)
    full = pd.concat(dfs, ignore_index=True)
    full['label']      = pd.to_numeric(full['label'], errors='coerce').fillna(0).astype(int)
    full['attack_cat'] = full['attack_cat'].astype(str).str.strip()

    df_f = full[SELECTED + ['label','attack_cat']].copy()
    df_f[SELECTED] = df_f[SELECTED].apply(pd.to_numeric, errors='coerce')
    df_f.dropna(subset=SELECTED+['label'], inplace=True)
    for col in LOG_COLS:
        df_f[col] = np.log1p(df_f[col])

    X    = df_f[SELECTED].values.astype(np.float64)
    y    = df_f['label'].values.astype(int)
    cats = df_f['attack_cat'].values

    logging.info(f'Total: {len(y):,}  attack: {y.sum():,}  benign: {(y==0).sum():,}')

    # Category distribution
    for cat, cnt in sorted(pd.Series(cats[y==1]).value_counts().items(), key=lambda x: -x[1]):
        logging.info(f'  {cat:<20}: {cnt:>7,} attack samples')

    # Build sample weights
    sw = np.ones(len(y), dtype=np.float64)
    for i, (label, cat) in enumerate(zip(y, cats)):
        if label == 1:
            sw[i] = CATEGORY_WEIGHTS.get(cat, 1.0)

    # Same split as prepare_dataset.py (test_size=0.2, random_state=42, stratify=y)
    idx = np.arange(len(y))
    idx_tr, idx_te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)

    X_tr, X_te = X[idx_tr], X[idx_te]
    y_tr, y_te = y[idx_tr], y[idx_te]
    sw_tr      = sw[idx_tr]
    cats_te    = cats[idx_te]

    scaler = RobustScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    logging.info(f'Train: {X_tr_s.shape}  pos={y_tr.sum():,}  neg={(y_tr==0).sum():,}')
    logging.info(f'Test:  {X_te_s.shape}  pos={y_te.sum():,}  neg={(y_te==0).sum():,}')

    neg_count = (y_tr == 0).sum()
    pos_count = (y_tr == 1).sum()
    spw = neg_count / pos_count
    logging.info(f'scale_pos_weight={spw:.2f}')

    model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=4,
        learning_rate=0.05,
        objective='binary:logistic',
        tree_method='hist',
        scale_pos_weight=spw,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_lambda=1.0,
        reg_alpha=0.1,
        gamma=0.3,
        random_state=42,
        n_jobs=-1,
        eval_metric='logloss',
    )
    model.fit(
        X_tr_s, y_tr,
        sample_weight=sw_tr,
        eval_set=[(X_te_s, y_te)],
        verbose=100,
    )

    proba = model.predict_proba(X_te_s)[:, 1]

    # Threshold sweep
    print('\nThreshold sweep (overall):')
    best_f1, best_t = 0, 0.5
    for t in [x/100 for x in range(40, 96, 5)]:
        yp = (proba >= t).astype(int)
        m = metrics(y_te, yp)
        mark = ' <--' if m['f1'] > best_f1 else ''
        if m['f1'] > best_f1:
            best_f1, best_t = m['f1'], t
        print(f"  t={t:.2f}: TP={m['tp']:,} FP={m['fp']} FN={m['fn']:,} "
              f"Rec={m['recall']:.4f} Prec={m['precision']:.4f} F1={m['f1']:.4f} FPR={m['fpr']:.6f}{mark}")

    print(f'\nBest overall: threshold={best_t:.2f}  F1={best_f1:.4f}')

    # Per-category at threshold=0.90 (keep same as v1 for fair comparison)
    THRESHOLD = 0.90
    yp_90 = (proba >= THRESHOLD).astype(int)
    print(f'\n=== Per-category Recall @ threshold={THRESHOLD} ===')
    GRUP_A = {'Generic','DoS','Exploits','Reconnaissance','Analysis','Backdoor','Backdoors'}
    GRUP_B = {'Fuzzers','Shellcode','Worms'}
    all_cats_order = ['Generic','DoS','Exploits','Reconnaissance','Analysis','Backdoor','Backdoors',
                      'Fuzzers','Shellcode','Worms']
    per_cat = {}
    for cat in all_cats_order:
        mask = cats_te == cat
        if mask.sum() == 0:
            continue
        yt_c = y_te[mask]; yp_c = yp_90[mask]
        m = metrics(yt_c, yp_c)
        per_cat[cat] = m
        per_cat[cat]['total'] = int(mask.sum())
        per_cat[cat]['n_attacks'] = int(yt_c.sum())
        group = 'A' if cat in GRUP_A else 'B'
        ok = '✅' if m['recall'] >= 0.80 else ('⚠️' if m['recall'] >= 0.60 else '❌')
        print(f"  [{group}] {cat:<18}: Recall={m['recall']:.4f} ({m['tp']:,}/{m['tp']+m['fn']:,})  {ok}")

    # Overall @ 0.90
    overall_90 = metrics(y_te, yp_90)
    print(f'\nOverall @ 0.90: Recall={overall_90["recall"]:.4f}  Prec={overall_90["precision"]:.4f}  '
          f'F1={overall_90["f1"]:.4f}  FPR={overall_90["fpr"]:.6f}')

    # Check acceptance: all Grup A >= 0.80
    grup_a_pass = all(per_cat.get(c, {}).get('recall', 0) >= 0.80
                      for c in GRUP_A if c in per_cat)
    print(f'\nGrup A acceptance (all >= 0.80): {"PASS ✅" if grup_a_pass else "FAIL ❌"}')

    # Save model
    model_path = BASE / 'models' / 'dos_model_v2.json'
    model.save_model(str(model_path))
    logging.info(f'Model saved: {model_path}')

    # Save scaler
    scaler_path = BASE / 'models' / 'scaler_v2.pkl'
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    logging.info(f'Scaler saved: {scaler_path}')

    # Save results
    result = {
        'model': 'dos_model_v2.json',
        'dataset': 'UNSW-NB15 (all 4 files, 20% test split, random_state=42)',
        'threshold': THRESHOLD,
        'n_test': int(len(y_te)),
        'overall': overall_90,
        'per_category': per_cat,
        'category_weights': CATEGORY_WEIGHTS,
        'hyperparams': {
            'n_estimators': 500, 'max_depth': 4, 'learning_rate': 0.05,
            'subsample': 0.8, 'colsample_bytree': 0.8, 'min_child_weight': 3,
            'reg_lambda': 1.0, 'reg_alpha': 0.1, 'gamma': 0.3,
            'scale_pos_weight': round(float(spw), 4),
        }
    }
    out_dir = BASE / 'results' / 'generalization' / 'phase2' / 'dos_model'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / 'unsw_per_category_v2.json'
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    logging.info(f'Results saved: {out_path}')

    print(f'\nScaler median: {[round(v,6) for v in scaler.center_.tolist()]}')
    print(f'Scaler IQR:    {[round(v,6) for v in scaler.scale_.tolist()]}')

if __name__ == '__main__':
    main()
