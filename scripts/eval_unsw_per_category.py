#!/usr/bin/env python3
"""Evaluate dos_model on UNSW-NB15 with per-attack-category breakdown.
Saves results to results/generalization/phase1/dos_model/unsw_per_category.json
"""
import numpy as np
import pandas as pd
import xgboost as xgb
import pickle
import json
import os
from pathlib import Path
from sklearn.model_selection import train_test_split

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
THRESHOLD = 0.90

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
    print('Loading UNSW-NB15 (all 4 files)...')
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
    cats = np.array(df_f['attack_cat'].tolist(), dtype=object)

    print(f'Total samples: {len(y):,}  attack: {y.sum():,}  benign: {(y==0).sum():,}')

    # Same split as prepare_dataset.py
    idx = np.arange(len(y))
    idx_tr, idx_te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)

    with open(BASE / 'models' / 'scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    X_te_s  = scaler.transform(X[idx_te])
    y_te    = y[idx_te]
    cats_te = cats[idx_te]

    model = xgb.XGBClassifier()
    model.load_model(str(BASE / 'models' / 'dos_model.json'))
    print(f'Model loaded: {len(model.get_booster().get_dump())} trees')

    proba = model.predict_proba(X_te_s)[:, 1]
    yp    = (proba >= THRESHOLD).astype(int)

    # Overall
    overall = metrics(y_te, yp)
    print()
    print(f'=== dos_model UNSW-NB15 (threshold={THRESHOLD}) ===')
    print(f'TP={overall["tp"]:,}  FP={overall["fp"]:,}  FN={overall["fn"]:,}  '
          f'Rec={overall["recall"]:.4f}  Prec={overall["precision"]:.4f}  '
          f'F1={overall["f1"]:.4f}  FPR={overall["fpr"]:.6f}')

    # Per-category
    print()
    hdr = f'{"Category":<18} {"Total":>8} {"Attacks":>8} {"TP":>7} {"FN":>7} {"FP":>7} {"Recall":>8}'
    print(hdr)
    print('-' * len(hdr))
    per_cat = {}
    for cat in sorted(set(cats_te), key=str):
        mask = cats_te == cat
        yt_c = y_te[mask]; yp_c = yp[mask]
        m = metrics(yt_c, yp_c)
        per_cat[cat] = m
        per_cat[cat]['total'] = int(mask.sum())
        per_cat[cat]['n_attacks'] = int(yt_c.sum())
        print(f'{cat:<18} {mask.sum():>8,} {yt_c.sum():>8,} {m["tp"]:>7,} '
              f'{m["fn"]:>7,} {m["fp"]:>7,} {m["recall"]:>8.4f}')

    # Save
    out_dir = BASE / 'results' / 'generalization' / 'phase1' / 'dos_model'
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        'model': 'dos_model.json',
        'dataset': 'UNSW-NB15 (all 4 files, 20% test split, same as X_test.npy)',
        'threshold': THRESHOLD,
        'n_test': int(len(y_te)),
        'overall': overall,
        'per_category': per_cat,
    }
    out_path = out_dir / 'unsw_per_category.json'
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'\nSaved: {out_path}')


if __name__ == '__main__':
    main()
