#!/usr/bin/env python3
"""Analyze UNSW per-category feature distributions vs benign.
Goal: understand why Exploits/Fuzzers/Shellcode/Worms have low recall.
"""
import numpy as np
import pandas as pd
import xgboost as xgb
import pickle
from sklearn.model_selection import train_test_split
from pathlib import Path

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

def main():
    print('Loading UNSW-NB15...')
    dfs = []
    for i in [1,2,3,4]:
        df = pd.read_csv(BASE / 'data' / 'unsw' / f'UNSW-NB15_{i}.csv',
                         header=None, names=UNSW_COLS, low_memory=False)
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

    idx = np.arange(len(y))
    idx_tr, idx_te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)

    with open(BASE / 'models' / 'scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    X_te_s  = scaler.transform(X[idx_te])
    y_te    = y[idx_te]
    cats_te = cats[idx_te]

    model = xgb.XGBClassifier()
    model.load_model(str(BASE / 'models' / 'dos_model.json'))
    proba = model.predict_proba(X_te_s)[:, 1]

    # Per-category score distribution
    print()
    print('Score distribution per category (attack flows only):')
    print(f'{"Category":<18} {"N":>7}  {"p10":>6}  {"p25":>6}  {"p50":>6}  {"p75":>6}  {"p90":>6}  {"mean":>6}  {">=0.9":>8}')
    print('-' * 82)

    all_cats = ['Generic','DoS','Exploits','Fuzzers','Reconnaissance','Shellcode','Worms','Analysis','Backdoor','Backdoors']
    for cat in all_cats:
        mask = (cats_te == cat) & (y_te == 1)
        if mask.sum() == 0:
            continue
        scores = proba[mask]
        n = len(scores)
        above = (scores >= 0.9).sum()
        p = np.percentile(scores, [10,25,50,75,90])
        print(f'{cat:<18} {n:>7,}  {p[0]:>6.3f}  {p[1]:>6.3f}  {p[2]:>6.3f}  {p[3]:>6.3f}  {p[4]:>6.3f}  {scores.mean():>6.3f}  {above:>6,}({100*above/n:>4.1f}%)')

    print()
    benign_mask = y_te == 0
    b_scores = proba[benign_mask]
    n = len(b_scores)
    above = (b_scores >= 0.9).sum()
    p = np.percentile(b_scores, [10,25,50,75,90])
    print(f'{"BENIGN":<18} {n:>7,}  {p[0]:>6.3f}  {p[1]:>6.3f}  {p[2]:>6.3f}  {p[3]:>6.3f}  {p[4]:>6.3f}  {b_scores.mean():>6.3f}  {above:>6,}({100*above/n:>4.1f}%)')

    # Check: what threshold would get Exploits Recall to 0.80?
    print()
    print('Threshold needed for Recall=0.80 per low-recall category:')
    for cat in ['Exploits','Fuzzers','Reconnaissance','Shellcode','Worms']:
        mask = (cats_te == cat) & (y_te == 1)
        if mask.sum() == 0:
            continue
        scores = sorted(proba[mask])
        n = len(scores)
        # 80% threshold = score at 20th percentile from bottom
        idx_80 = max(0, int(0.20 * n))
        t_80 = scores[idx_80]
        # What FPR does this cause?
        b_mask = y_te == 0
        fp = (proba[b_mask] >= t_80).sum()
        tn = (proba[b_mask] < t_80).sum()
        fpr = fp / (fp + tn)
        print(f'  {cat:<18}: threshold={t_80:.4f} → FPR={fpr:.6f} ({fp} benign FP)')

if __name__ == '__main__':
    main()
