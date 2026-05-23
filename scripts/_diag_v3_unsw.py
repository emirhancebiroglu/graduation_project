#!/usr/bin/env python3
"""Diagnose v3 model score distribution on UNSW-NB15_1.csv"""
import numpy as np
import pandas as pd
import xgboost as xgb
import json
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
BASE_COLS = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']

with open(BASE / 'models' / 'dos_fpr_opt_v3_scaler.json') as f:
    scaler = json.load(f)

model = xgb.XGBClassifier()
model.load_model(str(BASE / 'models' / 'dos_fpr_opt_v3.json'))

df = pd.read_csv(BASE / 'data' / 'unsw' / 'UNSW-NB15_1.csv',
                 header=None, names=UNSW_COLS, low_memory=False)
if str(df.iloc[0, 0]).strip().lower() == 'srcip':
    df = df.iloc[1:]
df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
df[BASE_COLS] = df[BASE_COLS].apply(pd.to_numeric, errors='coerce')
df.dropna(subset=BASE_COLS + ['label'], inplace=True)

x = df[BASE_COLS].values.astype(np.float64)
spkts   = x[:, 1]; dpkts = x[:, 2]
sbytes  = x[:, 3]; dbytes = x[:, 4]
dintpkt = x[:, 10]

X = np.column_stack([
    x,
    sbytes / np.maximum(spkts, 1),
    dbytes / np.maximum(dpkts, 1),
    np.zeros(len(x)),
    np.zeros(len(x)),
    np.zeros(len(x)),
    dintpkt.copy()
])

y = df['label'].values.astype(int)

# Raw feature stats for attacks
X_att = X[y == 1]
print("Attack count:", len(X_att))
print("Feature names:", scaler['feature_names'])
print("Raw attack means:", np.round(X_att.mean(axis=0), 4))
print("Scaler median:   ", np.round(scaler['median'], 4))

# Apply scaling
log_idx = scaler['log1p_indices']
X2 = X.copy()
X2[:, log_idx] = np.log1p(X2[:, log_idx])
median = np.array(scaler['median'])
iqr    = np.array(scaler['iqr'])
iqr    = np.where(iqr == 0, 1.0, iqr)
Xs = (X2 - median) / iqr

print("\nScaled attack means:", np.round(Xs[y == 1].mean(axis=0), 4))

proba = model.predict_proba(Xs)[:, 1]
print("\nScore percentiles ALL:    ", np.percentile(proba, [0,10,25,50,75,90,95,99,100]).round(4))
print("Score percentiles ATTACK: ", np.percentile(proba[y == 1], [0,10,25,50,75,90,95,99,100]).round(4))
print("Score percentiles BENIGN: ", np.percentile(proba[y == 0], [0,10,25,50,75,90,95,99,100]).round(4))
print("\nAttacks score>=0.90:", int((proba[y == 1] >= 0.90).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.50:", int((proba[y == 1] >= 0.50).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.30:", int((proba[y == 1] >= 0.30).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.10:", int((proba[y == 1] >= 0.10).sum()), "/", int((y == 1).sum()))
