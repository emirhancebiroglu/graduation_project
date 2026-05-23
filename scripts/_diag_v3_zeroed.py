#!/usr/bin/env python3
"""Score distribution check with swin/dwin/fin_cnt/ack_cnt/syn_cnt all zeroed."""
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

# Zero swin, dwin
x[:, 7] = 0.0
x[:, 8] = 0.0

X = np.column_stack([
    x,
    sbytes / np.maximum(spkts, 1),   # fwd_pkt_mean
    dbytes / np.maximum(dpkts, 1),   # bwd_pkt_mean
    np.zeros(len(x)),                 # fin_cnt
    np.zeros(len(x)),                 # ack_cnt
    np.zeros(len(x)),                 # syn_cnt
    dintpkt.copy()                    # bwd_iat
])

y = df['label'].values.astype(int)

log_idx = scaler['log1p_indices']
X2 = X.copy()
X2[:, log_idx] = np.log1p(X2[:, log_idx])
median = np.array(scaler['median'])
iqr    = np.array(scaler['iqr'])
iqr    = np.where(iqr == 0, 1.0, iqr)
Xs = (X2 - median) / iqr

print("Scaled feature means (attack):")
for i, name in enumerate(scaler['feature_names']):
    print(f"  [{i:2d}] {name:<15} = {Xs[y==1, i].mean():.4f}")

proba = model.predict_proba(Xs)[:, 1]
print("\nScore percentiles ALL:    ", np.percentile(proba, [0,10,25,50,75,90,95,99,100]).round(6))
print("Score percentiles ATTACK: ", np.percentile(proba[y == 1], [0,10,25,50,75,90,95,99,100]).round(6))
print("Score percentiles BENIGN: ", np.percentile(proba[y == 0], [0,10,25,50,75,90,95,99,100]).round(6))
print("\nAttacks score>=0.90:", int((proba[y == 1] >= 0.90).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.50:", int((proba[y == 1] >= 0.50).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.10:", int((proba[y == 1] >= 0.10).sum()), "/", int((y == 1).sum()))
print("Attacks score>=0.01:", int((proba[y == 1] >= 0.01).sum()), "/", int((y == 1).sum()))

# Feature importance check
print("\nFeature importances (gain):")
booster = model.get_booster()
scores = booster.get_score(importance_type='gain')
for name, imp in sorted(scores.items(), key=lambda x: -x[1])[:10]:
    print(f"  {name}: {imp:.2f}")
