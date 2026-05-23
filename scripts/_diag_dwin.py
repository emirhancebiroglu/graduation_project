#!/usr/bin/env python3
"""Diagnose dwin/swin distribution in CIC training data vs UNSW."""
import numpy as np
import pandas as pd
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

with open(BASE / 'models' / 'dos_fpr_opt_v3_scaler.json') as f:
    scaler = json.load(f)

print("=== V3 Scaler (trained on CIC) ===")
for i, name in enumerate(scaler['feature_names']):
    print(f"  [{i:2d}] {name:<15} median={scaler['median'][i]:.4f}  iqr={scaler['iqr'][i]:.4f}")

print("\n=== UNSW file 1 — raw value distributions ===")
df = pd.read_csv(BASE / 'data' / 'unsw' / 'UNSW-NB15_1.csv',
                 header=None, names=UNSW_COLS, low_memory=False)
if str(df.iloc[0, 0]).strip().lower() == 'srcip':
    df = df.iloc[1:]
df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)

for col in ['swin', 'dwin', 'sintpkt', 'dintpkt', 'smeansz', 'dmeansz']:
    v = pd.to_numeric(df[col], errors='coerce').dropna()
    print(f"  {col:<12} min={v.min():.2f}  p25={v.quantile(.25):.2f}  median={v.median():.2f}  "
          f"p75={v.quantile(.75):.2f}  max={v.max():.2f}")

print("\n=== log1p transform check for dwin ===")
print("  log1p indices:", scaler['log1p_indices'])
# dwin is index 8 → in log1p_indices → log1p applied
dwin_raw = pd.to_numeric(df['dwin'], errors='coerce').dropna()
print(f"  dwin raw median = {dwin_raw.median():.2f}")
print(f"  log1p(dwin) median = {np.log1p(dwin_raw).median():.4f}")
print(f"  v3 scaler dwin median = {scaler['median'][8]:.4f}  (should match log1p(CIC dwin median))")
print(f"  v3 scaler dwin iqr = {scaler['iqr'][8]:.4f}")

# If dwin median in UNSW is 65535:
# log1p(65535) = 11.09
# scaled = (11.09 - 10.27) / 0.095 = 8.6 (still extreme if IQR is small)
print(f"\n  log1p(109) = {np.log1p(109):.4f}")
print(f"  scaled_dwin = (log1p(109) - {scaler['median'][8]:.4f}) / {scaler['iqr'][8]:.4f} = "
      f"{(np.log1p(109) - scaler['median'][8]) / scaler['iqr'][8]:.4f}")

# What does CIC dwin look like?
print("\n=== CIC training data dwin (from scaler median/IQR) ===")
print(f"  CIC dwin: log1p median = {scaler['median'][8]:.4f} → raw median = {np.expm1(scaler['median'][8]):.2f}")
print(f"  CIC dwin: log1p IQR = {scaler['iqr'][8]:.4f}")
print(f"  CIC swin: log1p median = {scaler['median'][7]:.4f} → raw median = {np.expm1(scaler['median'][7]):.2f}")
