#!/usr/bin/env python3
import numpy as np, pandas as pd
data = np.loadtxt('/tmp/xgb_train_v2.txt', comments='#')
for i in range(3):
    si = data[i,17]; di = data[i,18]; sp = int(data[i,19]); dp = int(data[i,20])
    si_s = f'{(int(si)>>24)&0xFF}.{(int(si)>>16)&0xFF}.{(int(si)>>8)&0xFF}.{int(si)&0xFF}'
    di_s = f'{(int(di)>>24)&0xFF}.{(int(di)>>16)&0xFF}.{(int(di)>>8)&0xFF}.{int(di)&0xFF}'
    print(f'dump: si={si_s} di={di_s} sp={sp} dp={dp}')

csv = pd.read_csv('/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv',
    low_memory=False, on_bad_lines='skip', nrows=3)
csv.columns = csv.columns.str.strip()
src_col = [c for c in csv.columns if 'Source IP' in c][0]
dst_col = [c for c in csv.columns if 'Destination IP' in c][0]
sp_col = [c for c in csv.columns if 'Source Port' in c and 'Destination' not in c][0]
dp_col = [c for c in csv.columns if 'Destination Port' in c][0]
for _, r in csv.iterrows():
    print(f'csv:  si={r[src_col]} di={r[dst_col]} sp={r[sp_col]} dp={r[dp_col]} label={r["Label"]}')
