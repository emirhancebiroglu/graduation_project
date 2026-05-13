#!/usr/bin/env python3
import pandas as pd
import numpy as np

df = pd.read_csv('/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', low_memory=False, on_bad_lines='skip')
df.columns = df.columns.str.strip()
scanner = df[df['Source IP'] == '172.16.0.1'].copy()

orig_ts = pd.to_datetime(scanner['Timestamp']).astype('int64')
new_ts = orig_ts.copy()
for ts_val in orig_ts.unique():
    mask = orig_ts == ts_val
    n = mask.sum()
    if n > 1:
        offset_ns = ((np.arange(n, dtype=np.float64) + 0.5) / n * 60 * 1e9).astype('int64')
        new_ts.loc[mask] = orig_ts.loc[mask] + offset_ns

epoch_s = new_ts.astype(np.float64) / 1e9
window_id = (epoch_s // 10).astype(int)
scanner['window_id'] = window_id

port_counts = scanner.groupby('window_id')['Destination Port'].nunique()
flow_counts = scanner.groupby('window_id').size()
stats = pd.DataFrame({'flows': flow_counts, 'unique_ports': port_counts})
print('Stats:')
print(stats.describe())
print()
print('Windows with unique_ports == flows:', (stats['unique_ports'] == stats['flows']).sum())
print('Total windows:', len(stats))
print('Windows with unique_ports < 3:', (stats['unique_ports'] < 3).sum())
print('Windows with unique_ports >= 5:', (stats['unique_ports'] >= 5).sum())
print()
print('Sample windows (first 15):')
for i, row in stats.head(15).iterrows():
    print(f'  window={i}: {row["flows"]} flows, {row["unique_ports"]} unique ports')
