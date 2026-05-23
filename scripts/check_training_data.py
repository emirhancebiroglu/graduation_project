"""Check bot training data quality: how many flows per window for bot vs benign."""
import pandas as pd
import numpy as np
from collections import defaultdict

WINDOW_SEC = 300

cicids_dir = '/home/emirhan/bitirme/data/raw/cicids2017'

# Friday Bot
fri = f'{cicids_dir}/Friday-WorkingHours-Morning.pcap_ISCX.csv'
print("=== Friday Bot flows ===")
df = pd.read_csv(fri, low_memory=False, encoding='cp1252')
lc = [c for c in df.columns if 'label' in c.lower()][0]

bot_srcs = ['192.168.10.5','192.168.10.8','192.168.10.9',
            '192.168.10.14','192.168.10.15','192.168.10.12','192.168.10.17']

for src in bot_srcs:
    flows = df[(df[lc].str.strip() == 'Bot') & (df[' Source IP'].str.strip() == src)]
    print(f'  {src}: {len(flows)} Bot-labeled flows')

print()

# Also check how many total flows these IPs have (including non-Bot)
print("=== All flows from bot IPs (including BENIGN) ===")
for src in bot_srcs:
    all_flows = df[df[' Source IP'].str.strip() == src]
    bot_flows = all_flows[all_flows[lc].str.strip() == 'Bot']
    print(f'  {src}: {len(all_flows)} total, {len(bot_flows)} Bot-labeled')
    if len(all_flows) > 0:
        timestamps = pd.to_datetime(all_flows[' Timestamp']).values.astype(np.int64) / 1e9
        first_win = int(timestamps.min() / WINDOW_SEC) * WINDOW_SEC
        last_win = int(timestamps.max() / WINDOW_SEC) * WINDOW_SEC
        n_windows = (last_win - first_win) // WINDOW_SEC + 1
        flows_per_win = defaultdict(list)
        for ts, row in zip(timestamps, all_flows.iterrows()):
            win = int(ts / WINDOW_SEC) * WINDOW_SEC
            flows_per_win[win].append(1)
        print(f'  Windows: {len(flows_per_win)}, avg flows/win: {np.mean([len(v) for v in flows_per_win.values()]):.1f}')
        bot_per_win = defaultdict(list)
        for ts, row in zip(timestamps, all_flows.iterrows()):
            if row[1][lc].strip() == 'Bot':
                win = int(ts / WINDOW_SEC) * WINDOW_SEC
                bot_per_win[win].append(1)
        print(f'  Bot-labeled windows: {len(bot_per_win)}, avg bot-flows/win: {np.mean([len(v) for v in bot_per_win.values()]):.1f}')

print()
print("=== BENIGN comparison (first 5 IPs from Monday) ===")
mon = f'{cicids_dir}/Monday-WorkingHours.pcap_ISCX.csv'
mon_df = pd.read_csv(mon, low_memory=False, encoding='cp1252')
benign = mon_df[mon_df[lc].str.strip() == 'BENIGN']
benign_srcs = benign[' Source IP'].unique()[:5]
for src in benign_srcs:
    flows = benign[benign[' Source IP'] == src]
    timestamps = pd.to_datetime(flows[' Timestamp']).values.astype(np.int64) / 1e9
    first_win = int(timestamps.min() / WINDOW_SEC) * WINDOW_SEC
    last_win = int(timestamps.max() / WINDOW_SEC) * WINDOW_SEC
    flows_per_win = defaultdict(list)
    for ts in timestamps:
        win = int(ts / WINDOW_SEC) * WINDOW_SEC
        flows_per_win[win].append(1)
    fpu = [len(v) for v in flows_per_win.values()]
    print(f'  {src}: {len(flows)} flows, {len(flows_per_win)} windows, avg={np.mean(fpu):.1f}, max={max(fpu)}')
