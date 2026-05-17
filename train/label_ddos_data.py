#!/usr/bin/env python3
"""
Label ddos_train_data.txt using CICIDS2017 Friday CSV ground truth.
Label=1 for windows where the destination IP is being DDoSed.
"""
import numpy as np, pandas as pd, socket, struct

# Load dump
data = np.loadtxt('/tmp/ddos_train_data.txt', comments='#')
features = data[:, 1:8].astype(np.float64)  # 7 features
scores = data[:, 8]  # score
keys = data[:, 9].astype(np.uint64)  # (dst_ip << 32) | dst_port

# Extract dst IP from key (upper 32 bits of uint64)
def key_to_ip(key):
    ip_raw = int(key) >> 32
    return f'{(ip_raw>>24)&0xFF}.{(ip_raw>>16)&0xFF}.{(ip_raw>>8)&0xFF}.{ip_raw&0xFF}'
def key_to_port(key):
    return int(key) & 0xFFFF

# Find DDoS victim IPs from Friday CSV
csv_dir = '/home/emirhan/bitirme/data/raw/cicids2017/'
friday_csv = csv_dir + 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
df = pd.read_csv(friday_csv, low_memory=False, on_bad_lines='skip', encoding='utf-8', encoding_errors='replace')
df.columns = df.columns.str.strip()
df['Label'] = df['Label'].str.strip()

ddos = df[df['Label'].str.contains('DDoS', na=False)]
src_col = ' Source IP' if ' Source IP' in ddos.columns else 'Source IP'
dst_col = ' Destination IP' if ' Destination IP' in ddos.columns else 'Destination IP'

victim_ips = set(ddos[dst_col].unique())
print(f'DDoS victim IPs found: {len(victim_ips)}')
for ip in list(victim_ips)[:5]:
    print(f'  {ip}')

# Also check which IPs received DDoS flows (attacker sends to victim)
print(f'Total DDoS flows in CSV: {len(ddos)}')
print(f'DDoS source IPs: {ddos[src_col].nunique()}')
print(f'DDoS dest IPs: {ddos[dst_col].nunique()}')

# Label: 1 if dst_ip:port matches a known DDoS victim service
y = np.zeros(len(data), dtype=int)
matched = 0
for i in range(len(data)):
    ip_str = key_to_ip(keys[i])
    port = key_to_port(keys[i])
    # DDoS to port 80 on the victim is the LOIC target
    if ip_str in victim_ips:
        y[i] = 1
        matched += 1

print(f'\nTotal rows: {len(data)}')
print(f'Labeled DDoS: {y.sum()}')
print(f'Labeled benign: {(1-y).sum()}')
print(f'Matched victim IPs: {matched}')

if y.sum() < 5:
    print('\nWARNING: Very few DDoS labels. Using heuristic labeling instead.')
    print('Labeling all Friday windows with high pkt_count and low unique_src as DDoS.')
    # Heuristic: high total_pkts + low unique_src ratio = likely DDoS (single-source LOIC)
    total = features[:, 0]
    src_ratio = features[:, 5]
    for i in range(len(data)):
        if total[i] > 100 and src_ratio[i] < 0.3:
            y[i] = 1
    print(f'After heuristic: DDoS={y.sum()}, benign={(1-y).sum()}')

# Save labeled data
np.save('/tmp/ddos_y.npy', y)
np.save('/tmp/ddos_X.npy', features)
print('\nSaved to /tmp/ddos_X.npy, /tmp/ddos_y.npy')
