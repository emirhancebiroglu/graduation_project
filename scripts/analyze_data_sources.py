import pandas as pd
df = pd.read_csv('/home/emirhan/bitirme/data/raw/ctu13_binetflow/ctu13_botnet_only.csv', nrows=50000)
labels = df['Label'].unique()
print('Unique labels:', len(labels))
for l in sorted(labels)[:15]:
    print(' ', l)

bot_ips = set()
for _, r in df.iterrows():
    if 'From-Botnet' in str(r['Label']):
        bot_ips.add(r['SrcAddr'])
print(f'\nBot src IPs (first 50000 rows): {len(bot_ips)}')
print('Sample bot IPs:', list(bot_ips)[:5])

# Also count by bot source
from collections import Counter
src_counts = Counter()
for _, r in df.iterrows():
    if 'From-Botnet' in str(r['Label']):
        src_counts[r['SrcAddr']] += 1
print('\nTop bot src IPs by flow count:')
for ip, cnt in src_counts.most_common(5):
    print(f'  {ip}: {cnt}')

# CICIDS Friday analysis
print('\n=== CICIDS Friday Analysis ===')
fri = pd.read_csv('/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv', low_memory=False, encoding='cp1252', nrows=200000)
lc = [c for c in fri.columns if 'label' in c.lower()][0]
bot_srcs = ['192.168.10.5','192.168.10.8','192.168.10.9','192.168.10.14','192.168.10.15','192.168.10.12','192.168.10.17']
for src in bot_srcs:
    flows = fri[fri[' Source IP'].str.strip() == src]
    bot = flows[flows[lc].str.strip() == 'Bot']
    print(f'{src}: {len(flows)} flows, {len(bot)} Bot')
