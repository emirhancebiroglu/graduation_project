import numpy as np
from collections import defaultdict

# IP to label mapping
BOT_IPS = {3232238085: '.5', 3232238088: '.8', 3232238089: '.9',
           3232238092: '.12', 3232238094: '.14', 3232238095: '.15', 
           3232238097: '.17'}  # 192.168.10.x
FP_IPS = {3232238096: '.16', 3232238099: '.19', 3232238105: '.25',
          3232238131: '.51', 2886729729: '.1'}  # .1 = 172.16.0.1

lines = open('/tmp/botcl_train_data.txt').readlines()

by_label = defaultdict(list)
for line in lines[1:]:
    parts = line.strip().split()
    if len(parts) < 20: continue
    src_ip = int(parts[19])
    vals = [float(x) for x in parts[1:18]]  # skip lb, score, src_ip
    score = float(parts[18])
    if src_ip in BOT_IPS:
        by_label['bot'].append(vals + [score])
    elif src_ip in FP_IPS:
        by_label['fp'].append(vals + [score])

for label in ['bot', 'fp']:
    arr = np.array(by_label[label])
    print(f'\n=== {label.upper()} ({len(arr)} samples) ===')
    print(f'  avg score: {arr[:, -1].mean():.4f}')
    names = ['syn_cnt','dst_ips','dst_ports','iat_cv','entropy','port_ratio','rate',
             'ip_conc','ip_ratio','ip_entropy','iat_q90','time_density','port_ip_ratio',
             'handshake','inc_ratio','data_density','rst_rate']
    for i, n in enumerate(names):
        print(f'  {n:15s}: mean={arr[:,i].mean():.4f} std={arr[:,i].std():.4f}')
