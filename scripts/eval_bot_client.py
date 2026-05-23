#!/usr/bin/env python3
"""eval_bot_client.py — Bot Client Inspector Evaluation (Friday)

Per-src-IP evaluation: match alerted internal IPs against known bot clients.
"""

import pandas as pd
import argparse
import re
from pathlib import Path

CICIDS_BOT_CSV = '/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
SNORT_LOG = '/home/emirhan/bitirme/results/bot_client/Friday-WorkingHours/snort_output.log'

def get_bot_client_ips(path):
    df = pd.read_csv(path, low_memory=False, encoding='cp1252')
    lc = [c for c in df.columns if 'label' in c.lower()][0]
    bot = df[df[lc].astype(str).str.strip() == 'Bot']
    srcs = set(bot[' Source IP'].unique())
    internal = {ip for ip in srcs if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')}
    print(f'CICIDS Bot src IPs: {len(srcs)} total, {len(internal)} internal')
    for ip in sorted(internal):
        count = (bot[' Source IP'] == ip).sum()
        print(f'  {ip}: {count} Bot flows')
    return internal

def parse_alerts_from_log(path):
    pat = re.compile(r'\[botcl\] ALERT: (\d+\.\d+\.\d+\.\d+) score=([\d.]+)')
    alerted = {}
    with open(path) as f:
        for line in f:
            m = pat.search(line)
            if m:
                ip = m.group(1)
                score = float(m.group(2))
                if ip not in alerted or score > alerted[ip]:
                    alerted[ip] = score
    print(f'\nSnort alerts: {len(alerted)} unique IPs')
    return alerted

def main():
    bot_ips = get_bot_client_ips(CICIDS_BOT_CSV)
    alerted = parse_alerts_from_log(SNORT_LOG)

    tp = {ip: sc for ip, sc in alerted.items() if ip in bot_ips}
    fp = {ip: sc for ip, sc in alerted.items() if ip not in bot_ips}
    fn = bot_ips - set(alerted.keys())

    print('\n' + '='*60)
    print('  Bot Client Evaluation (Friday)')
    print('='*60)
    print(f'  Bot client IPs (ground truth): {len(bot_ips)}')
    print(f'  Alerted IPs:                   {len(alerted)}')
    print(f'')
    print(f'  TP (detected bots):  {len(tp)}')
    print(f'  FP (false alarm):    {len(fp)}')
    print(f'  FN (missed bots):    {len(fn)}')
    print(f'')
    prec = len(tp) / len(alerted) if alerted else 0
    rec = len(tp) / len(bot_ips) if bot_ips else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
    print(f'  Precision: {prec:.4f}')
    print(f'  Recall:    {rec:.4f}')
    print(f'  F1:        {f1:.4f}')
    print(f'')
    print(f'  TP IPs (correctly detected):')
    for ip in sorted(tp):
        print(f'    {ip}: score={tp[ip]:.4f}')
    print(f'')
    print(f'  FP IPs (false alarms):')
    for ip in sorted(fp):
        print(f'    {ip}: score={fp[ip]:.4f}')
    print(f'')
    print(f'  FN IPs (missed bots):')
    for ip in sorted(fn):
        print(f'    {ip}')
    print('='*60)

if __name__ == '__main__':
    main()
