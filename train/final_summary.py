#!/usr/bin/env python3
import json, os, subprocess
base = '/home/emirhan/bitirme/results/portscan'
print('='*70)
print('PORTSCAN INSPECTOR v1 - PRODUCTION FREEZE')
print('Threshold: 0.50 | 7-feature XGBoost + NULL/XMAS heuristic')
print('='*70)
print(f'{"Day":<10} {"Alerts":>7} {"Scanner":>8} {"Recall":>8} {"SYN Cov":>9} {"FPs":>5}')
print('-'*70)
for d in ['monday','tuesday','wednesday','thursday','friday']:
    path = os.path.join(base, f'metrics_{d}.json')
    with open(path) as f:
        m = json.load(f)
    w = m['window_level']
    s = m['scanner_ips']
    p = m['packet_coverage']
    fp = m['false_positives']
    total = w['total_scanner_windows']
    alerted = w['alerted_scanner_windows']
    recall = w['window_recall'] if total > 0 else 0
    syn_cov = p['syn_coverage'] if total > 0 else 0
    fpc = fp['total_non_scanner_alerts']
    name = d.capitalize()
    print(f'{name:<10} {alerted:>7} {total:>8} {recall:>7.1%} {syn_cov:>8.2%} {fpc:>5}')
print('-'*70)
print()
print('ATTACK PCAP DETECTION:')
for t in ['fin','null','xmas']:
    log = f'/home/emirhan/bitirme/results/portscan/attack_{t}/snort_output.log'
    r = subprocess.run(['grep','-c','ALERT',log], capture_output=True, text=True)
    c = r.stdout.strip() or '0'
    print(f'  {t}.pcap: {c} alerts')
print()
print('FROZEN FILES:')
print('  configs/snort_portscan.lua')
print('  configs/snort_combined.lua')
print('  results/portscan/metrics_*.json')
print('  docs/portscan/FINAL_RESULTS.md')
