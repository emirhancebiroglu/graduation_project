#!/usr/bin/env python3
"""
eval_botnet_c2.py — Botnet C2 Inspector Evaluation (Friday)

Two evaluation modes:
1. Per-IP: match alerted IPs against CICIDS Bot dst IPs (external only)
2. Threshold sweep: test all thresholds on Snort log scores
"""

import pandas as pd
import argparse
import logging
import re
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CICIDS_BOT_CSV = '/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
SNORT_LOG = '/home/emirhan/bitirme/results/botnet_c2/Friday-WorkingHours/snort_output2.log'

def is_internal(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    a = int(parts[0])
    b = int(parts[1])
    if a == 10:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 127:
        return True
    return False

def get_c2_server_ips(path):
    df = pd.read_csv(path, low_memory=False, encoding='cp1252')
    lc = [c for c in df.columns if 'label' in c.lower()][0]
    bot = df[df[lc].astype(str).str.strip() == 'Bot']
    all_dst = set(bot[' Destination IP'].unique())
    external = {ip for ip in all_dst if not is_internal(ip)}
    logging.info(f'CICIDS Bot dst IPs: {len(all_dst)} total, {len(external)} external (C2 servers)')
    return external

def parse_scores_from_log(path):
    scores = []
    pat = re.compile(r'\[botc2\] (\d+\.\d+\.\d+\.\d+) syns=\S+ srcs=\S+ iat_cv=\S+ ports=\S+ score=([\d.]+)')
    with open(path) as f:
        for line in f:
            m = pat.search(line)
            if m:
                dst_ip = m.group(1)
                score = float(m.group(2))
                scores.append((dst_ip, score))
    logging.info(f'Parsed {len(scores)} inference scores from log')
    return scores

def threshold_sweep(scores, c2_ips, thresholds=None):
    if thresholds is None:
        thresholds = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45,
                      0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]

    results = []
    for thr in thresholds:
        alerted = set()
        for ip, score in scores:
            if score >= thr:
                alerted.add(ip)
        tp = alerted & c2_ips
        fp = alerted - c2_ips
        fn = c2_ips - alerted
        precision = len(tp) / len(alerted) if alerted else 0
        recall = len(tp) / len(c2_ips) if c2_ips else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        results.append((thr, len(tp), len(fp), len(fn), precision, recall, f1, sorted(tp), sorted(fp), sorted(fn)))
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bot-csv', default=CICIDS_BOT_CSV)
    parser.add_argument('--snort-log', default=SNORT_LOG)
    parser.add_argument('--output', default='/home/emirhan/bitirme/results/botnet_c2/eval_summary.txt')
    args = parser.parse_args()

    c2_ips = get_c2_server_ips(args.bot_csv)
    scores = parse_scores_from_log(args.snort_log)
    results = threshold_sweep(scores, c2_ips)

    lines = []
    lines.append('='*80)
    lines.append('  Botnet C2 Threshold Sweep (Friday PCAP, external C2 IPs only)')
    lines.append('='*80)
    lines.append(f'  C2 server IPs (external): {sorted(c2_ips)}')
    lines.append(f'  Total inferences in log: {len(scores)}')
    lines.append(f'  Unique IPs tracked: {len(set(ip for ip,_ in scores))}')
    lines.append('')
    lines.append(f'  {"thr":<6} {"TP":<6} {"FP":<6} {"FN":<6} {"Prec":<8} {"Recall":<8} {"F1":<8}  FN IPs')
    lines.append(f'  {"-"*6} {"-"*6} {"-"*6} {"-"*6} {"-"*8} {"-"*8} {"-"*8}  {"-"*30}')

    best_f1 = 0.0
    best_row = None
    for thr, tp, fp, fn, prec, rec, f1, tp_ips, fp_ips, fn_ips in results:
        fn_str = ','.join(fn_ips) if fn_ips else '-'
        lines.append(f'  {thr:<6.2f} {tp:<6} {fp:<6} {fn:<6} {prec:<8.4f} {rec:<8.4f} {f1:<8.4f}  {fn_str}')
        if f1 > best_f1:
            best_f1 = f1
            best_row = (thr, tp, fp, fn, prec, rec, f1, tp_ips, fp_ips, fn_ips)

    lines.append('')
    lines.append('='*80)
    if best_row:
        thr, tp, fp, fn, prec, rec, f1, tp_ips, fp_ips, fn_ips = best_row
        lines.append(f'  BEST: thr={thr:.2f} TP={tp} FP={fp} FN={fn} Prec={prec:.4f} Rec={rec:.4f} F1={f1:.4f}')
        lines.append(f'  TP IPs: {sorted(tp_ips)}')
        if len(fp_ips) <= 20:
            lines.append(f'  FP IPs: {sorted(fp_ips)}')
        else:
            lines.append(f'  FP IPs ({len(fp_ips)} total): {sorted(fp_ips)[:10]}...')
        lines.append(f'  FN IPs: {sorted(fn_ips)}')
    lines.append('='*80)

    output = '\n'.join(lines)
    print(output)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        f.write(output + '\n')
    logging.info(f'Results saved: {args.output}')

if __name__ == '__main__':
    main()
