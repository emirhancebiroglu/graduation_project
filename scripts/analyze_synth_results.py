#!/usr/bin/env python3
"""Analyze synthetic bruteforce test results."""
import os, re

log_dir = '/tmp/synth_bruteforce_test'
print(f"{'Tool':<20} {'Alert':<8} {'MaxScore':<10} {'MaxSyns':<8} {'MaxRSTah':<10} {'Status':<12}")
print("-"*70)

results = []
for f in sorted(os.listdir(log_dir)):
    log_path = os.path.join(log_dir, f, 'snort_output.log')
    if not os.path.exists(log_path):
        continue
    rst_ah_vals, score_vals, syn_vals = [], [], []
    with open(log_path) as lf:
        for line in lf:
            m = re.search(r'score=([\d.]+)', line)
            if m: score_vals.append(float(m.group(1)))
            m2 = re.search(r'rst_ah=([\d.]+)', line)
            if m2: rst_ah_vals.append(float(m2.group(1)))
            m3 = re.search(r'syns=(\d+)', line)
            if m3: syn_vals.append(int(m3.group(1)))
    
    max_score = max(score_vals) if score_vals else 0
    max_rst = max(rst_ah_vals) if rst_ah_vals else 0
    max_syn = max(syn_vals) if syn_vals else 0
    alert_csv = os.path.join(log_dir, f, 'alert_csv.txt')
    alert_count = sum(1 for _ in open(alert_csv)) if os.path.exists(alert_csv) else 0
    status = 'DETECTED' if alert_count > 0 else 'MISSED'
    results.append((f, alert_count, max_score, max_syn, max_rst, status))

for r in results:
    print(f"{r[0]:<20} {r[1]:<8} {r[2]:<10.4f} {r[3]:<8} {r[4]:<10.4f} {r[5]:<12}")

detected = sum(1 for r in results if r[5] == 'DETECTED')
total = len(results)
print(f"\nDetection rate: {detected}/{total} = {detected/total*100:.0f}%")
print(f"\nMissed tools (all slow-rate <7/min):")
for r in results:
    if r[5] == 'MISSED':
        print(f"  {r[0]}: max_score={r[2]:.4f}, max_syns={r[3]}/60s window")
print(f"\nRecommended fix: lower threshold or add 600s slow window")
