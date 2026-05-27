#!/usr/bin/env python3
"""eval_windows_fast.py — Window-level recall from Snort logs (no PCAP parsing)

Uses the [model] ALERT: IP score=X lines in snort_output.log to count
how many windows per attacker IP were detected. Snort fires an alert per
window (after 30-min dedup), so alert count ≈ window count detected.

For bruteforce and bot client, the total windows is estimated from
the ground truth: SYN packets / min_syns threshold.
"""
import re, json
from pathlib import Path
from collections import defaultdict

BASE = Path('/home/emirhan/bitirme')

MODELS = {
    'bruteforce': {
        'gid': 307,
        'alert_pattern': r'\[bfc\] ALERT: ([\d.]+)',
        'eval_file': BASE / 'results/bruteforce/eval_bruteforce.json',
        'attack_days': {'Tuesday': ['172.16.0.1']},
        'window_sec': 120,
        'min_syns': 3,
        'pcap': BASE / 'pcaps/Tuesday-WorkingHours.pcap',
        'log_dirs': {d: BASE / f'results/bruteforce/{d}' for d in ['Monday','Tuesday','Wednesday','Thursday','Friday']},
    },
}

def analyze_model(name, cfg):
    print(f"\n{'='*60}")
    print(f"  {name.upper()} — Window-Level Analysis")
    print(f"{'='*60}")
    print(f"  GID: {cfg['gid']}  Window: {cfg['window_sec']}s  min_syns: {cfg['min_syns']}")

    for day, attacker_ips in cfg['attack_days'].items():
        log_dir = cfg['log_dirs'].get(day)
        if not log_dir or not log_dir.exists():
            print(f"  {day}: No log directory")
            continue

        log_file = log_dir / 'snort_output.log'
        if not log_file.exists():
            print(f"  {day}: No snort_output.log")
            continue

        # Count per-IP alert lines (each line = one window detected)
        alerts = defaultdict(int)
        scores = defaultdict(list)
        with open(log_file) as f:
            for line in f:
                m = re.search(cfg['alert_pattern'], line)
                if m:
                    ip = m.group(1)
                    score_m = re.search(r'score=([\d.]+)', line)
                    score = float(score_m.group(1)) if score_m else 0
                    alerts[ip] += 1
                    scores[ip].append(score)

        print(f"\n  {day} — Alerts detected in snort_output.log:")

        for ip in attacker_ips:
            n = alerts.get(ip, 0)
            avg_score = sum(scores.get(ip, [0])) / max(len(scores.get(ip, [])), 1)
            print(f"    {ip}: {n} alert windows, avg score={avg_score:.4f}")

        # Non-attacker alerts (FPs)
        fp_ips = {ip for ip in alerts if ip not in attacker_ips}
        fp_total = sum(alerts[ip] for ip in fp_ips)
        if fp_ips:
            print(f"    FP IPs: {len(fp_ips)} unique, {fp_total} total alert windows")
            for ip in sorted(fp_ips)[:5]:
                print(f"      {ip}: {alerts[ip]} alerts")

    print(f"\n  Attack day window recall note:")
    print(f"  Alert count = window count (each alert = one window detected)")
    print(f"  IP-level recall is the authoritative metric for cross-flow models")

# BruteForce analysis
analyze_model('bruteforce', MODELS['bruteforce'])

# Bot client analysis
print(f"\n{'='*60}")
print(f"  BOT_CLIENT — Window-Level Analysis")
print(f"{'='*60}")
print(f"  GID: 306  Window: 300s  min_syns: 3")
BOT_IPS = ['192.168.10.5','192.168.10.8','192.168.10.9','192.168.10.12',
           '192.168.10.14','192.168.10.15','192.168.10.17']
log_file = BASE / 'results/bot_client/Friday/snort_output.log'

alert_counts = defaultdict(int)
inference_counts = defaultdict(int)
if log_file.exists():
    with open(log_file) as f:
        for line in f:
            # Count ALERT lines (detected windows)
            m = re.search(r'\[botcl\] ALERT: ([\d.]+) score=([\d.]+)', line)
            if m:
                alert_counts[m.group(1)] += 1
            # Count inference lines (total windows evaluated, suppressed or not)
            m2 = re.search(r'\[botcl\] ([\d.]+) syns=\d+.*score=([\d.]+)', line)
            if m2:
                inference_counts[m2.group(1)] += 1

print(f"\n  Friday — Bot IP window analysis:")
for ip in BOT_IPS:
    n_alert = alert_counts.get(ip, 0)
    n_inf = inference_counts.get(ip, 0)
    print(f"    {ip}: {n_alert} alert windows, {n_inf} total inference windows")

fp_ips = {ip for ip in alert_counts if ip not in BOT_IPS}
print(f"\n  FP IPs (alerted but not bot): {len(fp_ips)}")
for ip in sorted(fp_ips):
    print(f"    {ip}: {alert_counts[ip]} alerts")

# DDoS analysis
print(f"\n{'='*60}")
print(f"  DDOS_AGGREGATOR — Window-Level Analysis")
print(f"{'='*60}")
print(f"  GID: 304  Window: 60s  min_packets: 3")
ddos_log = BASE / 'results/ddos_aggregator/Friday-WorkingHours/snort_output.log'
if ddos_log.exists():
    with open(ddos_log) as f:
        ddos_alerts = [line for line in f if 'ALERT' in line and 'ddos_agg' in line]
    print(f"\n  Friday: {len(ddos_alerts)} DDoS alert windows targeting 192.168.10.50:80")
    if ddos_alerts:
        scores = [float(re.search(r'score=([\d.]+)', l).group(1)) for l in ddos_alerts if re.search(r'score=([\d.]+)', l)]
        avg_s = sum(scores) / len(scores) if scores else 0
        print(f"  Avg score: {avg_s:.4f}")

ddos_wed_log = BASE / 'results/ddos_aggregator/Wednesday-WorkingHours/snort_output.log'
if ddos_wed_log.exists():
    with open(ddos_wed_log) as f:
        ddos_alerts_wed = [line for line in f if 'ALERT' in line and 'ddos_agg' in line]
    print(f"  Wednesday: {len(ddos_alerts_wed)} DDoS alert windows targeting 192.168.10.50:80")

# Community comparison
print(f"\n{'='*60}")
print(f"  COMMUNITY RULES — IP-Level Attack Detection")
print(f"{'='*60}")
comm_dir = BASE / 'results/community'
known_ips = ['172.16.0.1','192.168.10.5','192.168.10.8','192.168.10.9',
             '192.168.10.12','192.168.10.14','192.168.10.15','192.168.10.17','192.168.10.50']
for day in ['Tuesday', 'Wednesday', 'Friday']:
    alert_file = comm_dir / day / 'alert_csv.txt'
    if not alert_file.exists():
        continue
    print(f"\n  {day}:")
    with open(alert_file) as f:
        lines = f.readlines()
    print(f"    Total alerts: {len(lines)}")
    total_alerts_for_ips = 0
    for ip in known_ips:
        count = sum(1 for l in lines if ip in l)
        if count > 0:
            total_alerts_for_ips += count
            print(f"    {ip}: {count} alerts")
    print(f"    Total for known IPs: {total_alerts_for_ips} / {len(lines)} total")
    print(f"    FPR estimate: {(len(lines) - total_alerts_for_ips) / len(lines) * 100:.2f}% (alert lines not matching known attack IPs)")
