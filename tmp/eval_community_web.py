#!/usr/bin/env python3
"""Evaluate community rules against Thursday web attacks."""
import pandas as pd
import re
from collections import defaultdict

CICIDS_CSV = "/home/emirhan/bitirme/data/raw/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
ALERT_CSV = "/home/emirhan/bitirme/results/community_web/alert_csv.txt"
SNORT_LOG = "/home/emirhan/bitirme/results/community_web/snort.log"

# 1. Get attack flows from CICIDS
df = pd.read_csv(CICIDS_CSV, low_memory=False, encoding='cp1252')
lc = [c for c in df.columns if 'label' in c.lower()][0]
labels = df[lc].astype(str).str.strip()

attack_data = {}
for name, label_val in [('XSS', 'Web Attack \u2013 XSS'), ('SQLi', 'Web Attack \u2013 Sql Injection'), ('BruteForce', 'Web Attack \u2013 Brute Force')]:
    mask = labels == label_val
    attack_data[name] = df[mask]
    print(f'{name}: {mask.sum()} flows')

print("=== Ground Truth ===")
for name, subset in attack_data.items():
    print(f"  {name}: {len(subset)} flows, src IPs: {subset[' Source IP'].unique()}")

# 2. Extract attack IPs
attack_src_ips = set()
for name, subset in attack_data.items():
    for ip in subset[' Source IP'].unique():
        attack_src_ips.add(ip)
print(f"\n  Attack src IPs: {attack_src_ips}")

# 3. Parse alert CSV
alert_pattern = re.compile(r'^[^,]+,\s*\d+,\s*\w+,\s*\w+,\s*\d+,\s*\w+,\s*([\d.]+:\d+),\s*([\d.]+:\d+),')
sids = defaultdict(int)
src_ip_alerts = defaultdict(set)
dst_ip_alerts = defaultdict(set)

with open(ALERT_CSV) as f:
    for line in f:
        parts = line.strip().split(',')
        if len(parts) < 9:
            continue
        src_field = parts[6].strip()
        dst_field = parts[7].strip()
        gid_field = parts[8].strip()
        src_ip = src_field.split(':')[0]
        dst_ip = dst_field.split(':')[0]
        if src_ip in attack_src_ips:
            src_ip_alerts[src_ip].add(gid_field)
        # Also check dst IPs

print("\n=== Community Rule Alerts for Attack IPs ===")
for ip in sorted(attack_src_ips):
    if ip in src_ip_alerts:
        print(f"  {ip}: {len(src_ip_alerts[ip])} unique rule SIDs triggered")
        # Show top SIDs
        # (we can't count per SID easily from this format without more parsing)
    else:
        print(f"  {ip}: NO alerts from community rules")

# 4. Check Snort log for web attack detection
print("\n=== Snort Log Check ===")
with open(SNORT_LOG) as f:
    for line in f:
        if 'WEB' in line or 'SQL' in line.upper() or 'XSS' in line.upper():
            if any(ip in line for ip in attack_src_ips):
                print(f"  {line.strip()[:120]}...")

print("\n=== Summary ===")
print(f"  Total alerts: {sum(1 for _ in open(ALERT_CSV))}")
print(f"  Attack src IP alerts matched: {sum(1 for v in src_ip_alerts.values() if v)}")
