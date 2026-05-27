#!/usr/bin/env python3
"""eval_bf_windows.py — BruteForce window-level recall evaluation

Parses Tuesday PCAP for SYN packets from 172.16.0.1 (bruteforce attacker),
groups into 120s windows (bruteforce window), counts how many were detected
in Snort alert output.

Usage:
  python3 scripts/eval_bf_windows.py \
    --pcap pcaps/Tuesday-WorkingHours.pcap \
    --alert-csv results/bruteforce/Tuesday/alert_csv.txt \
    --attacker-ip 172.16.0.1 \
    --window 120
"""
import argparse, sys
from pathlib import Path
from collections import defaultdict
import pandas as pd
from scapy.all import PcapReader, IP, TCP

ATTACKER_IP_DEFAULT = '172.16.0.1'
WINDOW_SEC = 120

def parse_syns(pcap_path):
    for pkt in PcapReader(str(pcap_path)):
        if IP in pkt and TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02 and not (flags & 0x10):
                yield float(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--alert-csv', required=True)
    parser.add_argument('--attacker-ip', default=ATTACKER_IP_DEFAULT)
    parser.add_argument('--window', type=int, default=WINDOW_SEC)
    parser.add_argument('--min-syns', type=int, default=3, help='min_syns threshold')
    args = parser.parse_args()

    print(f"PCAP:        {Path(args.pcap).name}")
    print(f"Alert CSV:   {args.alert_csv}")
    print(f"Attacker IP: {args.attacker_ip}")
    print(f"Window:      {args.window}s  min_syns={args.min_syns}")

    # Parse all SYNs from PCAP
    print("Parsing SYNs from PCAP...")
    packets = list(parse_syns(args.pcap))
    print(f"  Total SYNs: {len(packets)}")

    df = pd.DataFrame(packets, columns=['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['window_id'] = (df['ts'] // args.window).astype(int)

    windows = defaultdict(list)
    for (src_ip, wid), group in df.groupby(['src_ip', 'window_id']):
        windows[(src_ip, wid)] = len(group)

    attacker_windows = {k: v for k, v in windows.items() if k[0] == args.attacker_ip}
    attacker_windows_above_min = {k: v for k, v in attacker_windows.items() if v >= args.min_syns}
    benign_windows = {k: v for k, v in windows.items() if k[0] != args.attacker_ip and v >= args.min_syns}

    print(f"\nAttacker ({args.attacker_ip}) windows total:       {len(attacker_windows)}")
    print(f"Attacker windows >= min_syns={args.min_syns}: {len(attacker_windows_above_min)}")
    print(f"Benign windows >= min_syns={args.min_syns}:  {len(benign_windows)}")

    # Parse alerts
    alerts = []
    alert_path = Path(args.alert_csv)
    if alert_path.exists():
        with open(alert_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 7:
                    alerts.append(parts)

    print(f"\nTotal alerts: {len(alerts)}")

    # Count alerts per src IP
    alert_counts = defaultdict(int)
    for parts in alerts:
        try:
            src_ip = parts[3].strip()
            alert_counts[src_ip] += 1
        except Exception:
            continue

    attacker_alert_count = alert_counts.get(args.attacker_ip, 0)
    total_attacker_windows = len(attacker_windows_above_min)

    recall = attacker_alert_count / total_attacker_windows if total_attacker_windows > 0 else 0.0
    fp_ips = {k for k in alert_counts if k != args.attacker_ip}
    fp_alerts = sum(v for k, v in alert_counts.items() if k != args.attacker_ip)

    print(f"\n{'='*50}")
    print(f"WINDOW-LEVEL METRICS (BruteForce)")
    print(f"{'='*50}")
    print(f"Attacker windows (ground truth, >=min_syns): {total_attacker_windows}")
    print(f"Attacker windows detected (alerts):          {attacker_alert_count}")
    print(f"FP alerts (non-attacker IPs):                {fp_alerts}")
    print(f"FP IPs:                                      {len(fp_ips)}")
    if fp_ips:
        print(f"  FP IPs: {sorted(fp_ips)[:10]}")
    print(f"Window Recall:  {recall:.4f}  ({attacker_alert_count}/{total_attacker_windows})")
    print(f"{'='*50}")

if __name__ == '__main__':
    main()
