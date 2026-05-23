#!/usr/bin/env python3
"""
eval_portscan_window_recall.py -- Window-level recall evaluation for portscan_inspector

Parses a PCAP, computes windows for 172.16.0.1 (scanner), counts how many
were detected in Snort alert_csv output. Gives window-level TP/FP/FN.

Usage:
  python3 scripts/eval_portscan_window_recall.py \
    --pcap /home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap \
    --alert-csv /home/emirhan/bitirme/results/portscan_v2/wednesday_eval/alert_csv.txt \
    --scanner-ip 172.16.0.1 \
    --window 60
"""

import argparse
import sys
from pathlib import Path
from math import log2
from collections import defaultdict

import pandas as pd
from scapy.all import PcapReader, IP, TCP


SCANNER_IP_DEFAULT = '172.16.0.1'
WINDOW_SEC = 60


def parse_syns(pcap_path):
    for pkt in PcapReader(str(pcap_path)):
        if IP not in pkt or TCP not in pkt:
            continue
        flags = pkt[TCP].flags
        if flags & 0x02 and not (flags & 0x10):
            yield float(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport


def ip_to_int(ip_str):
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--alert-csv', required=True,
                        help='Snort alert_csv.txt output file')
    parser.add_argument('--scanner-ip', default=SCANNER_IP_DEFAULT)
    parser.add_argument('--window', type=int, default=WINDOW_SEC)
    parser.add_argument('--min-packets', type=int, default=5,
                        help='min_packets threshold used in Snort config')
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    alert_path = Path(args.alert_csv)
    scanner_ip = args.scanner_ip
    window_sec = args.window

    print(f"PCAP:       {pcap_path.name}")
    print(f"Alert CSV:  {alert_path}")
    print(f"Scanner IP: {scanner_ip}")
    print(f"Window:     {window_sec}s  min_packets={args.min_packets}")

    # Parse all SYNs from PCAP
    print("Parsing SYNs from PCAP...")
    packets = list(parse_syns(pcap_path))
    print(f"  Total SYNs: {len(packets)}")

    # Build windows for ALL source IPs
    df = pd.DataFrame(packets, columns=['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['window_id'] = (df['ts'] // window_sec).astype(int)

    windows = defaultdict(list)
    for (src_ip, wid), group in df.groupby(['src_ip', 'window_id']):
        windows[(src_ip, wid)] = len(group)

    # Scanner windows (positive ground truth)
    scanner_windows = {k: v for k, v in windows.items() if k[0] == scanner_ip}
    scanner_windows_above_min = {k: v for k, v in scanner_windows.items() if v >= args.min_packets}
    benign_windows = {k: v for k, v in windows.items() if k[0] != scanner_ip and v >= args.min_packets}

    print(f"\nScanner ({scanner_ip}) windows total:       {len(scanner_windows)}")
    print(f"Scanner windows >= min_packets={args.min_packets}: {len(scanner_windows_above_min)}")
    print(f"Benign windows >= min_packets={args.min_packets}:  {len(benign_windows)}")

    if not alert_path.exists():
        print(f"\nAlert CSV not found: {alert_path}")
        print("Run Snort first, then re-run this script.")
        sys.exit(1)

    # Parse alerts from CSV
    # Snort alert_csv format: timestamp,pkt_num,proto,src,sport,dst,dport,...
    # GID:302 = portscan_inspector alerts
    alerts = []
    with open(alert_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 7:
                continue
            alerts.append(parts)

    if not alerts:
        print("\nNo alerts found in CSV.")
        scanner_detected = 0
    else:
        # Extract alerted source IPs
        alerted_src_ips = set()
        for parts in alerts:
            try:
                src_ip = parts[3].strip() if len(parts) > 3 else ''
                if src_ip:
                    alerted_src_ips.add(src_ip)
            except Exception:
                continue

        scanner_detected = 1 if scanner_ip in alerted_src_ips else 0
        benign_fp_ips = alerted_src_ips - {scanner_ip}
        total_alerts = len(alerts)

        print(f"\nTotal alerts:           {total_alerts}")
        print(f"Unique alerted src IPs: {len(alerted_src_ips)}")
        print(f"Scanner detected:       {'YES' if scanner_detected else 'NO'}")
        print(f"FP IPs (non-scanner):   {len(benign_fp_ips)}")
        if benign_fp_ips:
            print(f"  FP IPs: {sorted(benign_fp_ips)}")

    # Window-level metrics (Snort fires once per IP per window, so alert = window TP)
    # Count alert lines per src IP to estimate window count
    alert_counts = defaultdict(int)
    for parts in alerts:
        try:
            src_ip = parts[3].strip()
            alert_counts[src_ip] += 1
        except Exception:
            continue

    scanner_alert_count = alert_counts.get(scanner_ip, 0)
    total_scanner_windows = len(scanner_windows_above_min)

    recall = scanner_alert_count / total_scanner_windows if total_scanner_windows > 0 else 0.0
    fp_alerts = sum(v for k, v in alert_counts.items() if k != scanner_ip)

    print(f"\n{'='*50}")
    print(f"WINDOW-LEVEL METRICS")
    print(f"{'='*50}")
    print(f"Scanner windows (ground truth, >=min_pkts): {total_scanner_windows}")
    print(f"Scanner windows detected (alerts):          {scanner_alert_count}")
    print(f"FP alerts (non-scanner IPs):                {fp_alerts}")
    print(f"Window Recall:  {recall:.4f}  ({scanner_alert_count}/{total_scanner_windows})")
    print(f"{'='*50}")

    if recall >= 0.90:
        print(f"PASS: Recall {recall:.3f} >= 0.90 target")
    else:
        print(f"FAIL: Recall {recall:.3f} < 0.90 target")
        missed = total_scanner_windows - scanner_alert_count
        print(f"  Missed windows: {missed}")


if __name__ == '__main__':
    main()