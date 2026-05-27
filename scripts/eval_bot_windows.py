#!/usr/bin/env python3
"""eval_bot_windows.py — Bot Client window-level recall evaluation

Parses Friday PCAP for SYN packets from known bot IPs (7 IPs),
groups into 300s windows per IP, counts how many were detected
in Snort alert output.
"""
import argparse, sys
from pathlib import Path
from collections import defaultdict
import pandas as pd
from scapy.all import PcapReader, IP, TCP

BOT_IPS = [
    '192.168.10.5', '192.168.10.8', '192.168.10.9',
    '192.168.10.12', '192.168.10.14', '192.168.10.15', '192.168.10.17'
]
WINDOW_SEC = 300

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
    parser.add_argument('--window', type=int, default=WINDOW_SEC)
    parser.add_argument('--min-syns', type=int, default=3)
    args = parser.parse_args()

    print(f"PCAP:       {Path(args.pcap).name}")
    print(f"Alert CSV:  {args.alert_csv}")
    print(f"Window:     {args.window}s  min_syns={args.min_syns}")
    print(f"Bot IPs:    {BOT_IPS}")

    print("Parsing SYNs from PCAP...")
    packets = list(parse_syns(args.pcap))
    print(f"  Total SYNs: {len(packets)}")

    df = pd.DataFrame(packets, columns=['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['window_id'] = (df['ts'] // args.window).astype(int)

    bot_set = set(BOT_IPS)
    print(f"\n{'='*60}")
    print(f"PER-BOT-IP WINDOW ANALYSIS")
    print(f"{'='*60}")

    total_bot_windows = 0
    total_detected = 0

    for bot_ip in BOT_IPS:
        ip_packets = df[df['src_ip'] == bot_ip]
        if len(ip_packets) == 0:
            print(f"  {bot_ip}: 0 SYNs in PCAP")
            continue
        windows = ip_packets.groupby('window_id').size()
        windows_above_min = windows[windows >= args.min_syns]
        n_windows = len(windows_above_min)
        total_bot_windows += n_windows
        print(f"  {bot_ip}: {len(ip_packets)} SYNs, {len(windows)} windows, {n_windows} >= min_syns")

    # Parse alerts
    alert_path = Path(args.alert_csv)
    alerts_per_src = defaultdict(int)
    if alert_path.exists():
        with open(alert_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 7:
                    src = parts[3].strip()
                    if src in bot_set:
                        alerts_per_src[src] += 1

    print(f"\n{'='*60}")
    print(f"ALERTS PER BOT IP")
    print(f"{'='*60}")
    for ip in BOT_IPS:
        n_alerts = alerts_per_src.get(ip, 0)
        print(f"  {ip}: {n_alerts} alert lines")

    total_alert_lines = sum(alerts_per_src.values())
    print(f"\n  Total alert lines for bot IPs: {total_alert_lines}")

    # FP check: alert source IPs that are NOT bot IPs
    all_alert_srcs = set()
    if alert_path.exists():
        with open(alert_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 7:
                    all_alert_srcs.add(parts[3].strip())
    fp_srcs = all_alert_srcs - bot_set
    print(f"\n  FP source IPs (alerted but not bot): {len(fp_srcs)}")
    if fp_srcs:
        print(f"  FP IPs: {sorted(fp_srcs)[:15]}")

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total bot windows (>=min_syns): {total_bot_windows}")
    print(f"Total bot alert lines:          {total_alert_lines}")
    print(f"Note: Window-level recall cannot be directly computed because")
    print(f"Snort dedup (30-min cooldown) merges multiple windows into fewer alerts.")
    print(f"IP-level recall is the authoritative metric.")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
