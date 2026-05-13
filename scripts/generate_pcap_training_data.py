#!/usr/bin/env python3
"""
generate_pcap_training_data.py — Generate PortScan training data from PCAP

Parses Friday-WorkingHours.pcap using tshark, extracts TCP SYN-only packets,
groups by source IP into sliding time windows, computes cross-flow features.

Output: data/processed/portscan_from_pcap/
  X_train.npy, y_train.npy, X_val.npy, y_val.npy, X_test.npy, y_test.npy
  scaler.pkl, metadata.json
"""

import argparse
import json
import logging
import pickle
import sys
from collections import defaultdict
from pathlib import Path
from math import log2

import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP, TCP
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCANNER_IPS = ['172.16.0.1']
WINDOW_SEC = 60
FEATURE_NAMES = [
    'total_syns',          # total SYN count in window
    'unique_dst_ports',    # distinct destination ports
    'unique_dst_ips',      # distinct destination IPs
    'dst_port_entropy',    # Shannon entropy of dst port distribution
    'src_port_range',      # delta between min/max source ports
    'unique_port_ratio',   # unique_dst_ports / total_syns
    'syn_rate',            # total_syns / window_sec
]


def parse_syns(pcap_path: Path):
    """Yield (ts, src_ip, dst_ip, src_port, dst_port) for each SYN-only packet."""
    count = 0
    for pkt in PcapReader(str(pcap_path)):
        if IP not in pkt or TCP not in pkt:
            continue
        flags = pkt[TCP].flags
        if flags & 0x02 and not (flags & 0x10):  # SYN and not ACK
            ts = float(pkt.time)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            yield (ts, src_ip, dst_ip, src_port, dst_port)
            count += 1
            if count % 100000 == 0:
                logging.info(f"  Processed {count} SYNs...")
    logging.info(f"  Total SYNs: {count}")


def process_sliding_windows(pcap_path: Path, window_sec: int):
    """Single-pass: collect all SYNs into DataFrame, then group by src_ip + window."""
    all_packets = list(parse_syns(pcap_path))
    logging.info(f"Building windows from {len(all_packets)} SYNs...")

    df = pd.DataFrame(all_packets, columns=['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['window_id'] = (df['ts'] // window_sec).astype(int)
    df['is_scanner'] = df['src_ip'].isin(SCANNER_IPS).astype(int)

    grouped = df.groupby(['src_ip', 'window_id'])

    logging.info("Computing window features...")
    rows = []
    for (src_ip, wid), group in grouped:
        group = group.reset_index(drop=True)
        total_syns = len(group)
        unique_dst_ports = group['dst_port'].nunique()
        unique_dst_ips = group['dst_ip'].nunique()

        # Destination port entropy
        port_counts = group['dst_port'].value_counts()
        total = port_counts.sum()
        entropy = -sum((c / total) * log2(c / total) for c in port_counts if c > 0)

        # Source port range
        src_port_range = group['src_port'].max() - group['src_port'].min()

        # Unique port ratio
        unique_port_ratio = unique_dst_ports / total_syns if total_syns > 0 else 0

        # SYN rate
        syn_rate = total_syns / window_sec

        label = group['is_scanner'].max()

        rows.append({
            'src_ip': src_ip,
            'window_id': wid,
            'total_syns': total_syns,
            'unique_dst_ports': unique_dst_ports,
            'unique_dst_ips': unique_dst_ips,
            'dst_port_entropy': entropy,
            'src_port_range': src_port_range,
            'unique_port_ratio': unique_port_ratio,
            'syn_rate': syn_rate,
            'label': label,
        })

    result = pd.DataFrame(rows)
    logging.info(f"Total windows: {len(result)} (scanner: {result['label'].sum()}, benign: {(1-result['label']).sum()})")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=str,
                        default='/tmp/friday_syns.pcap')
    parser.add_argument('--output-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_from_pcap'))
    parser.add_argument('--window', type=int, default=WINDOW_SEC)
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not pcap_path.exists():
        logging.error(f"PCAP not found: {pcap_path}")
        sys.exit(1)

    logging.info(f"Processing PCAP: {pcap_path}")
    logging.info(f"Window: {args.window}s, features: {len(FEATURE_NAMES)}")

    windows = process_sliding_windows(pcap_path, args.window)

    logging.info(f"Label distribution: {windows['label'].value_counts().to_dict()}")

    X = windows[FEATURE_NAMES].values.astype(np.float64)
    y = windows['label'].values.astype(np.int64)

    # log1p on count features
    log1p_cols = ['total_syns', 'unique_dst_ports', 'unique_dst_ips', 'syn_rate']
    for i, name in enumerate(FEATURE_NAMES):
        if name in log1p_cols:
            X[:, i] = np.log1p(X[:, i])

    # Train/val/test split (70/15/15, stratified)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.15 / 0.85, random_state=42, stratify=y_temp
    )

    logging.info(f"Train: {X_train.shape}, pos={y_train.sum()}/{len(y_train)}")
    logging.info(f"Val:   {X_val.shape}, pos={y_val.sum()}/{len(y_val)}")
    logging.info(f"Test:  {X_test.shape}, pos={y_test.sum()}/{len(y_test)}")

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    np.save(out_dir / 'X_train.npy', X_train_scaled)
    np.save(out_dir / 'y_train.npy', y_train)
    np.save(out_dir / 'X_val.npy', X_val_scaled)
    np.save(out_dir / 'y_val.npy', y_val)
    np.save(out_dir / 'X_test.npy', X_test_scaled)
    np.save(out_dir / 'y_test.npy', y_test)

    with open(out_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    metadata = {
        'source': str(pcap_path),
        'window_seconds': args.window,
        'feature_count': len(FEATURE_NAMES),
        'feature_names': FEATURE_NAMES,
        'log1p_features': log1p_cols,
        'scanner_ips': SCANNER_IPS,
        'train_samples': len(X_train),
        'val_samples': len(X_val),
        'test_samples': len(X_test),
        'attack_rate_train': float(y_train.sum() / len(y_train)),
        'attack_rate_val': float(y_val.sum() / len(y_val)),
        'attack_rate_test': float(y_test.sum() / len(y_test)),
        'scaler_median': [round(v, 10) for v in scaler.center_.tolist()],
        'scaler_iqr': [round(v, 10) for v in scaler.scale_.tolist()],
    }
    with open(out_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logging.info(f"Saved to {out_dir}")
    logging.info(f"Scaler median: {[round(v, 6) for v in scaler.center_.tolist()]}")
    logging.info(f"Scaler iqr:    {[round(v, 6) for v in scaler.scale_.tolist()]}")


if __name__ == '__main__':
    main()
