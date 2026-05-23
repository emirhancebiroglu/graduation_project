#!/usr/bin/env python3
"""
generate_pcap_training_data.py -- Generate PortScan training data from one or more PCAPs

IMPORTANT: log1p is applied to ALL 7 features to match C++ preprocess() in
portscan_flow_tracker.h: for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) f[i] = std::log1p(f[i]);

Output: data/processed/portscan_v2/ (or --output-dir)
  X_train.npy, y_train.npy, X_val.npy, y_val.npy, X_test.npy, y_test.npy
  scaler.pkl, metadata.json
"""

import argparse
import json
import logging
import pickle
import sys
from pathlib import Path
from math import log2

import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP, TCP
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DEFAULT_SCANNER_IPS = ['172.16.0.1']
WINDOW_SEC = 60
FEATURE_NAMES = [
    'total_syns',
    'unique_dst_ports',
    'unique_dst_ips',
    'dst_port_entropy',
    'src_port_range',
    'unique_port_ratio',
    'syn_rate',
]
LOG1P_FEATURES = FEATURE_NAMES[:]


def parse_syns(pcap_path: Path):
    count = 0
    for pkt in PcapReader(str(pcap_path)):
        if IP not in pkt or TCP not in pkt:
            continue
        flags = pkt[TCP].flags
        if flags & 0x02 and not (flags & 0x10):
            ts = float(pkt.time)
            yield (ts, pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            count += 1
            if count % 100000 == 0:
                logging.info(f"  Processed {count} SYNs...")
    logging.info(f"  Total SYNs: {count}")


def process_sliding_windows(pcap_path: Path, window_sec: int, scanner_ips: list):
    logging.info(f"Parsing {pcap_path.name}...")
    all_packets = list(parse_syns(pcap_path))
    logging.info(f"  Building windows from {len(all_packets)} SYNs...")

    df = pd.DataFrame(all_packets, columns=['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['window_id'] = (df['ts'] // window_sec).astype(int)
    df['is_scanner'] = df['src_ip'].isin(scanner_ips).astype(int)

    rows = []
    for (src_ip, wid), group in df.groupby(['src_ip', 'window_id']):
        group = group.reset_index(drop=True)
        total_syns = len(group)
        unique_dst_ports = group['dst_port'].nunique()
        unique_dst_ips = group['dst_ip'].nunique()

        port_counts = group['dst_port'].value_counts()
        total = port_counts.sum()
        entropy = -sum((c / total) * log2(c / total) for c in port_counts if c > 0)

        src_port_range = float(group['src_port'].max() - group['src_port'].min())
        unique_port_ratio = unique_dst_ports / total_syns if total_syns > 0 else 0.0
        syn_rate = total_syns / window_sec
        label = group['is_scanner'].max()

        rows.append({
            'src_ip': src_ip, 'window_id': wid, 'pcap': pcap_path.name,
            'total_syns': total_syns, 'unique_dst_ports': unique_dst_ports,
            'unique_dst_ips': unique_dst_ips, 'dst_port_entropy': entropy,
            'src_port_range': src_port_range, 'unique_port_ratio': unique_port_ratio,
            'syn_rate': syn_rate, 'label': label,
        })

    result = pd.DataFrame(rows)
    pos = int(result['label'].sum())
    logging.info(f"  {pcap_path.name}: {len(result)} windows (pos={pos}, neg={len(result)-pos})")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=str, default=None)
    parser.add_argument('--pcap-list', type=str, default=None,
                        help='Comma-separated list of PCAP paths')
    parser.add_argument('--scanner-ips', type=str,
                        default=','.join(DEFAULT_SCANNER_IPS))
    parser.add_argument('--output-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v2'))
    parser.add_argument('--window', type=int, default=WINDOW_SEC)
    args = parser.parse_args()

    pcap_paths = []
    if args.pcap_list:
        for p in args.pcap_list.split(','):
            p = p.strip()
            if p:
                pcap_paths.append(Path(p))
    elif args.pcap:
        pcap_paths.append(Path(args.pcap))
    else:
        logging.error("Must provide --pcap or --pcap-list")
        sys.exit(1)

    scanner_ips = [ip.strip() for ip in args.scanner_ips.split(',') if ip.strip()]
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for p in pcap_paths:
        if not p.exists():
            logging.error(f"PCAP not found: {p}")
            sys.exit(1)

    logging.info(f"PCAPs: {[p.name for p in pcap_paths]}")
    logging.info(f"Scanner IPs: {scanner_ips}")

    all_windows = []
    for pcap_path in pcap_paths:
        all_windows.append(process_sliding_windows(pcap_path, args.window, scanner_ips))

    windows = pd.concat(all_windows, ignore_index=True)

    total_pos = int(windows['label'].sum())
    total_neg = len(windows) - total_pos
    logging.info(f"Combined: {len(windows)} windows (pos={total_pos}, neg={total_neg})")

    if total_pos == 0:
        logging.error("No positive samples! Check --scanner-ips.")
        sys.exit(1)

    X = windows[FEATURE_NAMES].values.astype(np.float64)
    y = windows['label'].values.astype(np.int64)

    # log1p on ALL 7 features -- matches C++ preprocess() exactly
    for i in range(len(FEATURE_NAMES)):
        X[:, i] = np.log1p(X[:, i])

    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.15/0.85, random_state=42, stratify=y_temp)

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
        'sources': [str(p) for p in pcap_paths],
        'window_seconds': args.window,
        'scanner_ips': scanner_ips,
        'feature_count': len(FEATURE_NAMES),
        'feature_names': FEATURE_NAMES,
        'log1p_features': LOG1P_FEATURES,
        'total_windows': len(windows),
        'total_positive': total_pos,
        'total_negative': total_neg,
        'train_samples': len(X_train),
        'val_samples': len(X_val),
        'test_samples': len(X_test),
        'attack_rate_train': float(y_train.sum() / len(y_train)),
        'scaler_median': [round(v, 10) for v in scaler.center_.tolist()],
        'scaler_iqr': [round(v, 10) for v in scaler.scale_.tolist()],
    }
    with open(out_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logging.info(f"Saved to {out_dir}")
    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print(f"PCAPs: {[p.name for p in pcap_paths]}")
    print(f"Total windows: {len(windows)}")
    print(f"Positive (scanner): {total_pos}")
    print(f"Negative (benign):  {total_neg}")
    print(f"Train/Val/Test:     {len(X_train)}/{len(X_val)}/{len(X_test)}")
    print(f"Scaler median: {[round(v, 6) for v in scaler.center_.tolist()]}")
    print(f"Scaler iqr:    {[round(v, 6) for v in scaler.scale_.tolist()]}")
    print("=" * 60)


if __name__ == '__main__':
    main()