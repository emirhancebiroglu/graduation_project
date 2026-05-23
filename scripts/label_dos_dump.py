#!/usr/bin/env python3
"""
label_dos_dump.py — Join Snort dump CSVs with CIC ground truth labels

Snort dump: src_ip, src_port, dst_ip, dst_port, proto, 17_features, score
CIC CSV:    Flow ID = "src_ip-dst_ip-src_port-dst_port-proto" (bidirectional)

Output: data/snort_dump/labeled/<day>_labeled.csv with 'label' column
        0 = BENIGN, 1 = DoS/attack (CIC-labeled)

Matching strategy:
  1. Build set of attack flow IDs from CIC CSV (bidirectional)
  2. Tag Snort dump rows as 1 if their 5-tuple matches an attack flow ID

Note: CIC IP map: 192.168.10.51 → 172.16.0.1 (PCAP vs CSV IP mismatch)
"""

import logging
import pandas as pd
import numpy as np
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

BASE_DIR   = Path('/home/emirhan/bitirme')
DUMP_DIR   = BASE_DIR / 'data/snort_dump'
CIC_DIR    = BASE_DIR / 'data/raw/cicids2017'
OUT_DIR    = DUMP_DIR / 'labeled'
OUT_DIR.mkdir(parents=True, exist_ok=True)

# PCAP IP → CIC CSV IP mapping
IP_MAP = {'192.168.10.51': '172.16.0.1'}

# Day → CIC CSV file(s)
DAY_CSV_MAP = {
    'Monday':   ['Monday-WorkingHours.pcap_ISCX.csv'],
    'Tuesday':  ['Tuesday-WorkingHours.pcap_ISCX.csv'],
    'Wednesday':['Wednesday-workingHours.pcap_ISCX.csv'],
}

PROTO_MAP = {'tcp': 6, 'udp': 17, 'icmp': 1, 'TCP': 6, 'UDP': 17, 'ICMP': 1}


def map_ip(ip: str) -> str:
    return IP_MAP.get(ip, ip)


def build_attack_flow_ids(csv_files: list) -> set:
    """Return set of flow IDs (bidirectional) for non-BENIGN rows in CIC CSVs."""
    attack_fids = set()
    for fname in csv_files:
        path = CIC_DIR / fname
        if not path.exists():
            log.warning(f'CIC CSV not found: {path}')
            continue
        log.info(f'  Loading CIC: {fname}')
        df = pd.read_csv(path, low_memory=False, on_bad_lines='skip',
                         encoding='utf-8', encoding_errors='replace')
        df.columns = df.columns.str.strip()
        if 'Label' not in df.columns or 'Flow ID' not in df.columns:
            log.warning(f'  Missing Label or Flow ID column in {fname}')
            continue
        df['Label'] = df['Label'].str.strip()
        attacks = df[df['Label'] != 'BENIGN']
        log.info(f'  {len(attacks)} attack rows in {fname}')

        for _, row in attacks.iterrows():
            fid = str(row.get('Flow ID', '')).strip()
            if not fid:
                continue
            # CIC Flow ID format: "src_ip-dst_ip-src_port-dst_port-proto"
            # Add both directions
            attack_fids.add(fid)
            # Reverse
            parts = fid.split('-')
            if len(parts) == 5:
                rev = f"{parts[1]}-{parts[0]}-{parts[3]}-{parts[2]}-{parts[4]}"
                attack_fids.add(rev)

    log.info(f'  Total attack flow IDs: {len(attack_fids)}')
    return attack_fids


def dump_row_to_fid(row) -> tuple:
    """Generate flow ID strings from a Snort dump row (5-tuple)."""
    src = map_ip(str(row['src_ip']))
    dst = map_ip(str(row['dst_ip']))
    sp  = int(row['src_port'])
    dp  = int(row['dst_port'])
    pr  = int(row['proto'])

    fid1 = f"{src}-{dst}-{sp}-{dp}-{pr}"
    fid2 = f"{dst}-{src}-{dp}-{sp}-{pr}"
    return fid1, fid2


def label_dump(day: str, csv_files: list):
    dump_path = DUMP_DIR / f'{day}_features.csv'
    if not dump_path.exists():
        log.warning(f'Dump file not found: {dump_path}')
        return None

    log.info(f'\n[{day}] Building attack flow IDs...')
    attack_fids = build_attack_flow_ids(csv_files)

    log.info(f'[{day}] Loading dump: {dump_path}')
    df = pd.read_csv(dump_path, low_memory=False)
    log.info(f'  {len(df)} rows')

    labels = np.zeros(len(df), dtype=np.int8)
    for i, row in enumerate(df.itertuples(index=False)):
        src = map_ip(str(row.src_ip))
        dst = map_ip(str(row.dst_ip))
        sp  = int(row.src_port)
        dp  = int(row.dst_port)
        pr  = int(row.proto)
        fid1 = f"{src}-{dst}-{sp}-{dp}-{pr}"
        fid2 = f"{dst}-{src}-{dp}-{sp}-{pr}"
        if fid1 in attack_fids or fid2 in attack_fids:
            labels[i] = 1

    df['label'] = labels
    tp  = int((labels == 1).sum())
    tn  = int((labels == 0).sum())
    log.info(f'  Label stats: attack={tp} benign={tn} ({tp/(tp+tn)*100:.1f}% attack)')

    out = OUT_DIR / f'{day}_labeled.csv'
    df.to_csv(out, index=False)
    log.info(f'  Saved: {out}')
    return df


def main():
    log.info('=' * 60)
    log.info('DoS Dump Labeling — CIC Ground Truth Join')
    log.info('=' * 60)

    for day, csv_files in DAY_CSV_MAP.items():
        df = label_dump(day, csv_files)
        if df is not None:
            log.info(f'  [{day}] label distribution: {df["label"].value_counts().to_dict()}')

    log.info('\nDone. Labeled files in: ' + str(OUT_DIR))
    log.info('Next: python3 train/train_dos_fpr_opt_v3.py')


if __name__ == '__main__':
    main()
