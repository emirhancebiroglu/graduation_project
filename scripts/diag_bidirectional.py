#!/usr/bin/env python3
"""
diag_bidirectional.py — For 10 random Wednesday attack flows, check:
  1. Forward and reverse CSV rows (are both directions present?)
  2. Are they labeled the same or differently?
  3. Which direction's Flow ID appears in the t=0.90 alert set?

Prints only — writes nothing to disk.
"""

from pathlib import Path
import pandas as pd
import random

REPO       = Path(__file__).resolve().parent.parent
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}

PROTO_NUM_TO_NAME = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: '?'}


def parse_ip_port(field):
    field = field.strip()
    lc = field.rfind(':')
    if lc == -1:
        return field, 0
    try:
        return field[:lc], int(field[lc + 1:])
    except ValueError:
        return field[:lc], 0


def valid_ip(ip):
    if not ip:
        return False
    if ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
        return False
    return ':' not in ip


def build_alert_fid_sets(alert_file):
    """Return (forward_fids, reverse_fids, all_fids) — all as plain sets of strings."""
    forward_fids = set()
    reverse_fids = set()
    with open(alert_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 8:
                continue
            try:
                proto_str = parts[2].strip()
                src_ip, src_port = parse_ip_port(parts[6].strip())
                dst_ip, dst_port = parse_ip_port(parts[7].strip())
                if not valid_ip(src_ip) or not valid_ip(dst_ip):
                    continue
                if src_port == 0 or dst_port == 0:
                    continue
                proto_num = PROTO_MAP.get(proto_str, 0)
                src_m = IP_MAP.get(src_ip, src_ip)
                dst_m = IP_MAP.get(dst_ip, dst_ip)

                # forward: alert direction (src→dst)
                forward_fids.add(f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}")
                forward_fids.add(f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}")
                # reverse: opposite direction (dst→src)
                reverse_fids.add(f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}")
                reverse_fids.add(f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}")
            except (IndexError, ValueError):
                continue
    all_fids = forward_fids | reverse_fids
    return forward_fids, reverse_fids, all_fids


def main():
    print("Loading alert file...", flush=True)
    fwd_fids, rev_fids, all_fids = build_alert_fid_sets(ALERT_FILE)
    print(f"  Forward FIDs: {len(fwd_fids):,}   Reverse FIDs: {len(rev_fids):,}   All: {len(all_fids):,}")

    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['label_clean'] = df['Label'].str.strip()

    # Build lookup: tuple → list of rows
    # tuple = (src_ip, dst_ip, src_port, dst_port, proto_num)
    print("Building tuple index...", flush=True)
    df['src_ip']   = df['Source IP'].str.strip()
    df['dst_ip']   = df['Destination IP'].str.strip()
    df['src_port'] = pd.to_numeric(df['Source Port'], errors='coerce').fillna(0).astype(int)
    df['dst_port'] = pd.to_numeric(df['Destination Port'], errors='coerce').fillna(0).astype(int)
    df['proto']    = pd.to_numeric(df['Protocol'], errors='coerce').fillna(0).astype(int)

    # Index by (src_ip, dst_ip, src_port, dst_port, proto)
    tuple_index = {}
    for idx, row in df.iterrows():
        key = (row['src_ip'], row['dst_ip'], int(row['src_port']),
               int(row['dst_port']), int(row['proto']))
        tuple_index.setdefault(key, []).append(idx)

    # Sample 10 random attack rows (any DoS label)
    dos_labels = ['DoS Hulk', 'DoS GoldenEye', 'DoS slowloris',
                  'DoS Slowhttptest', 'Heartbleed']
    attacks = df[df['label_clean'].isin(dos_labels)]
    sample  = attacks.sample(10, random_state=7).copy()

    print()
    print("=" * 90)
    print("Bidirectional Flow Diagnostic — 10 random Wednesday attack flows")
    print("Alert set: t=0.90, mp=2")
    print("=" * 90)

    summary_rows = []

    for i, (idx, row) in enumerate(sample.iterrows()):
        fwd_fid    = str(row['Flow ID']).strip()
        src_ip     = row['src_ip']
        dst_ip     = row['dst_ip']
        src_port   = int(row['src_port'])
        dst_port   = int(row['dst_port'])
        proto_num  = int(row['proto'])
        proto_name = PROTO_NUM_TO_NAME.get(proto_num, str(proto_num))
        label      = row['label_clean']

        # Build the expected reverse Flow ID (same format as CIC: src-dst-sport-dport-proto)
        rev_key  = (dst_ip, src_ip, dst_port, src_port, proto_num)
        rev_idxs = tuple_index.get(rev_key, [])

        if rev_idxs:
            rev_rows  = df.loc[rev_idxs]
            rev_fid   = str(rev_rows.iloc[0]['Flow ID']).strip()
            rev_label = ' / '.join(rev_rows['label_clean'].unique())
            rev_count = len(rev_idxs)
        else:
            rev_fid   = '(not found)'
            rev_label = '(not found)'
            rev_count = 0

        # Alert membership
        fwd_in_fwd = fwd_fid in fwd_fids   # attack row's FID in alert forward set
        fwd_in_rev = fwd_fid in rev_fids   # attack row's FID in alert reverse set
        rev_in_fwd = rev_fid in fwd_fids   # reverse row's FID in alert forward set
        rev_in_rev = rev_fid in rev_fids   # reverse row's FID in alert reverse set

        fwd_alerted = fwd_in_fwd or fwd_in_rev
        rev_alerted = rev_in_fwd or rev_in_rev

        # Direction label for which alert matched
        def match_dir(in_fwd, in_rev):
            if in_fwd and in_rev:
                return "fwd+rev"
            if in_fwd:
                return "fwd"
            if in_rev:
                return "rev"
            return "none"

        fwd_match = match_dir(fwd_in_fwd, fwd_in_rev)
        rev_match = match_dir(rev_in_fwd, rev_in_rev)

        print(f"\n── [{i+1:02d}] {label} ──────────────────────────────────────────────")
        print(f"  ATTACK row:  {src_ip}:{src_port} → {dst_ip}:{dst_port}  ({proto_name})")
        print(f"               Flow ID: {fwd_fid}")
        print(f"               Label:   {label}")
        print(f"               Alert match: {fwd_match}")
        if rev_count > 0:
            print(f"  REVERSE row: {dst_ip}:{dst_port} → {src_ip}:{src_port}  ({proto_name})")
            print(f"               Flow ID: {rev_fid}")
            print(f"               Label:   {rev_label}  ({rev_count} row(s))")
            print(f"               Alert match: {rev_match}")
        else:
            print(f"  REVERSE row: (no matching row found in CSV)")

        same_label = (rev_count > 0 and label in rev_label) if rev_count > 0 else None

        summary_rows.append({
            '#':             i + 1,
            'Attack label':  label[:16],
            'tuple':         f"{src_ip}:{src_port}→{dst_ip}:{dst_port}",
            'Rev row?':      'yes' if rev_count > 0 else 'no',
            'Rev label':     rev_label[:12] if rev_count > 0 else '—',
            'Same label?':   ('yes' if same_label else 'no') if rev_count > 0 else '—',
            'Atk alerted':   fwd_match,
            'Rev alerted':   rev_match if rev_count > 0 else '—',
        })

    # Summary table
    print()
    print("=" * 90)
    print("Summary table")
    print("=" * 90)
    cols = ['#', 'Attack label', 'Rev row?', 'Rev label', 'Same label?', 'Atk alerted', 'Rev alerted']
    col_w = [3, 17, 9, 13, 11, 12, 12]
    print("  " + "  ".join(c.ljust(w) for c, w in zip(cols, col_w)))
    print("  " + "  ".join("-" * w for w in col_w))
    for r in summary_rows:
        print("  " + "  ".join(str(r[c]).ljust(w) for c, w in zip(cols, col_w)))

    # Aggregate answers
    has_rev    = sum(1 for r in summary_rows if r['Rev row?'] == 'yes')
    same_lbl   = sum(1 for r in summary_rows if r['Same label?'] == 'yes')
    diff_lbl   = sum(1 for r in summary_rows if r['Same label?'] == 'no')
    atk_alerted = sum(1 for r in summary_rows if r['Atk alerted'] != 'none')
    rev_alerted = sum(1 for r in summary_rows if r['Rev alerted'] not in ('none', '—'))

    print()
    print("─" * 60)
    print("Aggregate answers (over 10 sampled flows):")
    print(f"  Reverse row present in CSV:  {has_rev}/10")
    print(f"  When present — same label:   {same_lbl}/{has_rev}")
    print(f"  When present — diff label:   {diff_lbl}/{has_rev}")
    print(f"  Attack-direction row alerted: {atk_alerted}/10")
    print(f"  Reverse-direction row alerted:{rev_alerted}/{has_rev if has_rev else 10}")
    print("─" * 60)


if __name__ == '__main__':
    main()
