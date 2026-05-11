#!/usr/bin/env python3
"""
analyze_fp_wednesday.py — Profile the 20,317 Wednesday false positives.

Inputs:
  results/xgboost/Wednesday-workingHours/alert_csv.txt
  data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv

Output:
  results/xgboost/fp_analysis/wednesday_fp_report.txt
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np

REPO = Path(__file__).resolve().parent.parent

ALERT_FILE = REPO / "results/xgboost/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
OUT_FILE   = REPO / "results/xgboost/fp_analysis/wednesday_fp_report.txt"

TN_SAMPLE  = 50_000   # Section D TN sample size

# ── Reused from xgb_flowid_confusion_wednesday.py ────────────────────────────

PROTO_MAP = {
    'TCP': 6, 'UDP': 17, 'ICMP': 1,
    'tcp': 6, 'udp': 17, 'icmp': 1,
}

IP_MAP = {'192.168.10.51': '172.16.0.1'}


def parse_ip_port(field: str):
    field = field.strip()
    last_colon = field.rfind(':')
    if last_colon == -1:
        return field, 0
    ip = field[:last_colon]
    try:
        port = int(field[last_colon + 1:])
    except ValueError:
        port = 0
    return ip, port


def valid_ip(ip):
    if not ip or pd.isna(ip):
        return False
    if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
        return False
    if ":" in ip:
        return False
    return True


def map_ip(ip):
    return IP_MAP.get(ip, ip)


def extract_alert_flow_ids(alert_file: Path) -> set:
    flow_ids = set()
    with open(alert_file, 'r') as f:
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
                src_m = map_ip(src_ip)
                dst_m = map_ip(dst_ip)
                flow_ids.add(f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}")
                flow_ids.add(f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}")
                if src_m != src_ip or dst_m != dst_ip:
                    flow_ids.add(f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}")
                    flow_ids.add(f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}")
            except (IndexError, ValueError):
                continue
    return flow_ids

# ── CIC column → inspector feature mapping ───────────────────────────────────

# Raw CIC column names (stripped) → (inspector_name, scale_factor)
# scale_factor converts CIC units to inspector units:
#   Flow Duration: µs → s  (÷ 1e6)
#   IAT columns:  µs → ms (÷ 1000)
#   All others:   1:1
CIC_TO_FEAT = {
    'Flow Duration':              ('dur',      1e-6),
    'Total Fwd Packets':          ('spkts',    1.0),
    'Total Backward Packets':     ('dpkts',    1.0),
    'Total Length of Fwd Packets':('sbytes',   1.0),
    'Total Length of Bwd Packets':('dbytes',   1.0),
    'Fwd Packet Length Mean':     ('smeansz',  1.0),
    'Bwd Packet Length Mean':     ('dmeansz',  1.0),
    'Init_Win_bytes_forward':     ('swin',     1.0),
    'Init_Win_bytes_backward':    ('dwin',     1.0),
    'Fwd IAT Mean':               ('sintpkt',  1e-3),
    'Bwd IAT Mean':               ('dintpkt',  1e-3),
}

FEAT_ORDER = ['dur','spkts','dpkts','sbytes','dbytes',
              'smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']


def build_feature_df(df: pd.DataFrame) -> pd.DataFrame:
    """Map CIC columns → inspector features with unit conversions."""
    out = {}
    for cic_col, (feat_name, scale) in CIC_TO_FEAT.items():
        col = df[cic_col] if scale == 1.0 else df[cic_col] * scale
        out[feat_name] = col.values
    return pd.DataFrame(out, index=df.index)


# ── Report helpers ────────────────────────────────────────────────────────────

def section_header(title: str) -> str:
    bar = '─' * 60
    return f"\n{bar}\n{title}\n{bar}\n"


def fmt_table(rows, headers):
    col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
             for i, h in enumerate(headers)]
    sep = '  '.join('-' * w for w in col_w)
    header_line = '  '.join(str(h).ljust(w) for h, w in zip(headers, col_w))
    lines = [header_line, sep]
    for row in rows:
        lines.append('  '.join(str(v).ljust(w) for v, w in zip(row, col_w)))
    return '\n'.join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    lines = []
    log = lines.append

    log("=" * 60)
    log("Wednesday FP Analysis — XGBoost Inspector (threshold=0.50, max_packets=2)")
    log("=" * 60)

    # ── Load alerts ──────────────────────────────────────────────────────────
    print("Loading alert flow IDs...", flush=True)
    alert_ids = extract_alert_flow_ids(ALERT_FILE)
    log(f"\nAlert flow IDs extracted: {len(alert_ids):,}")

    # ── Load CSV ─────────────────────────────────────────────────────────────
    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()

    # ── Identify FP and TN rows ──────────────────────────────────────────────
    benign = df[df['Label'].str.strip() == 'BENIGN'].copy()
    log(f"BENIGN rows in CSV:       {len(benign):,}")

    alerted = benign['Flow ID'].isin(alert_ids)
    fp_df = benign[alerted].copy()
    tn_df = benign[~alerted].copy()

    log(f"FP flows (BENIGN+alerted): {len(fp_df):,}")
    log(f"TN flows (BENIGN+quiet):   {len(tn_df):,}")

    total_fp = len(fp_df)

    # ── Section A — Destination port distribution ─────────────────────────────
    log(section_header("Section A — Destination Port Distribution of FPs (top 10)"))
    port_counts = (fp_df['Destination Port']
                   .value_counts()
                   .head(10)
                   .reset_index())
    port_counts.columns = ['dst_port', 'count']
    port_counts['pct'] = (port_counts['count'] / total_fp * 100).map('{:.1f}%'.format)
    rows_a = [tuple(r) for r in port_counts.itertuples(index=False)]
    log(fmt_table(rows_a, ['dst_port', 'count', 'pct']))

    # ── Section B — Packet count distribution ────────────────────────────────
    log(section_header("Section B — Packet Count Distribution of FPs"))
    fp_df['total_pkts'] = fp_df['Total Fwd Packets'] + fp_df['Total Backward Packets']

    buckets = [
        ('1',     fp_df['total_pkts'] == 1),
        ('2',     fp_df['total_pkts'] == 2),
        ('3-5',   fp_df['total_pkts'].between(3, 5)),
        ('6-10',  fp_df['total_pkts'].between(6, 10)),
        ('11-50', fp_df['total_pkts'].between(11, 50)),
        ('50+',   fp_df['total_pkts'] > 50),
    ]
    rows_b = []
    for label, mask in buckets:
        n = mask.sum()
        rows_b.append((label, n, f"{n/total_fp*100:.1f}%"))
    log(fmt_table(rows_b, ['pkt_bucket', 'count', 'pct']))

    # ── Section C — Score band distribution (TODO) ────────────────────────────
    log(section_header("Section C — Score Band Distribution of FPs"))
    log("TODO: Requires re-replay with per-flow score logging.")
    log("Inspector logs show 'total=X above_thresh=Y' counts but not per-flow scores.")
    log("Will be populated in task 02 (threshold sweep produces per-threshold FP counts).")

    # ── Section D — Feature comparison: FP vs TN ────────────────────────────
    log(section_header("Section D — Feature Comparison: FP Cohort vs TN Sample (medians)"))
    log(f"(TN sample: up to {TN_SAMPLE:,} rows; no log1p or scaling applied)")

    feat_fp = build_feature_df(fp_df)
    tn_sample = tn_df.sample(min(TN_SAMPLE, len(tn_df)), random_state=42)
    feat_tn = build_feature_df(tn_sample)

    rows_d = []
    for feat in FEAT_ORDER:
        med_fp = feat_fp[feat].median()
        med_tn = feat_tn[feat].median()
        ratio  = (med_fp / med_tn) if med_tn != 0 else float('nan')
        rows_d.append((feat,
                       f"{med_fp:.4g}",
                       f"{med_tn:.4g}",
                       f"{ratio:.2f}x"))
    log(fmt_table(rows_d, ['feature', 'median_FP', 'median_TN', 'FP/TN_ratio']))

    # ── Section E — FP cohorts by packet count ───────────────────────────────
    log(section_header("Section E — FP Cohorts by Packet Count"))

    if 'total_pkts' not in fp_df.columns:
        fp_df['total_pkts'] = fp_df['Total Fwd Packets'] + fp_df['Total Backward Packets']

    cohorts = [
        ('Short  (≤3 pkts)',  fp_df['total_pkts'] <= 3),
        ('Medium (4-20 pkts)',fp_df['total_pkts'].between(4, 20)),
        ('Long   (>20 pkts)', fp_df['total_pkts'] > 20),
    ]

    cohort_sum = 0
    for cohort_name, mask in cohorts:
        sub = fp_df[mask]
        n   = len(sub)
        cohort_sum += n
        log(f"\n{cohort_name}  — {n:,} flows ({n/total_fp*100:.1f}%)")

        # Top-3 destination ports
        top_ports = (sub['Destination Port']
                     .value_counts()
                     .head(3)
                     .reset_index())
        top_ports.columns = ['dst_port', 'count']
        port_str = ', '.join(
            f"{r.dst_port} ({r.count})"
            for r in top_ports.itertuples(index=False)
        )
        log(f"  Top-3 dst ports: {port_str}")

        # Median features
        feat_sub = build_feature_df(sub)
        med_row = {feat: f"{feat_sub[feat].median():.4g}" for feat in FEAT_ORDER}
        rows_e = [(f, med_row[f]) for f in FEAT_ORDER]
        log("  Median features:")
        log("  " + fmt_table(rows_e, ['feature', 'median']).replace('\n', '\n  '))

    log(f"\nCohort sum check: {cohort_sum:,}  (expected ≈ {total_fp:,})")

    # ── Summary ───────────────────────────────────────────────────────────────
    log(section_header("Summary"))

    short_pct = (fp_df['total_pkts'] <= 2).sum() / total_fp * 100
    top_port   = fp_df['Destination Port'].value_counts().idxmax()
    top_port_pct = fp_df['Destination Port'].value_counts().max() / total_fp * 100

    log(f"Total FPs profiled:       {total_fp:,}")
    log(f"FPs with ≤2 packets:      {short_pct:.1f}%")
    log(f"Top FP destination port:  {top_port} ({top_port_pct:.1f}%)")

    # Pattern detection (heuristic)
    if top_port_pct >= 60:
        pattern = "P1 — Port concentration"
    elif short_pct >= 70:
        pattern = "P2 — Short-flow concentration"
    else:
        pattern = "P4 — Mixed (run Phases 2, 3, 4 in sequence)"
    log(f"Dominant pattern:         {pattern}")

    # ── Write report ──────────────────────────────────────────────────────────
    report = '\n'.join(lines)
    print(report)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(report, encoding='utf-8')
    print(f"\nReport saved to: {OUT_FILE}", flush=True)

    # Return key stats for PROGRESS.md
    return total_fp, pattern, top_port, top_port_pct, short_pct


if __name__ == '__main__':
    main()
