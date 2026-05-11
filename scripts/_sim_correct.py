#!/usr/bin/env python3
"""Corrected simulation: derives dst_port for all 8,500 FPs from the CSV side."""
import pandas as pd
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
OUT_FILE   = REPO / "results/xgboost/fp_analysis/postfilter_simulation.txt"

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}

BASELINE_TN = 431_531
BASELINE_TP = 252_610
BASELINE_FN = 62

def parse_ip_port(field):
    field = field.strip()
    lc = field.rfind(':')
    if lc == -1:
        return field, 0
    try:
        return field[:lc], int(field[lc+1:])
    except ValueError:
        return field[:lc], 0

def valid_ip(ip):
    if not ip:
        return False
    if ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
        return False
    return ':' not in ip

def map_ip(ip):
    return IP_MAP.get(ip, ip)

def build_alert_fids(alert_file):
    """Return (fid_set, fid->dst_port dict)."""
    fid_set = set()
    fid_to_dst = {}
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
                src_m = map_ip(src_ip)
                dst_m = map_ip(dst_ip)
                for fid in [
                    f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}",
                    f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}",
                    f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}",
                ]:
                    fid_set.add(fid)
                    fid_to_dst[fid] = dst_port
            except (IndexError, ValueError):
                continue
    return fid_set, fid_to_dst

def main():
    lines = []

    print("Building alert FID set...", flush=True)
    alert_fids, fid_to_dst = build_alert_fids(ALERT_FILE)
    lines.append(f"Alert FID set size: {len(alert_fids):,}")

    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['total_pkts'] = df['Total Fwd Packets'] + df['Total Backward Packets']
    df['label_bin'] = (df['Label'].str.strip() != 'BENIGN').astype(int)

    benign = df[df['label_bin'] == 0].copy()
    attack = df[df['label_bin'] == 1].copy()

    fp_rows = benign[benign['Flow ID'].isin(alert_fids)].copy()
    tp_rows = attack[attack['Flow ID'].isin(alert_fids)].copy()

    fp_rows['alert_dst_port'] = fp_rows['Flow ID'].map(fid_to_dst)
    tp_rows['alert_dst_port'] = tp_rows['Flow ID'].map(fid_to_dst)

    total_fp = len(fp_rows)

    lines.append(f"BENIGN rows in CSV:  {len(benign):,}")
    lines.append(f"FP rows (matched):   {total_fp:,}  (baseline=8,500)")
    lines.append(f"TP rows (matched):   {len(tp_rows):,}  (baseline=252,610)")
    lines.append("")

    # Port distribution of FPs
    lines.append("Top 10 dst_port among FP rows:")
    for port, cnt in fp_rows['alert_dst_port'].value_counts().head(10).items():
        lines.append(f"  port {port:>5}: {cnt:>6,}  ({cnt/total_fp*100:.1f}%)")
    lines.append("")

    # Simulation
    lines.append("=" * 68)
    lines.append("Post-filter Rule Simulation  (baseline: t=0.90, max_packets=2)")
    lines.append("=" * 68)
    lines.append("")

    base_fpr    = total_fp / (total_fp + BASELINE_TN)
    base_recall = BASELINE_TP / (BASELINE_TP + BASELINE_FN)

    col_w = [8, 38, 14, 14, 10, 11, 9]
    headers = ["Rule", "Description", "FP suppressed", "TP suppressed",
               "Rem FP", "Rem FPR", "Recall"]
    lines.append("  ".join(h.ljust(w) for h, w in zip(headers, col_w)))
    lines.append("  ".join("-" * w for w in col_w))

    def row_str(vals):
        return "  ".join(str(v).ljust(w) for v, w in zip(vals, col_w))

    lines.append(row_str([
        "Baseline", "(no filter)", "—", "—",
        f"{total_fp:,}", f"{base_fpr:.4f}", f"{base_recall:.4f}"
    ]))

    rules = [
        ("Rule 1", "dst_port==53",
            fp_rows['alert_dst_port'] == 53,
            tp_rows['alert_dst_port'] == 53),
        ("Rule 2", "dst_port IN {53,137}",
            fp_rows['alert_dst_port'].isin([53, 137]),
            tp_rows['alert_dst_port'].isin([53, 137])),
        ("Rule 3", "dst_port IN {53,137,389}",
            fp_rows['alert_dst_port'].isin([53, 137, 389]),
            tp_rows['alert_dst_port'].isin([53, 137, 389])),
        ("Rule 4", "dst_port IN {53,137,389} AND pkts<=5",
            fp_rows['alert_dst_port'].isin([53, 137, 389]) & (fp_rows['total_pkts'] <= 5),
            tp_rows['alert_dst_port'].isin([53, 137, 389]) & (tp_rows['total_pkts'] <= 5)),
    ]

    results = []
    for name, desc, fp_mask, tp_mask in rules:
        fp_s = int(fp_mask.sum())
        tp_s = int(tp_mask.sum())
        rem_fp     = total_fp - fp_s
        rem_tn     = BASELINE_TN + fp_s
        rem_tp     = BASELINE_TP - tp_s
        rem_fn     = BASELINE_FN + tp_s
        rem_fpr    = rem_fp / (rem_fp + rem_tn)
        rem_recall = rem_tp / (rem_tp + rem_fn)
        results.append((name, desc, fp_s, tp_s, rem_fp, rem_fpr, rem_recall))
        lines.append(row_str([
            name, desc, f"{fp_s:,}", f"{tp_s:,}",
            f"{rem_fp:,}", f"{rem_fpr:.4f}", f"{rem_recall:.4f}"
        ]))

    lines.append("")
    lines.append("─" * 68)
    lines.append("Recommendation")
    lines.append("─" * 68)
    safe = [(n, d, fps, tps, rfp, rfpr, rr)
            for n, d, fps, tps, rfp, rfpr, rr in results if tps == 0]
    if safe:
        best = min(safe, key=lambda x: x[5])
        n, d, fps, tps, rfp, rfpr, rr = best
        lines.append(f"Best zero-TP-risk rule: {n} ({d})")
        lines.append(f"  FP suppressed: {fps:,}  Remaining FP: {rfp:,}  FPR: {rfpr:.4f}  Recall: {rr:.4f}")
        if rfpr < 0.01:
            lines.append("  FPR TARGET < 0.01 MET.")
        else:
            lines.append(f"  FPR target not met ({rfpr:.4f} > 0.01). Remaining FPs need further reduction.")

    report = "\n".join(lines)
    print("\n" + report)
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(report, encoding='utf-8')
    print(f"\nSaved: {OUT_FILE}")

if __name__ == '__main__':
    main()
