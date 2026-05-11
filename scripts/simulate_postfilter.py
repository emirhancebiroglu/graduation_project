#!/usr/bin/env python3
"""
simulate_postfilter.py — Offline simulation of candidate post-filter rules (task 04a).

For each candidate rule, computes:
  - FPs suppressed (BENIGN alerts silenced)
  - TPs suppressed (attack alerts silenced — must be 0)
  - Remaining FP count and FPR
  - Recall impact

Baseline: t=0.90, max_packets=2
  TP=252,610  TN=431,531  FP=8,500  FN=62

Inputs:
  results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt
  data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv

Output:
  results/xgboost/fp_analysis/postfilter_simulation.txt
"""

from pathlib import Path
import pandas as pd

REPO = Path(__file__).resolve().parent.parent

# Use the t=0.90 alert file (best operating point from task 02/03)
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
OUT_FILE   = REPO / "results/xgboost/fp_analysis/postfilter_simulation.txt"

# Baseline confusion matrix at t=0.90, mp=2 (from task 02 sweep)
BASELINE_TN = 431_531
BASELINE_FP = 8_500
BASELINE_TP = 252_610
BASELINE_FN = 62

# ── Reused flow-ID helpers (identical to xgb_flowid_confusion_wednesday.py) ──

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}

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
    return ":" not in ip

def map_ip(ip):
    return IP_MAP.get(ip, ip)


def parse_alerts(alert_file: Path) -> pd.DataFrame:
    """Parse alert CSV into a DataFrame with one row per alert.

    Columns: src_ip, src_port, dst_ip, dst_port, proto_num,
             fid1, fid2, fid3, fid4  (the four flow-ID variants)
    """
    rows = []
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
                rows.append({
                    'src_ip': src_ip, 'src_port': src_port,
                    'dst_ip': dst_ip, 'dst_port': dst_port,
                    'proto_num': proto_num,
                    'fid1': f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}",
                    'fid2': f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}",
                    'fid3': f"{dst_m}-{src_m}-{dst_port}-{src_port}-{proto_num}",
                    'fid4': f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}",
                })
            except (IndexError, ValueError):
                continue
    return pd.DataFrame(rows)


def main():
    lines = []
    log = lines.append

    log("=" * 70)
    log("Post-filter Rule Simulation — task 04a")
    log(f"Alert file: {ALERT_FILE.relative_to(REPO)}")
    log(f"Baseline:   t=0.90, max_packets=2")
    log(f"            TP={BASELINE_TP:,}  TN={BASELINE_TN:,}  "
        f"FP={BASELINE_FP:,}  FN={BASELINE_FN:,}")
    log(f"            FPR={BASELINE_FP/(BASELINE_FP+BASELINE_TN):.4f}  "
        f"Recall={BASELINE_TP/(BASELINE_TP+BASELINE_FN):.4f}")
    log("=" * 70)

    # ── Load and parse alerts ────────────────────────────────────────────────
    print("Parsing alert file...", flush=True)
    alerts = parse_alerts(ALERT_FILE)
    log(f"\nAlerts parsed: {len(alerts):,}")

    # ── Load ground-truth CSV ────────────────────────────────────────────────
    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['label_bin'] = (df['Label'].str.strip() != 'BENIGN').astype(int)
    df['total_pkts'] = df['Total Fwd Packets'] + df['Total Backward Packets']

    # Build a flow-ID → (label_bin, total_pkts) lookup using all four FID variants
    fid_cols = ['fid1', 'fid2', 'fid3', 'fid4']
    fid_set = set()
    for col in fid_cols:
        fid_set.update(alerts[col].tolist())

    csv_fid_map = {}   # fid → (label_bin, total_pkts)
    for _, row in df.iterrows():
        fid = str(row['Flow ID']).strip()
        if fid in fid_set:
            csv_fid_map[fid] = (int(row['label_bin']), int(row['total_pkts']))

    # Annotate each alert with its ground-truth label and packet count.
    # Use the first FID variant that hits; alerts not found in CSV are dropped.
    def lookup(alert_row):
        for col in fid_cols:
            hit = csv_fid_map.get(alert_row[col])
            if hit is not None:
                return hit
        return None

    print("Joining alerts to ground truth...", flush=True)
    annotated = []
    unmatched = 0
    for _, row in alerts.iterrows():
        result = lookup(row)
        if result is None:
            unmatched += 1
            continue
        label_bin, total_pkts = result
        annotated.append({
            'dst_port':   row['dst_port'],
            'proto_num':  row['proto_num'],
            'label_bin':  label_bin,     # 0=BENIGN, 1=ATTACK
            'total_pkts': total_pkts,
        })

    ann = pd.DataFrame(annotated)
    log(f"Alerts matched to CSV: {len(ann):,}  (unmatched/filtered: {unmatched:,})")

    # Verify counts align with known baseline
    matched_fp = (ann['label_bin'] == 0).sum()
    matched_tp = (ann['label_bin'] == 1).sum()
    log(f"  Matched FP (BENIGN alerted): {matched_fp:,}  "
        f"(baseline={BASELINE_FP:,})")
    log(f"  Matched TP (attack alerted): {matched_tp:,}  "
        f"(baseline={BASELINE_TP:,})")

    # ── Define candidate rules ───────────────────────────────────────────────
    #
    # Each rule is a boolean mask over ann indicating which alerted flows
    # would be SUPPRESSED (i.e., the filter fires → no alert emitted).
    # Rules are cumulative: each extends the previous.

    suppress_r1 = ann['dst_port'] == 53
    suppress_r2 = ann['dst_port'].isin([53, 137])
    suppress_r3 = ann['dst_port'].isin([53, 137, 389])
    suppress_r4 = ann['dst_port'].isin([53, 137, 389]) & (ann['total_pkts'] <= 5)

    rules = [
        ("Rule 1", "dst_port==53",                          suppress_r1),
        ("Rule 2", "dst_port IN {53,137}",                  suppress_r2),
        ("Rule 3", "dst_port IN {53,137,389}",              suppress_r3),
        ("Rule 4", "dst_port IN {53,137,389} AND pkts<=5",  suppress_r4),
    ]

    # ── Simulate each rule ───────────────────────────────────────────────────
    log("")
    log("─" * 70)
    log("Simulation Results")
    log("─" * 70)

    # Header
    col_w = [8, 38, 14, 14, 12, 14, 14]
    headers = ["Rule", "Description", "FP suppressed", "TP suppressed",
               "Remain FP", "Remain FPR", "Recall"]
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_w))
    sep = "  ".join("-" * w for w in col_w)
    log(header_line)
    log(sep)

    # Baseline row
    base_fpr    = BASELINE_FP / (BASELINE_FP + BASELINE_TN)
    base_recall = BASELINE_TP / (BASELINE_TP + BASELINE_FN)
    baseline_vals = ["Baseline", "(no filter)", "—", "—",
                     f"{BASELINE_FP:,}", f"{base_fpr:.4f}", f"{base_recall:.4f}"]
    log("  ".join(str(v).ljust(w) for v, w in zip(baseline_vals, col_w)))

    results = []
    for rule_name, desc, suppress_mask in rules:
        suppressed     = ann[suppress_mask]
        fp_suppressed  = (suppressed['label_bin'] == 0).sum()
        tp_suppressed  = (suppressed['label_bin'] == 1).sum()

        remaining_fp   = BASELINE_FP - fp_suppressed
        remaining_tn   = BASELINE_TN + fp_suppressed   # suppressed FPs become effective TNs
        remaining_tp   = BASELINE_TP - tp_suppressed
        remaining_fn   = BASELINE_FN + tp_suppressed

        remain_fpr    = remaining_fp / (remaining_fp + remaining_tn)
        remain_recall = remaining_tp / (remaining_tp + remaining_fn) if (remaining_tp + remaining_fn) > 0 else 0.0

        results.append({
            'rule': rule_name, 'desc': desc,
            'fp_supp': fp_suppressed, 'tp_supp': tp_suppressed,
            'rem_fp': remaining_fp, 'rem_fpr': remain_fpr,
            'recall': remain_recall,
        })

        row_vals = [
            rule_name, desc,
            f"{fp_suppressed:,}",
            f"{tp_suppressed:,}",
            f"{remaining_fp:,}",
            f"{remain_fpr:.4f}",
            f"{remain_recall:.4f}",
        ]
        log("  ".join(str(v).ljust(w) for v, w in zip(row_vals, col_w)))

    # ── Detail breakdown for each rule ──────────────────────────────────────
    log("")
    log("─" * 70)
    log("Detail: port breakdown of suppressed FPs per rule (top 5 ports)")
    log("─" * 70)
    for rule_name, desc, suppress_mask in rules:
        suppressed_fps = ann[suppress_mask & (ann['label_bin'] == 0)]
        port_counts = suppressed_fps['dst_port'].value_counts().head(5)
        log(f"\n{rule_name} ({desc}) — {len(suppressed_fps):,} FPs suppressed:")
        for port, count in port_counts.items():
            log(f"  port {port:>5}: {count:,}  ({count/len(suppressed_fps)*100:.1f}%)")

    # ── Recommendation ───────────────────────────────────────────────────────
    log("")
    log("─" * 70)
    log("Recommendation")
    log("─" * 70)
    # Find best rule: TP suppressed == 0, FPR minimised
    safe_rules = [r for r in results if r['tp_supp'] == 0]
    if safe_rules:
        best = min(safe_rules, key=lambda r: r['rem_fpr'])
        log(f"Best zero-TP-risk rule: {best['rule']} ({best['desc']})")
        log(f"  FPs suppressed: {best['fp_supp']:,}  "
            f"Remaining FP: {best['rem_fp']:,}  "
            f"FPR: {best['rem_fpr']:.4f}  "
            f"Recall: {best['recall']:.4f}")
        if best['rem_fpr'] < 0.01:
            log("  → FPR TARGET < 0.01 MET. Recommend implementing this rule in C++.")
        else:
            log("  → FPR target not met by filter alone. May need combination with task 04b.")
    else:
        log("No rule achieves zero TP suppression — review filter logic.")

    report = "\n".join(lines)
    print("\n" + report)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(report, encoding='utf-8')
    print(f"\nSaved: {OUT_FILE}")


if __name__ == '__main__':
    main()
