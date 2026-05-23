#!/usr/bin/env python3
"""
xgb_flowid_confusion_friday.py — PortScan Inspector confusion matrix (Friday)

Evaluates against all 3 Friday CSV files:
  - Friday-WorkingHours-Morning.pcap_ISCX.csv          (Benign)
  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv   (DDoS)
  - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (PortScan)

Positive class (attack=1): PortScan ONLY
Everything else (Benign, DDoS, Bot) = 0

Alert directory: results/portscan/Friday-WorkingHours/alert_csv.txt

Usage:
    python scripts/xgb_flowid_confusion_friday.py \
        --alert-dir ~/bitirme/results/portscan \
        --csv-dir ~/bitirme/data/raw/cicids2017 \
        --output ~/bitirme/results/portscan/confusion_matrix_friday.txt \
        --json-output ~/bitirme/results/portscan/metrics.json
"""

import pandas as pd
import numpy as np
import argparse
import json
import logging
from pathlib import Path
from sklearn.metrics import confusion_matrix

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

PROTO_MAP = {
    'TCP': 6, 'UDP': 17, 'ICMP': 1,
    'tcp': 6, 'udp': 17, 'icmp': 1,
}

# PCAP IP → CSV IP mapping (same as wednesday script)
IP_MAP = {
    '192.168.10.51': '172.16.0.1',
}

FRIDAY_ALERT_SUBDIR = 'Friday-WorkingHours'

FRIDAY_CSV_FILES = [
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

# PortScan ONLY is positive class
POSITIVE_LABEL = 'PortScan'


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


def extract_flow_ids_from_alerts(alert_dir: Path) -> set:
    flow_ids = set()
    total_alerts = 0
    filtered_out = 0
    found = False

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue

        if subdir.name != FRIDAY_ALERT_SUBDIR:
            logging.info(f"  Skipping (not Friday): {subdir.name}")
            continue

        found = True
        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
            logging.warning(f"  alert_csv.txt not found: {subdir}")
            continue

        subdir_alerts = 0
        subdir_clean = 0

        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                total_alerts += 1
                subdir_alerts += 1
                parts = line.split(',')
                if len(parts) < 8:
                    continue
                try:
                    proto_str = parts[2].strip()
                    src_ip, src_port = parse_ip_port(parts[6].strip())
                    dst_ip, dst_port = parse_ip_port(parts[7].strip())

                    if not valid_ip(src_ip) or not valid_ip(dst_ip):
                        filtered_out += 1
                        continue
                    if src_port == 0 or dst_port == 0:
                        filtered_out += 1
                        continue

                    proto_num = PROTO_MAP.get(proto_str, 0)

                    src_ip_mapped = map_ip(src_ip)
                    dst_ip_mapped = map_ip(dst_ip)

                    # Both directions
                    fid1 = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"
                    fid2 = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                    flow_ids.add(fid1)
                    flow_ids.add(fid2)

                    # Mapped IPs
                    if src_ip_mapped != src_ip or dst_ip_mapped != dst_ip:
                        fid3 = f"{dst_ip_mapped}-{src_ip_mapped}-{dst_port}-{src_port}-{proto_num}"
                        fid4 = f"{src_ip_mapped}-{dst_ip_mapped}-{src_port}-{dst_port}-{proto_num}"
                        flow_ids.add(fid3)
                        flow_ids.add(fid4)

                    subdir_clean += 1
                except (IndexError, ValueError):
                    continue

        logging.info(f"  {subdir.name}: {subdir_alerts} alerts, {subdir_clean} clean")

    if not found:
        logging.error(
            f"'{FRIDAY_ALERT_SUBDIR}' directory not found in {alert_dir}. "
            f"Check that Snort ran and produced alerts."
        )

    logging.info(f"Total alerts: {total_alerts}")
    logging.info(f"Filtered out: {filtered_out}")
    logging.info(f"Unique Flow IDs (both dirs + mapped): {len(flow_ids)}")
    return flow_ids


def compute_confusion_matrix(csv_dir: Path, alert_flows: set):
    all_dfs = []

    for csv_name in FRIDAY_CSV_FILES:
        csv_file = csv_dir / csv_name
        if not csv_file.exists():
            logging.warning(f"CSV not found, skipping: {csv_file}")
            continue

        logging.info(f"Loading: {csv_name}")
        try:
            df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip',
                             encoding='utf-8', encoding_errors='replace')
        except Exception as e:
            logging.error(f"Could not read {csv_name}: {e}")
            continue

        df.columns = df.columns.str.strip()
        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            logging.error(f"Missing 'Flow ID' or 'Label' in {csv_name}")
            continue

        df['Label'] = df['Label'].str.strip()
        logging.info(f"  Shape: {df.shape}, Labels: {df['Label'].value_counts().to_dict()}")
        all_dfs.append(df)

    if not all_dfs:
        logging.error("No CSV files loaded!")
        return None

    combined = pd.concat(all_dfs, ignore_index=True)
    logging.info(f"Combined shape: {combined.shape}")
    logging.info(f"Combined label distribution:\n{combined['Label'].value_counts()}")

    # PortScan=1, everything else=0
    combined['Predicted']    = combined['Flow ID'].isin(alert_flows).astype(int)
    combined['Label_binary'] = (combined['Label'] == POSITIVE_LABEL).astype(int)

    # Per-label breakdown
    logging.info("\nPer-label alert breakdown:")
    for label in combined['Label'].unique():
        subset = combined[combined['Label'] == label]
        alerted = subset['Predicted'].sum()
        total   = len(subset)
        logging.info(f"  {label:<40} alerted={alerted}/{total} ({100*alerted/total:.1f}%)")

    cm = confusion_matrix(combined['Label_binary'], combined['Predicted'], labels=[0, 1])
    TN, FP, FN, TP = cm.ravel()

    total     = int(TN + FP + FN + TP)
    accuracy  = (TP + TN) / total if total > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0

    return {
        'tp': int(TP), 'tn': int(TN), 'fp': int(FP), 'fn': int(FN),
        'accuracy': round(accuracy, 4),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'fpr': round(fpr, 4),
        'total': total,
        'confusion_matrix': [[int(TN), int(FP)], [int(FN), int(TP)]],
    }


def targets_hit(m) -> bool:
    return (m['recall'] >= 0.99 and
            m['precision'] >= 0.98 and
            m['f1'] >= 0.98 and
            m['fpr'] <= 0.01)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert-dir',   type=str, required=True)
    parser.add_argument('--csv-dir',     type=str, required=True)
    parser.add_argument('--output',      type=str, default=None)
    parser.add_argument('--json-output', type=str, default=None)
    parser.add_argument('--iteration',   type=int, default=0)
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir).expanduser()
    csv_dir   = Path(args.csv_dir).expanduser()

    logging.info("=" * 60)
    logging.info("PortScan Inspector — Friday Confusion Matrix")
    logging.info(f"Positive class: {POSITIVE_LABEL} only")
    logging.info("=" * 60)

    alert_flows = extract_flow_ids_from_alerts(alert_dir)
    if not alert_flows:
        logging.error("No flow IDs extracted from alerts!")
        return

    m = compute_confusion_matrix(csv_dir, alert_flows)
    if m is None:
        return

    hit = targets_hit(m)

    result_text = f"""
{'=' * 60}
PortScan Inspector — CIC-IDS2017 Friday Confusion Matrix
Scope:   Friday-WorkingHours (Morning + Afternoon-DDoS + Afternoon-PortScan)
Method:  Flow ID + IP mapping
Positive class: PortScan only (DDoS/Benign/Bot = negative)
Iteration: {args.iteration}
{'=' * 60}

                    Predicted Normal (0)    Predicted Attack (1)
Actual Normal  (0)  TN = {m['tn']:<20} FP = {m['fp']}
Actual Attack  (1)  FN = {m['fn']:<20} TP = {m['tp']}

{'─' * 60}
Total Rows:    {m['total']}
Accuracy:      {m['accuracy']:.4f}
Precision:     {m['precision']:.4f}   (target >=0.98)  {'✓ HIT' if m['precision'] >= 0.98 else '✗ MISS'}
Recall (TPR):  {m['recall']:.4f}   (target >=0.99)  {'✓ HIT' if m['recall'] >= 0.99 else '✗ MISS'}
F1-Score:      {m['f1']:.4f}   (target >=0.98)  {'✓ HIT' if m['f1'] >= 0.98 else '✗ MISS'}
FPR:           {m['fpr']:.4f}   (target <=0.01)  {'✓ HIT' if m['fpr'] <= 0.01 else '✗ MISS'}
{'─' * 60}
ALL TARGETS: {'✓ HIT — OPTIMIZATION COMPLETE' if hit else '✗ NOT YET'}
{'─' * 60}
"""

    print(result_text)

    if args.output:
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(result_text)
        logging.info(f"Saved: {out}")

    if args.json_output:
        m['iteration'] = args.iteration
        m['targets_hit'] = hit
        out_json = Path(args.json_output).expanduser()
        out_json.parent.mkdir(parents=True, exist_ok=True)
        with open(out_json, 'w') as f:
            json.dump(m, f, indent=2)
        # Append to history
        history_path = out_json.parent / 'history.jsonl'
        with open(history_path, 'a') as f:
            f.write(json.dumps(m) + '\n')
        logging.info(f"JSON saved: {out_json}")

    # Exit code: 0 = targets hit, 1 = not yet
    import sys
    sys.exit(0 if hit else 1)


if __name__ == "__main__":
    main()