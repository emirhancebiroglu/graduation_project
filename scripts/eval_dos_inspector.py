#!/usr/bin/env python3
"""eval_dos_inspector.py — Per-day confusion matrix for dos_inspector (GID:301)

Usage:
    python scripts/eval_dos_inspector.py \
        --alert-dir ~/bitirme/results/dos_inspector \
        --csv-dir ~/bitirme/data/raw/cicids2017 \
        --output ~/bitirme/results/dos_inspector/

Outputs per-day + per-attack-type confusion matrices.
"""

import pandas as pd
import numpy as np
import argparse
import logging
import json
import os
from pathlib import Path
from sklearn.metrics import confusion_matrix
from collections import OrderedDict

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, (np.ndarray,)):
            return obj.tolist()
        return super().default(obj)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP = {'192.168.10.51': '172.16.0.1'}

ALERT_SUBDIR_TO_DAY = {
    'Monday-WorkingHours': 'Monday',
    'Tuesday-WorkingHours': 'Tuesday',
    'Wednesday-workingHours': 'Wednesday',
    'Thursday-WorkingHours': 'Thursday',
    'Friday-WorkingHours': 'Friday',
}

DAY_TO_CSV_FILES = {
    'Monday': ['Monday-WorkingHours.pcap_ISCX.csv'],
    'Tuesday': ['Tuesday-WorkingHours.pcap_ISCX.csv'],
    'Wednesday': ['Wednesday-workingHours.pcap_ISCX.csv'],
    'Thursday': [
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    ],
    'Friday': [
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    ],
}


def parse_ip_port(field):
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


def extract_flows_from_alert_file(alert_file):
    flow_ids = set()
    if not alert_file.exists():
        return flow_ids
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
                src_ip_mapped = map_ip(src_ip)
                dst_ip_mapped = map_ip(dst_ip)
                for s, d in [(src_ip, dst_ip), (src_ip_mapped, dst_ip_mapped)]:
                    fid1 = f"{d}-{s}-{dst_port}-{src_port}-{proto_num}"
                    fid2 = f"{s}-{d}-{src_port}-{dst_port}-{proto_num}"
                    flow_ids.add(fid1)
                    flow_ids.add(fid2)
            except (IndexError, ValueError):
                continue
    return flow_ids


def compute_day_cm(csv_dir, day_name, alert_flows):
    csv_files = [csv_dir / f for f in DAY_TO_CSV_FILES[day_name]]
    cm = np.array([[0, 0], [0, 0]])
    total_rows = 0
    attack_details = {}

    for csv_file in csv_files:
        if not csv_file.exists():
            logging.warning(f"  CSV bulunamadı: {csv_file}")
            continue
        df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip',
                         encoding='utf-8', encoding_errors='replace')
        df.columns = df.columns.str.strip()
        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            continue
        df['Predicted'] = df['Flow ID'].isin(alert_flows).astype(int)
        df['Label_binary'] = df['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
        cm += confusion_matrix(df['Label_binary'], df['Predicted'], labels=[0, 1])
        total_rows += len(df)
        for label, group in df.groupby('Label'):
            label = str(label).strip()
            if label not in attack_details:
                attack_details[label] = {'total': 0, 'detected': 0}
            attack_details[label]['total'] += len(group)
            attack_details[label]['detected'] += group['Predicted'].sum()

    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])
    total = tp + tn + fp + fn
    acc = (tp + tn) / total if total > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': round(acc, 4), 'precision': round(prec, 4),
        'recall': round(rec, 4), 'f1': round(f1, 4), 'fpr': round(fpr, 4),
        'total': total_rows,
        'attack_details': attack_details,
    }


def format_day_result(day, m):
    header = f"{'='*60}\nDoS Inspector -- {day} ({DAY_TO_CSV_FILES[day][0][:25]}...)\n{'='*60}"
    cm_part = f"""
                    Pred: Normal (0)    Pred: Attack (1)
Actual: Normal (0)  TN = {m['tn']:<18} FP = {m['fp']}
Actual: Attack (1)  FN = {m['fn']:<18} TP = {m['tp']}
"""
    metrics = f"Total: {m['total']} | Acc={m['accuracy']:.4f} | Prec={m['precision']:.4f} | Rec={m['recall']:.4f} | F1={m['f1']:.4f} | FPR={m['fpr']:.4f}"
    details = "\n  Attack-type breakdown:"
    for label, d in sorted(m['attack_details'].items()):
        if label == 'BENIGN':
            continue
        rate = d['detected'] / d['total'] * 100 if d['total'] > 0 else 0
        details += f"\n    {label:50s}: {d['detected']:>6d}/{d['total']:<6d} ({rate:5.1f}%)"
    return f"{header}\n{cm_part}\n{metrics}\n{details}\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert-dir', type=str, required=True)
    parser.add_argument('--csv-dir', type=str, required=True)
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir).expanduser()
    csv_dir = Path(args.csv_dir).expanduser()
    output_dir = Path(args.output).expanduser() if args.output else alert_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = OrderedDict()

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue
        day = ALERT_SUBDIR_TO_DAY.get(subdir.name)
        if day is None:
            logging.info(f"Atlanıyor (bilinmeyen dizin): {subdir.name}")
            continue

        alert_file = subdir / "alert_csv.txt"
        logging.info(f"\n{'='*60}\nİşleniyor: {day} ({subdir.name})\n{'='*60}")
        flows = extract_flows_from_alert_file(alert_file)
        logging.info(f"  Benzersiz Flow ID: {len(flows)}")
        if not flows:
            logging.warning(f"  Hiç alert bulunamadı! {day} için sonuç: hepsi negatif.")
            all_results[day] = {
                'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
                'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0, 'fpr': 0,
                'total': 0, 'attack_details': {},
            }
            continue

        result = compute_day_cm(csv_dir, day, flows)
        all_results[day] = result
        logging.info(f"Done: {day} -- TP={result['tp']} TN={result['tn']} FP={result['fp']} FN={result['fn']} Rec={result['recall']} FPR={result['fpr']}")

    summary_file = output_dir / "confusion_matrix_all_days.txt"
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("DoS Inspector -- CIC-IDS2017 Per-Day Confusion Matrix\n")
        f.write("=" * 70 + "\n\n")
        for day, m in all_results.items():
            f.write(format_day_result(day, m))
            f.write("\n")
    logging.info(f"Saved per-day results: {summary_file}")

    json_file = output_dir / "metrics_all_days.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, cls=NumpyEncoder)
    logging.info(f"JSON kaydedildi: {json_file}")

    summary_msg = "\n" + "=" * 70 + "\n"
    summary_msg += "SUMMARY TABLE\n"
    summary_msg += "=" * 70 + "\n"
    summary_msg += f"{'Day':<12} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8} {'FPR':>8}\n"
    summary_msg += "-" * 88 + "\n"
    for day, m in all_results.items():
        summary_msg += f"{day:<12} {m['tp']:>8} {m['tn']:>8} {m['fp']:>8} {m['fn']:>8} {m['accuracy']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} {m['f1']:>8.4f} {m['fpr']:>8.4f}\n"
    print(summary_msg)
    with open(output_dir / "summary_table.txt", 'w', encoding='utf-8') as f:
        f.write(summary_msg)


if __name__ == "__main__":
    main()
