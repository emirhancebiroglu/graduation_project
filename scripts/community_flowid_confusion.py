#!/usr/bin/env python3
"""
community_flowid_confusion.py — Community Rules confusion matrix

lstm_flowid_confusion.py ile aynı mantık.
Tek fark: --alert-dir varsayılanı community dizinine işaret eder.

Kullanım:
    python community_flowid_confusion.py \
        --alert-dir ~/bitirme/results/community \
        --csv-dir ~/bitirme/data/raw/cicids2017 \
        --output ~/bitirme/results/community/confusion_matrix.txt
"""

import pandas as pd
import numpy as np
import argparse
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

# PCAP IP → CSV IP haritalama
IP_MAP = {
    '192.168.10.51': '172.16.0.1',
}


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

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue
        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
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

                    # IP haritalama uygula
                    src_ip_mapped = map_ip(src_ip)
                    dst_ip_mapped = map_ip(dst_ip)

                    # İki yönlü Flow ID
                    fid1 = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"
                    fid2 = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                    flow_ids.add(fid1)
                    flow_ids.add(fid2)

                    # Haritalanmış IP'lerle Flow ID
                    if src_ip_mapped != src_ip or dst_ip_mapped != dst_ip:
                        fid3 = f"{dst_ip_mapped}-{src_ip_mapped}-{dst_port}-{src_port}-{proto_num}"
                        fid4 = f"{src_ip_mapped}-{dst_ip_mapped}-{src_port}-{dst_port}-{proto_num}"
                        flow_ids.add(fid3)
                        flow_ids.add(fid4)

                    subdir_clean += 1
                except (IndexError, ValueError):
                    continue

        logging.info(f"  {subdir.name}: {subdir_alerts} alert, {subdir_clean} temiz")

    logging.info(f"Toplam alert: {total_alerts}")
    logging.info(f"Filtrelenen: {filtered_out}")
    logging.info(f"Temiz alert: {total_alerts - filtered_out}")
    logging.info(f"Benzersiz Flow ID (çift yön + haritalanmış): {len(flow_ids)}")
    return flow_ids


def compute_confusion_matrix(csv_dir: Path, alert_flows: set):
    csv_files = sorted(csv_dir.glob("*.csv"))
    cm_total = np.array([[0, 0], [0, 0]])
    total_rows = 0

    for csv_file in csv_files:
        logging.info(f"İşleniyor: {csv_file.name}")
        try:
            df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip',
                             encoding='utf-8', encoding_errors='replace')
        except Exception as e:
            logging.warning(f"Okunamadı: {csv_file.name} — {e}")
            continue
        df.columns = df.columns.str.strip()
        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            continue

        df['Predicted'] = df['Flow ID'].isin(alert_flows).astype(int)
        df['Label_binary'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        cm = confusion_matrix(df['Label_binary'], df['Predicted'], labels=[0, 1])
        cm_total += cm
        total_rows += len(df)

        file_tp = ((df['Label_binary'] == 1) & (df['Predicted'] == 1)).sum()
        file_fp = ((df['Label_binary'] == 0) & (df['Predicted'] == 1)).sum()
        file_attacks = (df['Label_binary'] == 1).sum()
        if file_attacks > 0:
            logging.info(f"  Saldırı: {file_attacks}, TP: {file_tp}, FP: {file_fp}")

    tn, fp, fn, tp = cm_total[0][0], cm_total[0][1], cm_total[1][0], cm_total[1][1]
    total = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': accuracy, 'precision': precision,
        'recall': recall, 'f1': f1, 'fpr': fpr, 'total': total_rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert-dir', type=str, required=True)
    parser.add_argument('--csv-dir', type=str, required=True)
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir)
    csv_dir = Path(args.csv_dir)

    logging.info("=" * 60)
    logging.info("Community Rules Alert → Flow ID")
    logging.info("=" * 60)
    logging.info(f"IP Haritalama: {IP_MAP}")
    alert_flows = extract_flow_ids_from_alerts(alert_dir)
    if not alert_flows:
        logging.error("Hiç Flow ID çıkarılamadı!")
        return

    logging.info("")
    logging.info("=" * 60)
    logging.info("Confusion Matrix")
    logging.info("=" * 60)
    m = compute_confusion_matrix(csv_dir, alert_flows)

    result = f"""
{'=' * 60}
Snort3 Community Rules — CIC-IDS2017 Confusion Matrix
Yöntem: Flow ID eşleştirme
IP Map: 192.168.10.51 → 172.16.0.1 (Tuesday)
{'=' * 60}

                    Tahmin: Normal (0)    Tahmin: Atak (1)
Gerçek: Normal (0)  TN = {m['tn']:<18} FP = {m['fp']}
Gerçek: Atak (1)    FN = {m['fn']:<18} TP = {m['tp']}

{'─' * 60}
Toplam Satır:  {m['total']}
Accuracy:      {m['accuracy']:.4f}
Precision:     {m['precision']:.4f}
Recall (TPR):  {m['recall']:.4f}
F1-Score:      {m['f1']:.4f}
FPR:           {m['fpr']:.4f}
{'─' * 60}
"""
    print(result)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(result)
        logging.info(f"Kaydedildi: {out}")


if __name__ == "__main__":
    main()
