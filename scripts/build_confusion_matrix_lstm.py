#!/usr/bin/env python3
"""
build_confusion_matrix_lstm.py — LSTM Inspector alert çıktısından confusion matrix hesapla

Snort3 alert_csv formatı (doğrulanmış):
  [0] timestamp, [1] pkt_num, [2] proto, [3] raw, [4] len, [5] dir,
  [6] src_ip:src_port, [7] dst_ip:dst_port, [8] gid:sid:rev, [9] action

Örnek satır:
  07/04-14:57:08.455510, 3407, UDP, raw, 320, C2S, 192.168.10.51:5353, 224.0.0.251:5353, 300:1:1, allow

CIC-IDS2017 Flow ID formatı:
  "srcIP-dstIP-srcPort-dstPort-protocol"
  Örnek: "192.168.10.5-205.174.165.73-52870-8080-6"

Kullanım:
    python build_confusion_matrix_lstm.py \
        --csv-dir ~/bitirme/data/raw/cicids2017 \
        --alert-dir ~/bitirme/results/lstm \
        --output ~/bitirme/results/lstm/confusion_matrix.txt
"""

import pandas as pd
import numpy as np
import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

PROTO_MAP = {
    'TCP': '6', 'UDP': '17', 'ICMP': '1',
    'tcp': '6', 'udp': '17', 'icmp': '1',
}


def load_cicids_labels(csv_dir: Path) -> dict:
    """
    CIC-IDS2017 CSV'lerden Flow ID → binary label eşleştirmesi.
    Aynı Flow ID'de hem BENIGN hem saldırı varsa → saldırı (1) olarak işaretlenir.
    """
    csv_files = sorted(csv_dir.glob("*.csv"))
    if not csv_files:
        logging.error(f"CSV bulunamadı: {csv_dir}")
        return {}

    flow_labels = {}
    total_rows = 0

    for csv_file in csv_files:
        logging.info(f"Yükleniyor: {csv_file.name}")
        try:
            df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip')
        except Exception as e:
            logging.warning(f"Okunamadı: {csv_file.name} — {e}")
            continue

        df.columns = df.columns.str.strip()

        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            logging.warning(f"Gerekli kolon yok: {csv_file.name}")
            continue

        for _, row in df.iterrows():
            flow_id = str(row['Flow ID']).strip()
            label_str = str(row['Label']).strip()
            binary_label = 0 if label_str == 'BENIGN' else 1

            if flow_id in flow_labels:
                flow_labels[flow_id] = max(flow_labels[flow_id], binary_label)
            else:
                flow_labels[flow_id] = binary_label

        total_rows += len(df)

    n_normal = sum(1 for v in flow_labels.values() if v == 0)
    n_attack = sum(1 for v in flow_labels.values() if v == 1)

    logging.info(f"Toplam CSV satırı: {total_rows}")
    logging.info(f"Benzersiz Flow ID: {len(flow_labels)}")
    logging.info(f"  Normal (0): {n_normal}, Saldırı (1): {n_attack}")

    return flow_labels


def parse_ip_port(field: str):
    """
    'IP:port' veya 'IPv6:port' formatını ayrıştırır.
    IPv6 adresleri ':' içerdiği için son ':' ile ayırıyoruz.
    """
    field = field.strip()
    # Son ':' karakterini bul — port ayracı
    last_colon = field.rfind(':')
    if last_colon == -1:
        return field, '0'
    ip = field[:last_colon]
    port = field[last_colon + 1:]
    return ip, port


def load_lstm_alerts(alert_dir: Path) -> set:
    """
    LSTM Inspector alert_csv çıktılarından Flow ID'leri çıkarır.
    
    Doğrulanmış kolon formatı:
      [0]=timestamp, [1]=pkt, [2]=proto, [3]=raw, [4]=len, [5]=dir,
      [6]=src:port, [7]=dst:port, [8]=gid:sid:rev, [9]=action
    """
    alerted_flows = set()
    alert_count = 0
    parse_errors = 0

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue

        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
            logging.info(f"Alert yok: {subdir.name}")
            continue

        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(',')
                if len(parts) < 8:
                    parse_errors += 1
                    continue

                try:
                    proto_str = parts[2].strip()
                    src_field = parts[6].strip()
                    dst_field = parts[7].strip()

                    src_ip, src_port = parse_ip_port(src_field)
                    dst_ip, dst_port = parse_ip_port(dst_field)

                    proto_num = PROTO_MAP.get(proto_str, '0')

                    # CIC-IDS formatı: srcIP-dstIP-srcPort-dstPort-protoNum
                    flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                    alerted_flows.add(flow_id)

                    # Ters yön (Snort flow yönü CIC-IDS ile uyuşmayabilir)
                    flow_id_rev = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"
                    alerted_flows.add(flow_id_rev)

                    alert_count += 1
                except (IndexError, ValueError):
                    parse_errors += 1
                    continue

    logging.info(f"Toplam alert satırı: {alert_count}")
    logging.info(f"Parse hataları: {parse_errors}")
    logging.info(f"Benzersiz flow (çift yön): {len(alerted_flows)}")

    return alerted_flows


def compute_metrics(flow_labels: dict, alerted_flows: set) -> dict:
    """Confusion matrix ve metrikleri hesaplar."""
    tp = fp = tn = fn = 0

    for flow_id, actual in flow_labels.items():
        predicted = 1 if flow_id in alerted_flows else 0

        if actual == 1 and predicted == 1:
            tp += 1
        elif actual == 0 and predicted == 0:
            tn += 1
        elif actual == 0 and predicted == 1:
            fp += 1
        elif actual == 1 and predicted == 0:
            fn += 1

    total = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': accuracy, 'precision': precision,
        'recall': recall, 'f1': f1, 'fpr': fpr, 'total': total,
    }


def main():
    parser = argparse.ArgumentParser(description="LSTM Inspector Confusion Matrix")
    parser.add_argument('--csv-dir', type=str, required=True,
                        help="CIC-IDS2017 CSV dizini")
    parser.add_argument('--alert-dir', type=str, required=True,
                        help="LSTM alert çıktı dizini")
    parser.add_argument('--output', type=str, default=None,
                        help="Sonuç dosyası yolu")
    args = parser.parse_args()

    csv_dir = Path(args.csv_dir)
    alert_dir = Path(args.alert_dir)

    # 1. Label'ları yükle
    logging.info("=" * 60)
    logging.info("CIC-IDS2017 Label Yükleme")
    logging.info("=" * 60)
    flow_labels = load_cicids_labels(csv_dir)
    if not flow_labels:
        logging.error("Label yüklenemedi!")
        return

    # 2. Alert'leri yükle
    logging.info("")
    logging.info("=" * 60)
    logging.info("LSTM Alert Yükleme")
    logging.info("=" * 60)
    alerted_flows = load_lstm_alerts(alert_dir)

    # 3. Confusion matrix
    logging.info("")
    logging.info("=" * 60)
    logging.info("Confusion Matrix")
    logging.info("=" * 60)
    m = compute_metrics(flow_labels, alerted_flows)

    result = f"""
{'=' * 60}
LSTM Inspector — CIC-IDS2017 Confusion Matrix
{'=' * 60}

                    Tahmin: Normal (0)    Tahmin: Atak (1)
Gerçek: Normal (0)  TN = {m['tn']:<18} FP = {m['fp']}
Gerçek: Atak (1)    FN = {m['fn']:<18} TP = {m['tp']}

{'─' * 60}
Toplam Flow:   {m['total']}
Accuracy:      {m['accuracy']:.4f}
Precision:     {m['precision']:.4f}
Recall (TPR):  {m['recall']:.4f}
F1-Score:      {m['f1']:.4f}
FPR:           {m['fpr']:.4f}
{'─' * 60}

Not: max_packets (100) eşiğine ulaşmayan kısa flow'lar
otomatik olarak Normal (0) tahmin edilmiştir.
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
