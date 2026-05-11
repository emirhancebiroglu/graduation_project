#!/usr/bin/env python3
"""
xgb_flowid_confusion_wednesday_v2.py — XGBoost Inspector confusion matrix (Wednesday only)

v2 change vs v1: only FORWARD-direction alert FIDs are used for matching.
  forward_fids = {src_ip-dst_ip-src_port-dst_port-proto,
                  src_m-dst_m-src_port-dst_port-proto}

Reverse-direction FIDs (dst→src) are discarded so that the server-reply CSV row
for an attack flow is NOT double-counted as a TP (or a matching BENIGN reply as FP).

Everything else — IP map, valid_ip, proto map, output format — is identical to v1.

Kullanım:
    python xgb_flowid_confusion_wednesday_v2.py \
        --alert-dir ~/bitirme/results/xgboost/sweep_threshold/t090_mp2 \
        --csv-dir   ~/bitirme/data/raw/cicids2017 \
        --output    ~/bitirme/results/xgboost/confusion_matrix_wednesday_v2_t090.txt
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

IP_MAP = {
    '192.168.10.51': '172.16.0.1',
}

WEDNESDAY_ALERT_SUBDIR = 'Wednesday-workingHours'
WEDNESDAY_CSV_NAME     = 'Wednesday-workingHours.pcap_ISCX.csv'


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
    """
    v2: returns only FORWARD-direction FIDs.

    For each alert row the inspector fired on src_ip:src_port → dst_ip:dst_port:
      fid_fwd       = src_ip-dst_ip-src_port-dst_port-proto
      fid_fwd_mapped = src_m-dst_m-src_port-dst_port-proto   (IP-mapped variant)

    Reverse FIDs (dst→src) are intentionally excluded so that the server-reply
    CSV row is not mistakenly matched as a TP/FP.
    """
    forward_fids = set()
    total_alerts = 0
    filtered_out = 0
    found = False

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue

        if subdir.name != WEDNESDAY_ALERT_SUBDIR:
            logging.info(f"  Atlanıyor (Wednesday değil): {subdir.name}")
            continue

        found = True
        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
            logging.warning(f"  alert_csv.txt bulunamadı: {subdir}")
            continue

        subdir_alerts = 0
        subdir_clean  = 0

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
                    src_m = map_ip(src_ip)
                    dst_m = map_ip(dst_ip)

                    # v2: FORWARD only — src→dst direction (the direction the alert fired on)
                    fid_fwd        = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                    fid_fwd_mapped = f"{src_m}-{dst_m}-{src_port}-{dst_port}-{proto_num}"

                    forward_fids.add(fid_fwd)
                    forward_fids.add(fid_fwd_mapped)

                    subdir_clean += 1
                except (IndexError, ValueError):
                    continue

        logging.info(f"  {subdir.name}: {subdir_alerts} alert, {subdir_clean} temiz")

    if not found:
        logging.error(
            f"'{WEDNESDAY_ALERT_SUBDIR}' dizini bulunamadı! "
            f"--alert-dir içindeki dizin isimlerini kontrol edin."
        )

    logging.info(f"Toplam alert: {total_alerts}")
    logging.info(f"Filtrelenen: {filtered_out}")
    logging.info(f"Temiz alert: {total_alerts - filtered_out}")
    logging.info(f"Benzersiz Forward FID (v2, yalnızca src→dst): {len(forward_fids)}")
    return forward_fids


def compute_confusion_matrix(csv_dir: Path, alert_flows: set):
    csv_file = csv_dir / WEDNESDAY_CSV_NAME
    cm_total = np.array([[0, 0], [0, 0]])
    total_rows = 0

    if not csv_file.exists():
        logging.error(f"Wednesday CSV bulunamadı: {csv_file}")
        return {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
                'accuracy': 0, 'precision': 0, 'recall': 0,
                'f1': 0, 'fpr': 0, 'total': 0}

    logging.info(f"İşleniyor: {csv_file.name}")
    try:
        df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip',
                         encoding='utf-8', encoding_errors='replace')
    except Exception as e:
        logging.error(f"Okunamadı: {csv_file.name} — {e}")
        return {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
                'accuracy': 0, 'precision': 0, 'recall': 0,
                'f1': 0, 'fpr': 0, 'total': 0}

    df.columns = df.columns.str.strip()
    if 'Flow ID' not in df.columns or 'Label' not in df.columns:
        logging.error("CSV'de 'Flow ID' veya 'Label' sütunu yok!")
        return {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
                'accuracy': 0, 'precision': 0, 'recall': 0,
                'f1': 0, 'fpr': 0, 'total': 0}

    df['Predicted']    = df['Flow ID'].isin(alert_flows).astype(int)
    df['Label_binary'] = df['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)

    attack_counts = df[df['Label_binary'] == 1]['Label'].value_counts()
    if not attack_counts.empty:
        logging.info("  Saldırı tipi dağılımı:")
        for label, count in attack_counts.items():
            logging.info(f"    {label}: {count}")

    cm = confusion_matrix(df['Label_binary'], df['Predicted'], labels=[0, 1])
    cm_total  += cm
    total_rows += len(df)

    file_tp = ((df['Label_binary'] == 1) & (df['Predicted'] == 1)).sum()
    file_fp = ((df['Label_binary'] == 0) & (df['Predicted'] == 1)).sum()
    file_attacks = (df['Label_binary'] == 1).sum()
    logging.info(f"  Toplam satır: {len(df)}, Saldırı: {file_attacks}, TP: {file_tp}, FP: {file_fp}")

    tn, fp, fn, tp = cm_total[0][0], cm_total[0][1], cm_total[1][0], cm_total[1][1]
    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp)    if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn)    if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn)    if (fp + tn) > 0 else 0

    return {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
            'accuracy': accuracy, 'precision': precision,
            'recall': recall, 'f1': f1, 'fpr': fpr, 'total': total_rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert-dir', type=str, required=True)
    parser.add_argument('--csv-dir',   type=str, required=True)
    parser.add_argument('--output',    type=str, default=None)
    parser.add_argument('--label',     type=str, default='')
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir).expanduser()
    csv_dir   = Path(args.csv_dir).expanduser()

    logging.info("=" * 60)
    logging.info("XGBoost Alert → Flow ID v2 (forward-only, Wednesday)")
    logging.info("=" * 60)
    logging.info(f"Alert dizini: {alert_dir / WEDNESDAY_ALERT_SUBDIR}")
    logging.info(f"CSV dosyası:  {csv_dir / WEDNESDAY_CSV_NAME}")
    logging.info(f"IP Haritalama: {IP_MAP}")
    logging.info("v2 değişikliği: Yalnızca ileri yön (src→dst) FID eşleşmesi")

    alert_flows = extract_flow_ids_from_alerts(alert_dir)
    if not alert_flows:
        logging.error("Hiç Forward FID çıkarılamadı!")
        return

    m = compute_confusion_matrix(csv_dir, alert_flows)

    label_line = f"  Run: {args.label}" if args.label else ""
    result = f"""
{'=' * 60}
XGBoost Inspector — Wednesday Confusion Matrix (v2: forward-only)
{label_line}
Kapsam:  Wednesday-workingHours.pcap_ISCX.csv
Yöntem:  Flow ID forward-only + IP haritalama (v2)
IP Map:  192.168.10.51 → 172.16.0.1
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
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(result)
        logging.info(f"Kaydedildi: {out}")


if __name__ == "__main__":
    main()
