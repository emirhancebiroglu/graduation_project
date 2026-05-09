#!/usr/bin/env python3
"""
dos_specialist_flowid_confusion.py — DoS Specialist confusion matrix
Bitirme Projesi — DoS Pilot Faz 5

xgb_flowid_confusion.py'den türetilmiştir.
Fark:
  - GID=302 alert'leri için ayrıştırma
  - DoS-spesifik sınıf etiketleri (Hulk, GoldenEye ayrı gösterilir)
  - --dos-only modu: sadece DoS flow'larına confusion matrix
  - Offline metriklerle karşılaştırmalı tablo

Kullanım:
    python scripts/dos_specialist_flowid_confusion.py \\
        --alert-dir ~/bitirme/results/dos_specialist \\
        --csv-dir   ~/bitirme/data/raw/cicids2017 \\
        --output    ~/bitirme/results/dos_specialist/confusion_matrix.txt

    # Sadece DoS-containing günler + per-attack-type breakdown:
    python scripts/dos_specialist_flowid_confusion.py \\
        --alert-dir ~/bitirme/results/dos_specialist \\
        --csv-dir   ~/bitirme/data/raw/cicids2017 \\
        --dos-only \\
        --output    ~/bitirme/results/dos_specialist/confusion_matrix.txt
"""

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# ── Sabitler ──────────────────────────────────────────────────────────────────
PROTO_MAP = {
    'TCP': 6, 'UDP': 17, 'ICMP': 1,
    'tcp': 6, 'udp': 17, 'icmp': 1,
}

IP_MAP = {
    '192.168.10.51': '172.16.0.1',
}

# DoS Specialist'in pozitif sınıfı (binary)
DOS_LABELS = {'DoS Hulk', 'DoS GoldenEye'}

# Per-attack breakdown için tüm bilinen saldırı etiketleri
ALL_ATTACK_LABELS = {
    'DoS Hulk', 'DoS GoldenEye',
    'DoS slowloris', 'DoS Slowhttptest',
    'DDoS', 'PortScan',
    'FTP-Patator', 'SSH-Patator',
    'Bot', 'Web Attack – Brute Force',
    'Web Attack – XSS', 'Web Attack – Sql Injection',
    'Heartbleed', 'Infiltration',
}

# Offline referans metrikleri (Faz 2 sonuçları)
OFFLINE_METRICS = {
    'mp_2':  {'F1': 0.9997, 'Recall': 0.9999, 'FPR': 0.0004, 'Threshold': 0.50},
    'mp_4':  {'F1': 0.9997, 'Recall': 0.9998, 'FPR': 0.0004, 'Threshold': 0.45},
    'mp_8':  {'F1': 0.9996, 'Recall': 0.9998, 'FPR': 0.0004, 'Threshold': 0.75},
    'full':  {'F1': 0.9997, 'Recall': 0.9999, 'FPR': 0.0005, 'Threshold': 0.50},
}
DEPLOYED_VARIANT = 'mp_2'


# ── Yardımcı fonksiyonlar ─────────────────────────────────────────────────────
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
    if ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
        return False
    if ':' in ip:
        return False
    return True


def map_ip(ip):
    return IP_MAP.get(ip, ip)


# ── Alert parsing ─────────────────────────────────────────────────────────────
def extract_flow_ids_from_alerts(alert_dir: Path) -> set:
    """
    alert_csv.txt dosyalarından GID=302 alertlerini parse et.
    Her alert için çift yönlü Flow ID seti döndür.
    """
    flow_ids   = set()
    total      = 0
    filtered   = 0
    gid302     = 0

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue
        alert_file = subdir / 'alert_csv.txt'
        if not alert_file.exists():
            continue

        sub_total = sub_clean = 0
        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                total += 1
                sub_total += 1
                parts = line.split(',')
                if len(parts) < 9:
                    continue

                # GID kontrolü: parts[8] = "GID:SID:Rev" formatı
                # Sadece GID=302 (dos_specialist) alertlerini al
                sig_field = parts[8].strip()
                if not sig_field.startswith('302:'):
                    continue
                gid302 += 1

                try:
                    proto_str = parts[2].strip()
                    src_ip, src_port = parse_ip_port(parts[6].strip())
                    dst_ip, dst_port = parse_ip_port(parts[7].strip())

                    if not valid_ip(src_ip) or not valid_ip(dst_ip):
                        filtered += 1
                        continue
                    if src_port == 0 or dst_port == 0:
                        filtered += 1
                        continue

                    proto_num = PROTO_MAP.get(proto_str, 0)
                    src_m = map_ip(src_ip)
                    dst_m = map_ip(dst_ip)

                    # Çift yönlü + haritalanmış IP
                    for s, d, sp, dp in [
                        (src_ip, dst_ip, src_port, dst_port),
                        (dst_ip, src_ip, dst_port, src_port),
                        (src_m,  dst_m,  src_port, dst_port),
                        (dst_m,  src_m,  dst_port, src_port),
                    ]:
                        flow_ids.add(f'{s}-{d}-{sp}-{dp}-{proto_num}')

                    sub_clean += 1
                except (IndexError, ValueError):
                    continue

        logging.info(f'  {subdir.name}: {sub_total} alert, {sub_clean} GID=302 temiz')

    logging.info(f'Toplam alert: {total} | GID=302: {gid302} | Filtrelenen: {filtered}')
    logging.info(f'Benzersiz Flow ID: {len(flow_ids)}')
    return flow_ids


# ── Confusion matrix ──────────────────────────────────────────────────────────
def compute_confusion_matrix(
    csv_dir: Path,
    alert_flows: set,
    dos_only: bool = False
) -> dict:
    """
    CIC-IDS2017 CSV'leri ile alert flow ID'lerini karşılaştır.

    dos_only=True: sadece DoS Hulk + GoldenEye flow'larını değerlendir
                   (diğer saldırılar ve BENIGN hariç)
    dos_only=False: tüm flow'lar (binary: any_attack vs BENIGN)
    """
    csv_files = sorted(csv_dir.glob('*.csv'))
    cm_total  = np.zeros((2, 2), dtype=np.int64)
    total_rows = 0

    # Per-attack type breakdown (DOS_LABELS + diğerleri ayrı)
    per_attack: dict[str, dict] = {}

    for csv_file in csv_files:
        logging.info(f'İşleniyor: {csv_file.name}')
        try:
            df = pd.read_csv(csv_file, low_memory=False,
                             on_bad_lines='skip',
                             encoding='utf-8', encoding_errors='replace')
        except Exception as e:
            logging.warning(f'Okunamadı: {csv_file.name} — {e}')
            continue

        df.columns = df.columns.str.strip()
        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            logging.warning(f'  Flow ID veya Label kolonu yok: {csv_file.name}')
            continue

        df['Label'] = df['Label'].str.strip()
        df['Predicted'] = df['Flow ID'].isin(alert_flows).astype(int)

        if dos_only:
            # Sadece BENIGN + DoS Hulk + GoldenEye satırları
            mask = df['Label'].isin(DOS_LABELS | {'BENIGN'})
            df = df[mask].copy()

        df['Label_binary'] = df['Label'].apply(
            lambda x: 0 if x == 'BENIGN' else 1
        )

        cm = confusion_matrix(df['Label_binary'], df['Predicted'], labels=[0, 1])
        cm_total += cm
        total_rows += len(df)

        # Per-attack breakdown
        for label in ALL_ATTACK_LABELS:
            sub = df[df['Label'] == label]
            if len(sub) == 0:
                continue
            if label not in per_attack:
                per_attack[label] = {'total': 0, 'tp': 0, 'fn': 0, 'fp': 0}
            per_attack[label]['total'] += len(sub)
            per_attack[label]['tp']    += ((sub['Label_binary'] == 1) & (sub['Predicted'] == 1)).sum()
            per_attack[label]['fn']    += ((sub['Label_binary'] == 1) & (sub['Predicted'] == 0)).sum()

    tn, fp, fn, tp = (cm_total[0][0], cm_total[0][1],
                      cm_total[1][0], cm_total[1][1])
    total   = int(tp + tn + fp + fn)
    acc     = (tp + tn) / total if total > 0 else 0.0
    prec    = tp / (tp + fp)    if (tp + fp) > 0 else 0.0
    rec     = tp / (tp + fn)    if (tp + fn) > 0 else 0.0
    f1      = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr_val = fp / (fp + tn)    if (fp + tn) > 0 else 0.0

    return {
        'tp': int(tp), 'tn': int(tn), 'fp': int(fp), 'fn': int(fn),
        'accuracy': acc, 'precision': prec, 'recall': rec,
        'f1': f1, 'fpr': fpr_val,
        'total': total_rows,
        'per_attack': per_attack,
    }


# ── Rapor üretimi ─────────────────────────────────────────────────────────────
def format_report(m: dict, dos_only: bool) -> str:
    offline = OFFLINE_METRICS[DEPLOYED_VARIANT]
    mode_str = 'DoS-Only (Hulk + GoldenEye vs BENIGN)' if dos_only else 'Binary (Any Attack vs BENIGN)'

    # Offline → Real-time delta
    f1_delta  = m['f1']      - offline['F1']
    rec_delta = m['recall']  - offline['Recall']
    fpr_delta = m['fpr']     - offline['FPR']

    lines = [
        '=' * 65,
        ' DoS Specialist Inspector — CIC-IDS2017 Real-time Confusion Matrix',
        f' Varyant: {DEPLOYED_VARIANT} | Threshold: {offline["Threshold"]:.2f} | Mod: {mode_str}',
        '=' * 65,
        '',
        f'                     Tahmin: Normal (0)   Tahmin: DoS (1)',
        f'Gerçek: Normal (0)   TN = {m["tn"]:<18} FP = {m["fp"]}',
        f'Gerçek: Saldırı (1)  FN = {m["fn"]:<18} TP = {m["tp"]}',
        '',
        '─' * 65,
        f'Toplam Flow:   {m["total"]}',
        f'Accuracy:      {m["accuracy"]:.4f}',
        f'Precision:     {m["precision"]:.4f}',
        f'Recall (TPR):  {m["recall"]:.4f}',
        f'F1-Score:      {m["f1"]:.4f}',
        f'FPR:           {m["fpr"]:.4f}',
        '─' * 65,
        '',
        '── Offline vs Real-time Karşılaştırma ──────────────────────────',
        f'{"Metrik":<15} {"Offline":>12} {"Real-time":>12} {"Delta":>10}',
        '─' * 52,
        f'{"F1":<15} {offline["F1"]:>12.4f} {m["f1"]:>12.4f} {f1_delta:>+10.4f}',
        f'{"Recall":<15} {offline["Recall"]:>12.4f} {m["recall"]:>12.4f} {rec_delta:>+10.4f}',
        f'{"FPR":<15} {offline["FPR"]:>12.4f} {m["fpr"]:>12.4f} {fpr_delta:>+10.4f}',
        '─' * 52,
        '',
    ]

    # Per-attack breakdown
    if m['per_attack']:
        lines += [
            '── Per-Attack Recall ────────────────────────────────────────────',
            f'{"Saldırı Türü":<35} {"Total":>8} {"TP":>8} {"FN":>8} {"Recall":>8}',
            '─' * 65,
        ]
        # DoS targetları en üste
        for label in ['DoS Hulk', 'DoS GoldenEye']:
            if label in m['per_attack']:
                a = m['per_attack'][label]
                t = a['total']
                r = a['tp'] / t if t > 0 else 0.0
                lines.append(
                    f'{label:<35} {t:>8} {a["tp"]:>8} {a["fn"]:>8} {r:>8.4f}  ← target'
                )
        # Diğerleri
        for label, a in sorted(m['per_attack'].items()):
            if label in ('DoS Hulk', 'DoS GoldenEye'):
                continue
            t = a['total']
            r = a['tp'] / t if t > 0 else 0.0
            lines.append(f'{label:<35} {t:>8} {a["tp"]:>8} {a["fn"]:>8} {r:>8.4f}')
        lines += ['─' * 65, '']

    # Pilot başarı kararı
    pilot_f1  = m['f1']  >= 0.93
    pilot_rec = m['recall'] >= 0.90
    pilot_fpr = m['fpr'] <= 0.01
    pilot_ok  = pilot_f1 and pilot_rec and pilot_fpr

    lines += [
        '── Pilot Başarı Kriteri (Real-time) ─────────────────────────────',
        f'  F1  ≥ 0.93   : {"✅" if pilot_f1  else "❌"}  ({m["f1"]:.4f})',
        f'  Recall ≥ 0.90: {"✅" if pilot_rec else "❌"}  ({m["recall"]:.4f})',
        f'  FPR ≤ 0.01   : {"✅" if pilot_fpr else "❌"}  ({m["fpr"]:.4f})',
        '',
        f'  PILOT SONUCU: {"✅ BAŞARILI — DDoS/BruteForce specialist\'lere geç" if pilot_ok else "❌ BAŞARISIZ — root cause analizi gerekli"}',
        '=' * 65,
    ]

    return '\n'.join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='DoS Specialist confusion matrix (GID=302)')
    parser.add_argument('--alert-dir', required=True,
                        help='results/dos_specialist/')
    parser.add_argument('--csv-dir',   required=True,
                        help='data/raw/cicids2017/')
    parser.add_argument('--output',    default=None,
                        help='Çıktı dosyası (.txt)')
    parser.add_argument('--dos-only',  action='store_true',
                        help='Sadece DoS Hulk + GoldenEye vs BENIGN değerlendir')
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir)
    csv_dir   = Path(args.csv_dir)

    logging.info('=' * 65)
    logging.info('DoS Specialist Alert → Flow ID Çıkarımı')
    logging.info('=' * 65)
    logging.info(f'IP Haritalama: {IP_MAP}')
    alert_flows = extract_flow_ids_from_alerts(alert_dir)

    if not alert_flows:
        logging.error('Hiç GID=302 Flow ID çıkarılamadı — alert_csv.txt kontrolü gerekli.')
        return

    logging.info('')
    logging.info('=' * 65)
    logging.info('Confusion Matrix Hesaplanıyor...')
    logging.info('=' * 65)
    m = compute_confusion_matrix(csv_dir, alert_flows, dos_only=args.dos_only)

    report = format_report(m, dos_only=args.dos_only)
    print('\n' + report)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(report)
        logging.info(f'Kaydedildi: {out}')


if __name__ == '__main__':
    main()