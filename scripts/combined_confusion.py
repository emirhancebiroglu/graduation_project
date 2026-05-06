#!/usr/bin/env python3
"""
combined_confusion.py — Combined Run Confusion Matrix
Bitirme Projesi: IDS Performans Karşılaştırma

Tek alert_csv.txt'ten GID/msg'ye göre 3 kaynağı ayırır:
  - GID=300 / "LSTM anomaly"      → LSTM Inspector
  - GID=301 / "XGBoost anomaly"   → XGBoost Inspector
  - Diğerleri                      → Community Rules

Üretilen matrisler:
  1) LSTM tek başına
  2) XGBoost tek başına
  3) Community Rules tek başına
  4) LSTM OR XGBoost   (ML Ensemble)
  5) LSTM OR Community (LSTM + Sig)
  6) XGB  OR Community (XGB  + Sig)
  7) Hepsi OR          (Full Ensemble)

Kullanım:
    python combined_confusion.py \\
        --alert-dir ~/bitirme/results/combined \\
        --csv-dir   ~/bitirme/data/raw/cicids2017 \\
        --output    ~/bitirme/results/combined/confusion_matrix.txt
"""

import pandas as pd
import numpy as np
import argparse
import logging
from pathlib import Path
from sklearn.metrics import confusion_matrix

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1,
             'tcp': 6, 'udp': 17, 'icmp': 1}

IP_MAP = {'192.168.10.51': '172.16.0.1'}


# ---------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------
def parse_ip_port(field: str):
    field = field.strip()
    last = field.rfind(':')
    if last == -1:
        return field, 0
    ip = field[:last]
    try:
        port = int(field[last + 1:])
    except ValueError:
        port = 0
    return ip, port


def valid_ip(ip):
    if not ip or pd.isna(ip):
        return False
    if ip.startswith(("224.", "239.")) or ip == "255.255.255.255":
        return False
    if ":" in ip:
        return False
    return True


def map_ip(ip):
    return IP_MAP.get(ip, ip)


def flow_ids_from_line(line: str):
    """alert_csv satırından hem yönlü + haritalanmış Flow ID set'i döndürür."""
    parts = line.split(',')
    if len(parts) < 8:
        return None
    try:
        proto_str  = parts[2].strip()
        src_ip, src_port = parse_ip_port(parts[6].strip())
        dst_ip, dst_port = parse_ip_port(parts[7].strip())

        if not valid_ip(src_ip) or not valid_ip(dst_ip):
            return None
        if src_port == 0 or dst_port == 0:
            return None

        proto = PROTO_MAP.get(proto_str, 0)
        si_m  = map_ip(src_ip)
        di_m  = map_ip(dst_ip)

        ids = {
            f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto}",
            f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}",
        }
        if si_m != src_ip or di_m != dst_ip:
            ids.add(f"{di_m}-{si_m}-{dst_port}-{src_port}-{proto}")
            ids.add(f"{si_m}-{di_m}-{src_port}-{dst_port}-{proto}")
        return ids
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------
# Alert parse: GID'e göre 3 ayrı set
# ---------------------------------------------------------------
def extract_flow_ids(alert_dir: Path):
    """
    Dönüş: (lstm_flows, xgb_flows, community_flows)
    Her biri benzersiz Flow ID set'i.
    """
    lstm_flows      = set()
    xgb_flows       = set()
    community_flows = set()

    stats = {'total': 0, 'lstm': 0, 'xgb': 0, 'community': 0, 'filtered': 0}

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue
        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
            continue

        logging.info(f"  Okunan: {subdir.name}/alert_csv.txt")

        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                stats['total'] += 1

                # 9. sütundaki GID:SID:Rev alanına göre ayır (300=LSTM, 301=XGBoost)
                # alert_csv: ts,pktnum,proto,svc,len,dir,src,dst,GID:SID:Rev,action
                _parts       = line.split(',')
                gid_field    = _parts[8].strip() if len(_parts) > 8 else ""
                is_lstm      = gid_field.startswith("300:")
                is_xgb       = gid_field.startswith("301:")
                is_community = not is_lstm and not is_xgb

                fids = flow_ids_from_line(line)
                if fids is None:
                    stats['filtered'] += 1
                    continue

                if is_lstm:
                    lstm_flows.update(fids)
                    stats['lstm'] += 1
                elif is_xgb:
                    xgb_flows.update(fids)
                    stats['xgb'] += 1
                else:
                    community_flows.update(fids)
                    stats['community'] += 1

    logging.info(f"Toplam alert: {stats['total']}")
    logging.info(f"  LSTM:      {stats['lstm']}")
    logging.info(f"  XGBoost:   {stats['xgb']}")
    logging.info(f"  Community: {stats['community']}")
    logging.info(f"  Filtrelenen: {stats['filtered']}")
    logging.info(f"Benzersiz Flow ID — LSTM:{len(lstm_flows)} "
                 f"XGB:{len(xgb_flows)} COM:{len(community_flows)}")

    return lstm_flows, xgb_flows, community_flows


# ---------------------------------------------------------------
# Confusion matrix hesaplama
# ---------------------------------------------------------------
def compute_metrics(y_true, y_pred):
    cm  = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp)    if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn)    if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0
    return dict(tp=tp, tn=tn, fp=fp, fn=fn,
                accuracy=accuracy, precision=precision,
                recall=recall, f1=f1, fpr=fpr, total=total)


def evaluate_all(csv_dir: Path,
                 lstm_flows, xgb_flows, community_flows):
    """7 kombinasyon için metrikleri hesaplar."""

    # Ensemble kombinasyonları
    ml_ensemble   = lstm_flows | xgb_flows
    lstm_plus_sig = lstm_flows | community_flows
    xgb_plus_sig  = xgb_flows  | community_flows
    full_ensemble = lstm_flows | xgb_flows | community_flows

    sets = {
        'LSTM':             lstm_flows,
        'XGBoost':          xgb_flows,
        'Community':        community_flows,
        'ML Ensemble':      ml_ensemble,
        'LSTM+Community':   lstm_plus_sig,
        'XGB+Community':    xgb_plus_sig,
        'Full Ensemble':    full_ensemble,
    }

    accumulators = {k: np.array([[0, 0], [0, 0]]) for k in sets}
    total_rows   = 0

    for csv_file in sorted(csv_dir.glob("*.csv")):
        logging.info(f"İşleniyor: {csv_file.name}")
        try:
            df = pd.read_csv(csv_file, low_memory=False,
                             on_bad_lines='skip',
                             encoding='utf-8', encoding_errors='replace')
        except Exception as e:
            logging.warning(f"Okunamadı: {csv_file.name} — {e}")
            continue

        df.columns = df.columns.str.strip()
        if 'Flow ID' not in df.columns or 'Label' not in df.columns:
            logging.warning(f"Flow ID/Label yok: {csv_file.name}")
            continue

        y_true = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
        total_rows += len(df)

        for name, flow_set in sets.items():
            y_pred = df['Flow ID'].isin(flow_set).astype(int)
            cm     = confusion_matrix(y_true, y_pred, labels=[0, 1])
            accumulators[name] += cm

    results = {}
    for name, cm in accumulators.items():
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        total     = tp + tn + fp + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0)
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0
        accuracy  = (tp + tn) / total if total > 0 else 0
        results[name] = dict(tp=int(tp), tn=int(tn), fp=int(fp), fn=int(fn),
                             accuracy=accuracy, precision=precision,
                             recall=recall, f1=f1, fpr=fpr, total=int(total))

    return results, total_rows


# ---------------------------------------------------------------
# Raporlama
# ---------------------------------------------------------------
def format_report(results: dict, total_rows: int) -> str:
    sep  = '=' * 72
    line = '─' * 72

    lines = [
        '',
        sep,
        'Combined Run — CIC-IDS2017 Confusion Matrix Karşılaştırması',
        'Yöntem: Flow ID eşleştirme + IP haritalama',
        f'Toplam Satır: {total_rows:,}',
        sep,
        '',
    ]

    # Özet tablo
    header = f"{'Yaklaşım':<22} {'Prec':>6} {'Recall':>7} {'F1':>7} {'FPR':>7} {'TP':>9} {'FP':>9} {'FN':>9}"
    lines += [header, line]

    order = ['LSTM', 'XGBoost', 'Community',
             'ML Ensemble', 'LSTM+Community', 'XGB+Community', 'Full Ensemble']

    for name in order:
        m = results[name]
        lines.append(
            f"{name:<22} {m['precision']:>6.4f} {m['recall']:>7.4f} "
            f"{m['f1']:>7.4f} {m['fpr']:>7.4f} "
            f"{m['tp']:>9,} {m['fp']:>9,} {m['fn']:>9,}"
        )

    lines += [line, '']

    # Her kombinasyon için detaylı matris
    for name in order:
        m = results[name]
        lines += [
            f"[ {name} ]",
            f"                    Tahmin: Normal (0)    Tahmin: Atak (1)",
            f"Gerçek: Normal (0)  TN = {m['tn']:<18,} FP = {m['fp']:,}",
            f"Gerçek: Atak (1)    FN = {m['fn']:<18,} TP = {m['tp']:,}",
            f"  Accuracy={m['accuracy']:.4f}  Precision={m['precision']:.4f}  "
            f"Recall={m['recall']:.4f}  F1={m['f1']:.4f}  FPR={m['fpr']:.4f}",
            '',
        ]

    lines.append(sep)
    return '\n'.join(lines)


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Combined Run confusion matrix — LSTM + XGB + Community')
    parser.add_argument('--alert-dir', required=True,
                        help='~/bitirme/results/combined')
    parser.add_argument('--csv-dir',   required=True,
                        help='~/bitirme/data/raw/cicids2017')
    parser.add_argument('--output',    default=None,
                        help='Çıktı dosyası (opsiyonel)')
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir).expanduser()
    csv_dir   = Path(args.csv_dir).expanduser()

    logging.info('=' * 60)
    logging.info('Combined Run — Flow ID Extraction')
    logging.info('=' * 60)
    logging.info(f'IP Map: {IP_MAP}')

    lstm_flows, xgb_flows, community_flows = extract_flow_ids(alert_dir)

    if not (lstm_flows or xgb_flows or community_flows):
        logging.error('Hiç Flow ID çıkarılamadı!')
        return

    logging.info('')
    logging.info('=' * 60)
    logging.info('Confusion Matrix Hesaplanıyor...')
    logging.info('=' * 60)

    results, total_rows = evaluate_all(
        csv_dir, lstm_flows, xgb_flows, community_flows)

    report = format_report(results, total_rows)
    print(report)

    if args.output:
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(report)
        logging.info(f'Kaydedildi: {out}')


if __name__ == '__main__':
    main()