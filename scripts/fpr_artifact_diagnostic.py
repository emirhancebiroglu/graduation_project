#!/usr/bin/env python3
"""
fpr_artifact_diagnostic.py — Aşama 0: FP Anatomisi

7,679 FP flow'u çek, şu soruları yanıtla:
1. Kaçı CICFlowMeter artifact? (çok kısa süre / 1 paket)
2. Hangi port/protokol dağılımı?
3. TCP flag profili nasıl? (SYN-only vs karma)
4. IAT dağılımı: DoS vs benign vs FP
5. Paket boyu dağılımı
6. swin dağılımı (bilinen FP driver)
7. Score distribution tahmini — kısa akış vs uzun akış FP oranı

Kullanım:
    python3 fpr_artifact_diagnostic.py
"""

import pandas as pd
import numpy as np
import json
import sys
from pathlib import Path
from collections import Counter

ALERT_FILE  = Path("/home/emirhan/bitirme/results/dos_inspector/Wednesday-workingHours/alert_csv.txt")
GT_CSV      = Path("/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv")
OUT_DIR     = Path("/home/emirhan/bitirme/results/fpr-opt-dos/phase0")
OUT_DIR.mkdir(parents=True, exist_ok=True)

IP_MAP = {'192.168.10.51': '172.16.0.1'}
PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}


# ── Helpers ─────────────────────────────────────────────────────────────────

def parse_ip_port(field):
    field = field.strip()
    i = field.rfind(':')
    if i == -1:
        return field, 0
    try:
        return field[:i], int(field[i+1:])
    except ValueError:
        return field[:i], 0


def valid_ip(ip):
    if not ip or pd.isna(ip):
        return False
    if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
        return False
    return ":" not in ip


def flow_ids_from_tuple(src_ip, dst_ip, src_port, dst_port, proto):
    ids = set()
    for s, d in [(src_ip, dst_ip), (dst_ip, src_ip)]:
        sp = src_port if s == src_ip else dst_port
        dp = dst_port if d == dst_ip else src_port
        ids.add(f"{s}-{d}-{sp}-{dp}-{proto}")
    return ids


# ── Step 1: Parse alerts → flow IDs ─────────────────────────────────────────

def load_alert_flow_ids():
    alert_flow_ids = set()
    n = 0
    with open(ALERT_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 8:
                continue
            try:
                proto_str = parts[2].strip()
                src_ip, src_port = parse_ip_port(parts[6])
                dst_ip, dst_port = parse_ip_port(parts[7])
                if not valid_ip(src_ip) or not valid_ip(dst_ip):
                    continue
                proto = PROTO_MAP.get(proto_str, 0)
                for ip in [src_ip, dst_ip]:
                    mapped = IP_MAP.get(ip, ip)
                    if mapped != ip:
                        src2 = mapped if ip == src_ip else src_ip
                        dst2 = mapped if ip == dst_ip else dst_ip
                        alert_flow_ids |= flow_ids_from_tuple(src2, dst2, src_port, dst_port, proto)
                alert_flow_ids |= flow_ids_from_tuple(src_ip, dst_ip, src_port, dst_port, proto)
                n += 1
            except Exception:
                continue
    print(f"Parsed {n} alerts → {len(alert_flow_ids)} unique flow IDs")
    return alert_flow_ids


# ── Step 2: Load ground truth CSV ───────────────────────────────────────────

def load_gt():
    print(f"Loading {GT_CSV.name} ...")
    df = pd.read_csv(GT_CSV, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    print(f"  Rows: {len(df):,}  Columns: {len(df.columns)}")
    return df


# ── Step 3: Tag TP / FP / TN / FN ──────────────────────────────────────────

def tag_flows(df, alert_ids):
    df = df.copy()
    df['alerted'] = df['Flow ID'].isin(alert_ids).astype(int)
    df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
    df['tag'] = 'TN'
    df.loc[(df['is_attack'] == 1) & (df['alerted'] == 1), 'tag'] = 'TP'
    df.loc[(df['is_attack'] == 0) & (df['alerted'] == 1), 'tag'] = 'FP'
    df.loc[(df['is_attack'] == 1) & (df['alerted'] == 0), 'tag'] = 'FN'
    counts = df['tag'].value_counts().to_dict()
    print(f"\nConfusion: {counts}")
    tp = counts.get('TP', 0)
    fp = counts.get('FP', 0)
    tn = counts.get('TN', 0)
    fn = counts.get('FN', 0)
    total_neg = fp + tn
    fpr = fp / total_neg if total_neg > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    print(f"  FPR={fpr:.4f}  Recall={recall:.4f}")
    return df


# ── Step 4: Artifact analysis ────────────────────────────────────────────────

def analyze_artifacts(fp_df):
    """CICFlowMeter flow split artifact heuristics"""
    results = {}

    total_fp = len(fp_df)
    results['total_fp'] = int(total_fp)

    # Heuristic 1: ultra-short duration (< 10ms) AND low packet count
    col_dur  = 'Flow Duration'       # microseconds in CIC CSV
    col_fwd  = 'Total Fwd Packets'
    col_bwd  = 'Total Backward Packets'

    if col_dur in fp_df.columns and col_fwd in fp_df.columns:
        fp_df[col_dur] = pd.to_numeric(fp_df[col_dur], errors='coerce').fillna(0)
        fp_df[col_fwd] = pd.to_numeric(fp_df[col_fwd], errors='coerce').fillna(0)
        fp_df[col_bwd] = pd.to_numeric(fp_df[col_bwd], errors='coerce').fillna(0)

        fp_df['total_pkts'] = fp_df[col_fwd] + fp_df[col_bwd]

        # CIC duration unit: microseconds
        short_dur  = fp_df[col_dur] < 10_000        # < 10ms
        one_pkt    = fp_df['total_pkts'] <= 1
        two_pkt    = fp_df['total_pkts'] <= 2

        art1 = (short_dur & one_pkt).sum()
        art2 = (short_dur & two_pkt).sum()
        art3 = one_pkt.sum()
        art4 = two_pkt.sum()
        art5 = short_dur.sum()

        results['artifact_short_dur_1pkt']  = int(art1)
        results['artifact_short_dur_2pkt']  = int(art2)
        results['artifact_1pkt_total']      = int(art3)
        results['artifact_2pkt_total']      = int(art4)
        results['artifact_short_dur_total'] = int(art5)

        results['artifact_pct_strict']  = round(100 * art1 / total_fp, 1)   # <10ms + 1pkt
        results['artifact_pct_loose']   = round(100 * art5 / total_fp, 1)   # <10ms only

        print(f"\n── Artifact Analysis ──────────────────────────")
        print(f"  Total FP:                 {total_fp:>6,}")
        print(f"  <10ms AND ≤1 pkt:         {art1:>6,}  ({results['artifact_pct_strict']:.1f}%) ← strict artifact")
        print(f"  <10ms AND ≤2 pkt:         {art2:>6,}  ({100*art2/total_fp:.1f}%)")
        print(f"  ≤1 pkt (any duration):    {art3:>6,}  ({100*art3/total_fp:.1f}%)")
        print(f"  ≤2 pkt (any duration):    {art4:>6,}  ({100*art4/total_fp:.1f}%)")
        print(f"  <10ms (any pkt count):    {art5:>6,}  ({results['artifact_pct_loose']:.1f}%)")
    else:
        print(f"  WARNING: duration/packet columns missing, skipping artifact heuristic")

    return results


# ── Step 5: Port distribution ────────────────────────────────────────────────

def analyze_ports(fp_df, tp_df, tn_df):
    print(f"\n── FP Port Distribution (Dst Port) ────────────────")
    if 'Destination Port' in fp_df.columns:
        fp_ports = pd.to_numeric(fp_df['Destination Port'], errors='coerce')
        top = fp_ports.value_counts().head(15)
        for port, cnt in top.items():
            print(f"  Port {int(port):>6}: {cnt:>5} FPs  ({100*cnt/len(fp_df):.1f}%)")
    return {}


# ── Step 6: TCP flag profile ──────────────────────────────────────────────────

def analyze_flags(fp_df, tp_df, tn_df):
    print(f"\n── TCP Flag Profile ────────────────────────────────")
    results = {}

    flag_cols = {
        'SYN Flag Count': 'syn',
        'FIN Flag Count': 'fin',
        'RST Flag Count': 'rst',
        'ACK Flag Count': 'ack',
        'PSH Flag Count': 'psh',
    }

    for group_name, group_df in [('FP', fp_df), ('TP', tp_df), ('TN', tn_df)]:
        row = {}
        for col, short in flag_cols.items():
            if col in group_df.columns:
                vals = pd.to_numeric(group_df[col], errors='coerce').fillna(0)
                row[short] = round(vals.mean(), 3)
        results[group_name] = row
        flags_str = '  '.join(f"{k}={v:.2f}" for k, v in row.items())
        print(f"  {group_name:>3}: {flags_str}")

    # SYN-only ratio (syn>0, fin=0, rst=0, ack=0)
    for group_name, group_df in [('FP', fp_df), ('TP', tp_df)]:
        if all(c in group_df.columns for c in ['SYN Flag Count', 'FIN Flag Count', 'RST Flag Count', 'ACK Flag Count']):
            syn  = pd.to_numeric(group_df['SYN Flag Count'], errors='coerce').fillna(0)
            fin  = pd.to_numeric(group_df['FIN Flag Count'], errors='coerce').fillna(0)
            rst  = pd.to_numeric(group_df['RST Flag Count'], errors='coerce').fillna(0)
            ack  = pd.to_numeric(group_df['ACK Flag Count'], errors='coerce').fillna(0)
            syn_only = ((syn > 0) & (fin == 0) & (rst == 0) & (ack == 0)).mean()
            print(f"  {group_name:>3} SYN-only ratio: {syn_only:.3f}")
            results[f'{group_name}_syn_only_ratio'] = round(float(syn_only), 4)

    return results


# ── Step 7: IAT analysis ──────────────────────────────────────────────────────

def analyze_iat(fp_df, tp_df, tn_df):
    print(f"\n── IAT Analysis (Flow IAT Mean, microseconds) ──────")
    results = {}
    col = 'Flow IAT Mean'
    if col not in fp_df.columns:
        print("  Column missing")
        return results

    for name, df in [('FP', fp_df), ('TP', tp_df), ('TN', tn_df)]:
        vals = pd.to_numeric(df[col], errors='coerce').dropna()
        vals = vals[vals >= 0]
        p25, p50, p75 = np.percentile(vals, [25, 50, 75])
        print(f"  {name:>3}: p25={p25:>10,.0f}  p50={p50:>10,.0f}  p75={p75:>10,.0f}  mean={vals.mean():>10,.0f}")
        results[name] = {'p25': float(p25), 'p50': float(p50), 'p75': float(p75), 'mean': float(vals.mean())}

    return results


# ── Step 8: swin analysis ────────────────────────────────────────────────────

def analyze_swin(fp_df, tp_df, tn_df):
    print(f"\n── Init Window Forward (swin) Analysis ────────────")
    results = {}
    col = 'Init_Win_bytes_forward'
    if col not in fp_df.columns:
        print("  Column missing")
        return results

    for name, df in [('FP', fp_df), ('TP', tp_df), ('TN', tn_df)]:
        vals = pd.to_numeric(df[col], errors='coerce').dropna()
        p25, p50, p75 = np.percentile(vals, [25, 50, 75])
        print(f"  {name:>3}: p25={p25:>8.0f}  p50={p50:>8.0f}  p75={p75:>8.0f}  mean={vals.mean():>8.1f}")
        # Bands
        band_small  = (vals >= 0)   & (vals < 100)
        band_mid    = (vals >= 100) & (vals < 500)
        band_large  = (vals >= 500)
        print(f"       swin<100={band_small.mean():.2f}  swin[100-500]={band_mid.mean():.2f}  swin>=500={band_large.mean():.2f}")
        results[name] = {'p50': float(p50), 'mean': float(vals.mean())}

    return results


# ── Step 9: Feature separability for candidate new features ─────────────────

def analyze_separability(fp_df, tp_df):
    """
    Candidate FPR-v3 features: do they separate FP from TP?
    Cohen's d (effect size) for each
    """
    print(f"\n── Feature Separability: FP vs TP (Cohen's d) ──────")
    candidates = [
        'SYN Flag Count', 'FIN Flag Count', 'RST Flag Count', 'ACK Flag Count',
        'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Mean', 'Bwd IAT Mean',
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
        'Packet Length Variance', 'Total Fwd Packets', 'Total Backward Packets',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'Flow Duration',
    ]
    results = {}
    rows = []
    for col in candidates:
        if col not in fp_df.columns:
            continue
        a = pd.to_numeric(fp_df[col], errors='coerce').dropna()
        b = pd.to_numeric(tp_df[col], errors='coerce').dropna()
        if len(a) < 10 or len(b) < 10:
            continue
        pooled_std = np.sqrt((a.std()**2 + b.std()**2) / 2)
        if pooled_std == 0:
            continue
        d = abs(a.mean() - b.mean()) / pooled_std
        rows.append((d, col, a.mean(), b.mean()))
        results[col] = round(float(d), 3)

    rows.sort(reverse=True)
    print(f"  {'Feature':<35} {'|d|':>6}  FP_mean={'':<12} TP_mean")
    for d, col, fp_mean, tp_mean in rows:
        marker = ' ← HIGH' if d > 1.0 else (' ← MED' if d > 0.5 else '')
        print(f"  {col:<35} {d:>6.3f}  {fp_mean:>14.1f}  {tp_mean:>14.1f}{marker}")

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  FPR Artifact Diagnostic — Aşama 0")
    print("=" * 60)

    alert_ids = load_alert_flow_ids()
    df = load_gt()
    df = tag_flows(df, alert_ids)

    fp_df = df[df['tag'] == 'FP'].copy()
    tp_df = df[df['tag'] == 'TP'].copy()
    tn_df = df[df['tag'] == 'TN'].copy()
    fn_df = df[df['tag'] == 'FN'].copy()

    print(f"\nFP={len(fp_df):,}  TP={len(tp_df):,}  TN={len(tn_df):,}  FN={len(fn_df):,}")

    report = {}
    report['confusion'] = {
        'TP': len(tp_df), 'FP': len(fp_df),
        'TN': len(tn_df), 'FN': len(fn_df),
        'FPR': round(len(fp_df) / (len(fp_df) + len(tn_df)), 4),
        'Recall': round(len(tp_df) / (len(tp_df) + len(fn_df)), 4),
    }

    report['artifacts']    = analyze_artifacts(fp_df)
    analyze_ports(fp_df, tp_df, tn_df)
    report['tcp_flags']    = analyze_flags(fp_df, tp_df, tn_df)
    report['iat']          = analyze_iat(fp_df, tp_df, tn_df)
    report['swin']         = analyze_swin(fp_df, tp_df, tn_df)
    report['separability'] = analyze_separability(fp_df, tp_df)

    # Save FP flows for further analysis
    fp_out = OUT_DIR / "fp_flows.csv"
    fp_df.to_csv(fp_out, index=False)
    print(f"\nFP flows saved: {fp_out}")

    report_out = OUT_DIR / "diagnostic_report.json"
    with open(report_out, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved:   {report_out}")

    # Print summary decision
    art_pct = report['artifacts'].get('artifact_pct_strict', 0)
    print(f"\n{'='*60}")
    print(f"  ÖZET")
    print(f"{'='*60}")
    print(f"  Total FP:          {len(fp_df):,}")
    print(f"  Artifact (strict): {report['artifacts'].get('artifact_short_dur_1pkt',0):,}  ({art_pct:.1f}%)")
    if art_pct >= 30:
        print(f"  → YÜKSEK artifact oranı — flow merging öncelikli")
    elif art_pct >= 15:
        print(f"  → ORTA artifact oranı — feature extension + artifact fix birlikte")
    else:
        print(f"  → DÜŞÜK artifact oranı — feature extension ana strateji")

    top_sep = sorted(report['separability'].items(), key=lambda x: -x[1])[:5]
    print(f"\n  Top-5 separating features (FP vs TP):")
    for feat, d in top_sep:
        print(f"    {feat:<35} d={d:.3f}")


if __name__ == "__main__":
    main()
