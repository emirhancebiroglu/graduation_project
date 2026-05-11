#!/usr/bin/env python3
"""
analyze_swin_fps.py — swin diagnostic on the 8,500 stubborn FPs at t=0.90, mp=2.

Investigates whether swin > 1020 (the LSTM clamp threshold) is concentrated
in the FP cohort, which would justify adding a swin clamp to the XGBoost C++ path.

Output: results/xgboost/fp_analysis/stubborn_fp_swin_analysis.txt
"""

from pathlib import Path
import pandas as pd
import numpy as np

REPO       = Path(__file__).resolve().parent.parent
ALERT_FILE = REPO / "results/xgboost/sweep_threshold/t090_mp2/Wednesday-workingHours/alert_csv.txt"
CSV_FILE   = REPO / "data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
OUT_FILE   = REPO / "results/xgboost/fp_analysis/stubborn_fp_swin_analysis.txt"

SWIN_CLAMP  = 1020   # LSTM path clamp value; XGBoost path currently has NO clamp
TN_SAMPLE   = 50_000

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP    = {'192.168.10.51': '172.16.0.1'}


def parse_ip_port(field):
    field = field.strip()
    lc = field.rfind(':')
    if lc == -1:
        return field, 0
    try:
        return field[:lc], int(field[lc + 1:])
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


def pct_stats(series, label, lines):
    s = series.dropna()
    lines.append(f"  {label}  n={len(s):,}")
    lines.append(f"    min={s.min():.1f}  p25={s.quantile(0.25):.1f}  "
                 f"median={s.median():.1f}  p75={s.quantile(0.75):.1f}  "
                 f"max={s.max():.1f}  mean={s.mean():.1f}")


def histogram(series, buckets, lines):
    """buckets: list of (label, lo, hi) where hi is exclusive (None = open)."""
    total = len(series)
    rows = []
    for label, lo, hi in buckets:
        if hi is None:
            mask = series >= lo
        else:
            mask = (series >= lo) & (series < hi)
        n = int(mask.sum())
        rows.append((label, n, n / total * 100 if total else 0))

    col_w = [16, 8, 7]
    lines.append("  " + "  ".join(h.ljust(w) for h, w in
                                   zip(["swin bucket", "count", "pct"], col_w)))
    lines.append("  " + "  ".join("-" * w for w in col_w))
    for label, n, pct in rows:
        lines.append("  " + "  ".join(
            str(v).ljust(w) for v, w in zip([label, f"{n:,}", f"{pct:.1f}%"], col_w)
        ))


def main():
    lines = []

    print("Building alert FID set...", flush=True)
    alert_fids, fid_to_dst = build_alert_fids(ALERT_FILE)

    print("Loading Wednesday CSV...", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False, on_bad_lines='skip',
                     encoding='utf-8', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    df['label_bin'] = (df['Label'].str.strip() != 'BENIGN').astype(int)
    df['total_pkts'] = df['Total Fwd Packets'] + df['Total Backward Packets']

    # swin = Init_Win_bytes_forward (inspector feature name: swin)
    df['swin'] = pd.to_numeric(df['Init_Win_bytes_forward'], errors='coerce')

    benign = df[df['label_bin'] == 0].copy()
    fp_rows = benign[benign['Flow ID'].isin(alert_fids)].copy()
    tn_rows = benign[~benign['Flow ID'].isin(alert_fids)].copy()

    fp_rows['alert_dst_port'] = fp_rows['Flow ID'].map(fid_to_dst)

    assert len(fp_rows) == 8500, f"Expected 8500 FPs, got {len(fp_rows)}"

    # ── Header ───────────────────────────────────────────────────────────────
    lines.append("=" * 68)
    lines.append("swin Diagnostic — 8,500 Stubborn FPs at t=0.90, max_packets=2")
    lines.append(f"LSTM clamp threshold: swin > {SWIN_CLAMP} → clamped to {SWIN_CLAMP}")
    lines.append("XGBoost path: NO clamp applied (intentional per CLAUDE.md)")
    lines.append("=" * 68)

    # ── 1. swin distribution of FPs ──────────────────────────────────────────
    lines.append("\n── 1. swin distribution of FPs (n=8,500) ──")
    pct_stats(fp_rows['swin'], "FP swin", lines)

    # ── 2. swin distribution of TNs ──────────────────────────────────────────
    lines.append(f"\n── 2. swin distribution of TNs (sample n={min(TN_SAMPLE, len(tn_rows)):,}) ──")
    tn_sample = tn_rows.sample(min(TN_SAMPLE, len(tn_rows)), random_state=42)
    pct_stats(tn_sample['swin'], "TN swin", lines)

    # ── 3. Histogram of FP swin ───────────────────────────────────────────────
    lines.append("\n── 3. swin histogram of FPs ──")
    buckets = [
        ("[0, 50]",       0,     51),
        ("[51, 255]",     51,    256),
        ("[256, 1024]",   256,   1025),
        ("[1025, 8192]",  1025,  8193),
        ("[8193, 29200]", 8193,  29201),
        ("[29201+]",      29201, None),
    ]
    histogram(fp_rows['swin'], buckets, lines)

    # ── 4. FPs with swin > SWIN_CLAMP ────────────────────────────────────────
    lines.append(f"\n── 4. FPs with swin > {SWIN_CLAMP} ──")
    fp_above = fp_rows[fp_rows['swin'] > SWIN_CLAMP]
    tn_above = tn_sample[tn_sample['swin'] > SWIN_CLAMP]
    n_fp_above = len(fp_above)
    n_tn_above = len(tn_above)
    lines.append(f"  FPs with swin > {SWIN_CLAMP}: {n_fp_above:,}  "
                 f"({n_fp_above / len(fp_rows) * 100:.1f}% of all FPs)")
    lines.append(f"  TNs with swin > {SWIN_CLAMP}: {n_tn_above:,}  "
                 f"({n_tn_above / len(tn_sample) * 100:.1f}% of TN sample)")

    # Enrichment ratio: how much more concentrated is swin>1020 in FPs vs TNs?
    fp_rate = n_fp_above / len(fp_rows)
    tn_rate = n_tn_above / len(tn_sample) if len(tn_sample) > 0 else 1e-9
    enrichment = fp_rate / tn_rate if tn_rate > 0 else float('inf')
    lines.append(f"  Enrichment ratio (FP rate / TN rate): {enrichment:.2f}x")

    # ── 5. Port breakdown of FPs with swin > SWIN_CLAMP ─────────────────────
    lines.append(f"\n── 5. Port breakdown of FPs with swin > {SWIN_CLAMP} ──")
    lines.append(f"  (These are the flows that a swin clamp would affect.)")
    lines.append(f"  Total: {n_fp_above:,} FP flows")
    if n_fp_above > 0:
        port_counts = fp_above['alert_dst_port'].value_counts().head(15)
        for port, cnt in port_counts.items():
            lines.append(f"  port {int(port) if pd.notna(port) else '?':>5}: "
                         f"{cnt:>5,}  ({cnt / n_fp_above * 100:.1f}%)")

        # Packet count distribution of these flows
        lines.append("")
        lines.append(f"  total_pkts distribution of FPs with swin > {SWIN_CLAMP}:")
        pkt_buckets = [
            ("1-2",   1,  3),
            ("3-5",   3,  6),
            ("6-10",  6, 11),
            ("11-50", 11, 51),
            ("51+",   51, None),
        ]
        for label, lo, hi in pkt_buckets:
            if hi is None:
                mask = fp_above['total_pkts'] >= lo
            else:
                mask = (fp_above['total_pkts'] >= lo) & (fp_above['total_pkts'] < hi)
            n = int(mask.sum())
            lines.append(f"    pkts {label:>6}: {n:>5,}  ({n / n_fp_above * 100:.1f}%)")

    # ── 6. Correlation: swin vs FP/TN label ──────────────────────────────────
    lines.append("\n── 6. swin vs FP/TN correlation ──")

    # Combine FP and TN sample for point-biserial correlation
    fp_swin = fp_rows['swin'].dropna()
    tn_swin = tn_sample['swin'].dropna()

    combined_vals   = np.concatenate([fp_swin.values, tn_swin.values])
    combined_labels = np.concatenate([np.ones(len(fp_swin)), np.zeros(len(tn_swin))])

    # Point-biserial correlation (equivalent to Pearson for binary y)
    from scipy import stats as scipy_stats
    r, p = scipy_stats.pointbiserialr(combined_labels, combined_vals)
    lines.append(f"  Point-biserial r(swin, is_FP) = {r:.4f}  p={p:.2e}")
    lines.append(f"  Interpretation: {'positive' if r > 0 else 'negative'} association — "
                 f"{'higher' if r > 0 else 'lower'} swin → more likely FP")
    lines.append(f"  Median swin:  FP={fp_swin.median():.0f}  TN={tn_swin.median():.0f}  "
                 f"ratio={fp_swin.median()/tn_swin.median():.2f}x")

    # ── Summary & clamp impact estimate ──────────────────────────────────────
    lines.append("\n── Summary & Clamp Impact Estimate ──")
    lines.append(f"  Flows with swin > {SWIN_CLAMP} in FP set: {n_fp_above:,} "
                 f"({n_fp_above / len(fp_rows) * 100:.1f}%)")
    lines.append(f"  Flows with swin > {SWIN_CLAMP} in TN set: {n_tn_above:,} "
                 f"({n_tn_above / len(tn_sample) * 100:.1f}%)")
    lines.append(f"  Enrichment: {enrichment:.2f}x")
    lines.append("")

    # Estimate FPR if swin clamp shifts scores of those flows below threshold
    # Conservative: assume only FPs with swin>1020 get fixed (upper bound)
    # TP risk: TN flows with swin>1020 scaled to full TN population
    tn_full = len(tn_rows)
    tn_above_full_est = int(round(tn_rate * tn_full))
    lines.append("  IF swin clamp reduces scores enough to drop those FPs below t=0.90:")
    lines.append(f"    FPs eliminated (upper bound):  {n_fp_above:,}")
    lines.append(f"    Remaining FP:                  {len(fp_rows) - n_fp_above:,}")
    remaining_fpr_est = (len(fp_rows) - n_fp_above) / (len(fp_rows) - n_fp_above + 431531 + n_fp_above)
    lines.append(f"    Estimated remaining FPR:        {remaining_fpr_est:.4f}")
    lines.append(f"    TN flows also affected (est.): {tn_above_full_est:,} "
                 f"(these would correctly stay silent — no harm)")
    lines.append("")
    if enrichment >= 2.0 and n_fp_above / len(fp_rows) >= 0.20:
        lines.append("  SIGNAL STRONG: swin > 1020 is significantly enriched in FPs.")
        lines.append("  Recommend adding swin clamp to XGBoost C++ path (task 04a).")
        lines.append("  This requires a C++ rebuild but no model retraining.")
    elif enrichment >= 1.5:
        lines.append("  SIGNAL MODERATE: swin enrichment exists but may not close the gap alone.")
        lines.append("  Clamp is still low-cost — worth implementing alongside port filter.")
    else:
        lines.append("  SIGNAL WEAK: swin is not strongly enriched in FPs.")
        lines.append("  Clamp unlikely to materially reduce FPR. Consider task 04b.")

    report = "\n".join(lines)
    print("\n" + report)
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(report, encoding='utf-8')
    print(f"\nSaved: {OUT_FILE}")


if __name__ == '__main__':
    main()
