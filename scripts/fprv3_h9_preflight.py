#!/usr/bin/env python3
"""
fprv3_h9_preflight.py — H9 TCP-state trigger pre-flight.

Extends H0 parquet (pkt1/pkt2) with pkt3 flags by streaming
Wednesday-workingHours.pcap once.  Then reports:
  - FP cohort: fraction with RST at pkt3
  - TP cohort: fraction with ACK or PSH+ACK at pkt3  (post-handshake data)

H9 premise holds if FP-RST >= 30% AND TP-data >= 50%.

Output:
  results/xgboost/fpr-v3/H0/flag_extraction_pkt3.parquet
  results/xgboost/fpr-v3/H0/h9_preflight_report.txt
"""

import json
import time
import logging
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.all import PcapReader, TCP, IP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

H0_PARQUET  = Path("/home/emirhan/bitirme/results/xgboost/fpr-v3/H0/flag_extraction.parquet")
WED_PCAP    = Path("/home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap")
OUT_DIR     = Path("/home/emirhan/bitirme/results/xgboost/fpr-v3/H0")

IP_MAP = {"192.168.10.51": "172.16.0.1"}

FLAG_FIN, FLAG_SYN, FLAG_RST = 0x01, 0x02, 0x04
FLAG_PSH, FLAG_ACK            = 0x08, 0x10

FLAG_NAMES = {
    FLAG_FIN: "FIN", FLAG_SYN: "SYN", FLAG_RST: "RST",
    FLAG_PSH: "PSH", FLAG_ACK: "ACK", 0x20: "URG",
    0x40: "ECE", 0x80: "CWR",
}


def flags_str(f: int) -> str:
    if f == 0:
        return "None"
    return "+".join(name for bit, name in sorted(FLAG_NAMES.items()) if f & bit)


def map_ip(ip: str) -> str:
    return IP_MAP.get(ip, ip)


def canonical_key_from_str(s: str):
    """Re-parse the string repr of tuple stored in parquet flow_id column."""
    # format: "('ip1', 'ip2', port1, port2, proto)"
    import ast
    return ast.literal_eval(s)


def canonical_5tuple(src_ip, src_port, dst_ip, dst_port, proto):
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return (dst_ip, src_ip, dst_port, src_port, proto)


# ---------- Step 1: build target set from H0 parquet -----------------------

def build_target_set(df: pd.DataFrame):
    """Return dict: canonical_key -> cohort string."""
    target = {}
    for _, row in df.iterrows():
        key = canonical_key_from_str(row["flow_id"])
        target[key] = row["cohort"]
        # add mapped-IP variant
        ip0_m = map_ip(key[0])
        ip1_m = map_ip(key[1])
        if ip0_m != key[0] or ip1_m != key[1]:
            target[(ip0_m, ip1_m, key[2], key[3], key[4])] = row["cohort"]
    return target


# ---------- Step 2: stream PCAP, collect pkt3 flags ------------------------

def stream_pkt3(pcap_path: Path, target: dict):
    """
    Single-pass stream.  For each target flow, collect packets 1-3.
    Returns dict: canonical_key -> list of (flags, paylen, dir) per packet (up to 3).
    We skip flows already having pkt3 if target set is exhausted early.
    """
    flows      = {}   # key -> {"cohort": str, "pkts": [...]}
    done_count = 0
    total_target = len(set(v for v in target.values()) and target)  # noqa — use len(target)
    total_target = len(target)

    log.info(f"Target set: {total_target} keys ({len(set(target.values()))} cohorts)")
    log.info(f"Streaming {pcap_path} for pkt3 …")

    pkt_count = 0
    matched   = 0
    t0 = time.time()
    report_every = 1_000_000

    # remaining: keys still needing pkt3
    remaining = set(target.keys())

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            pkt_count += 1
            if pkt_count % report_every == 0:
                elapsed = time.time() - t0
                log.info(f"  {pkt_count:,} pkts | {elapsed:.0f}s | matched {matched} | need_pkt3 {len(remaining)}")
            if not remaining:
                log.info("All target flows have pkt3 — early exit.")
                break
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue

            ip  = pkt[IP]
            tcp = pkt[TCP]
            src_ip, dst_ip = ip.src, ip.dst
            src_port, dst_port, proto = tcp.sport, tcp.dport, 6

            key = canonical_5tuple(src_ip, src_port, dst_ip, dst_port, proto)
            if key not in remaining:
                src_m, dst_m = map_ip(src_ip), map_ip(dst_ip)
                if src_m != src_ip or dst_m != dst_ip:
                    key2 = canonical_5tuple(src_m, src_port, dst_m, dst_port, proto)
                    if key2 in remaining:
                        key = key2
                    else:
                        continue
                else:
                    continue

            cohort = target[key]
            if key not in flows:
                flows[key] = {"cohort": cohort, "pkts": []}
                matched += 1

            entry = flows[key]
            if len(entry["pkts"]) >= 3:
                remaining.discard(key)
                continue

            flags  = int(tcp.flags)
            paylen = len(tcp.payload)
            # direction heuristic (same as H0)
            if flags & FLAG_SYN and not (flags & FLAG_ACK):
                direction = "C2S"
            elif flags & FLAG_SYN and flags & FLAG_ACK:
                direction = "S2C"
            else:
                direction = "C2S" if (src_ip, src_port) == (key[0], key[2]) else "S2C"

            entry["pkts"].append((flags, paylen, direction))
            if len(entry["pkts"]) == 3:
                remaining.discard(key)

    log.info(f"Done. {pkt_count:,} pkts | matched {matched} flows | {len(remaining)} never got pkt3")
    return flows


# ---------- Step 3: merge with H0 parquet ----------------------------------

def build_extended_df(h0_df: pd.DataFrame, flows: dict) -> pd.DataFrame:
    rows = []
    for _, row in h0_df.iterrows():
        key = canonical_key_from_str(row["flow_id"])
        # try mapped variant too
        ip0_m = map_ip(key[0])
        ip1_m = map_ip(key[1])
        mapped_key = (ip0_m, ip1_m, key[2], key[3], key[4])

        entry = flows.get(key) or flows.get(mapped_key)
        if entry and len(entry["pkts"]) >= 3:
            p3 = entry["pkts"][2]
            pkt3_flags, pkt3_paylen, pkt3_dir = p3
        else:
            pkt3_flags, pkt3_paylen, pkt3_dir = None, None, None

        rows.append({
            **row.to_dict(),
            "pkt3_flags"      : pkt3_flags,
            "pkt3_payload_len": pkt3_paylen,
            "pkt3_dir"        : pkt3_dir,
        })
    return pd.DataFrame(rows)


# ---------- Step 4: compute preflight stats --------------------------------

def is_rst(f):
    return f is not None and not np.isnan(float(f)) and int(f) & FLAG_RST

def is_post_handshake(f):
    """ACK-only or PSH+ACK — data transfer phase."""
    if f is None or np.isnan(float(f)):
        return False
    fi = int(f)
    ack = bool(fi & FLAG_ACK)
    syn = bool(fi & FLAG_SYN)
    rst = bool(fi & FLAG_RST)
    fin = bool(fi & FLAG_FIN)
    # post-handshake = ACK set, no SYN, no RST, no FIN (or PSH+ACK)
    return ack and not syn and not rst


def preflight_report(df: pd.DataFrame, out_dir: Path):
    fp_df = df[df["cohort"] == "FP"]
    tp_df = df[df["cohort"] == "TP"]
    tn_df = df[df["cohort"] == "TN"]

    def pkt3_coverage(sub):
        return sub["pkt3_flags"].notna().sum(), len(sub)

    fp_cov, fp_tot = pkt3_coverage(fp_df)
    tp_cov, tp_tot = pkt3_coverage(tp_df)
    tn_cov, tn_tot = pkt3_coverage(tn_df)

    fp_has_pkt3 = fp_df[fp_df["pkt3_flags"].notna()]
    tp_has_pkt3 = tp_df[tp_df["pkt3_flags"].notna()]
    tn_has_pkt3 = tn_df[tn_df["pkt3_flags"].notna()]

    fp_rst   = fp_has_pkt3["pkt3_flags"].apply(is_rst).sum()
    tp_data  = tp_has_pkt3["pkt3_flags"].apply(is_post_handshake).sum()
    tn_data  = tn_has_pkt3["pkt3_flags"].apply(is_post_handshake).sum()

    fp_rst_pct  = fp_rst / len(fp_has_pkt3) * 100 if len(fp_has_pkt3) else 0
    tp_data_pct = tp_data / len(tp_has_pkt3) * 100 if len(tp_has_pkt3) else 0
    tn_data_pct = tn_data / len(tn_has_pkt3) * 100 if len(tn_has_pkt3) else 0

    # top pkt3 flag combos per cohort
    def top_flags(sub, n=5):
        counts = sub["pkt3_flags"].dropna().astype(int).value_counts().head(n)
        total  = len(sub["pkt3_flags"].dropna())
        return [(flags_str(int(f)), cnt, cnt / total * 100) for f, cnt in counts.items()]

    premise_met = fp_rst_pct >= 30.0 and tp_data_pct >= 50.0

    lines = []
    lines.append("=== H9 Pre-flight — TCP State at Packet 3 ===")
    lines.append(f"Run date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"H9 premise: FP-RST-at-pkt3 >= 30% AND TP-post-handshake-at-pkt3 >= 50%")
    lines.append("")

    lines.append(f"FP cohort (n_total={fp_tot}, n_pkt3={fp_cov}):")
    lines.append(f"  RST at pkt3:              {fp_rst:4d} / {len(fp_has_pkt3)} = {fp_rst_pct:.1f}%  [threshold: >= 30%]")
    lines.append(f"  Post-handshake (ACK/PSH): {(fp_has_pkt3['pkt3_flags'].apply(is_post_handshake).sum()):4d} / {len(fp_has_pkt3)}")
    lines.append("  Top pkt3 flags:")
    for fs, cnt, pct in top_flags(fp_has_pkt3):
        lines.append(f"    {fs:25s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append("")

    lines.append(f"TP cohort (n_total={tp_tot}, n_pkt3={tp_cov}):")
    lines.append(f"  Post-handshake (ACK/PSH): {tp_data:4d} / {len(tp_has_pkt3)} = {tp_data_pct:.1f}%  [threshold: >= 50%]")
    lines.append(f"  RST at pkt3:              {(tp_has_pkt3['pkt3_flags'].apply(is_rst).sum()):4d} / {len(tp_has_pkt3)}")
    lines.append("  Top pkt3 flags:")
    for fs, cnt, pct in top_flags(tp_has_pkt3):
        lines.append(f"    {fs:25s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append("")

    lines.append(f"TN cohort (n_total={tn_tot}, n_pkt3={tn_cov}) — control:")
    lines.append(f"  Post-handshake (ACK/PSH): {tn_data:4d} / {len(tn_has_pkt3)} = {tn_data_pct:.1f}%")
    lines.append("  Top pkt3 flags:")
    for fs, cnt, pct in top_flags(tn_has_pkt3):
        lines.append(f"    {fs:25s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append("")

    lines.append("H9 PREMISE:")
    lines.append(f"  FP RST >= 30%:             {'PASS' if fp_rst_pct >= 30 else 'FAIL'}  ({fp_rst_pct:.1f}%)")
    lines.append(f"  TP post-handshake >= 50%:  {'PASS' if tp_data_pct >= 50 else 'FAIL'}  ({tp_data_pct:.1f}%)")
    lines.append(f"  Overall:                   {'PREMISE HOLDS — proceed to H9 C++ impl' if premise_met else 'PREMISE FAILS — report to user before implementing'}")

    report = "\n".join(lines)
    print(report)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "h9_preflight_report.txt").write_text(report)
    log.info(f"Report saved → {out_dir / 'h9_preflight_report.txt'}")

    summary = {
        "fp_rst_pct"    : fp_rst_pct,
        "tp_data_pct"   : tp_data_pct,
        "fp_pkt3_n"     : int(len(fp_has_pkt3)),
        "tp_pkt3_n"     : int(len(tp_has_pkt3)),
        "premise_met"   : premise_met,
    }
    (out_dir / "h9_preflight_summary.json").write_text(json.dumps(summary, indent=2))

    return premise_met


# ---------- main ------------------------------------------------------------

def main():
    log.info("Loading H0 parquet …")
    h0_df = pd.read_parquet(H0_PARQUET)
    log.info(f"  {len(h0_df)} rows, cohorts: {h0_df['cohort'].value_counts().to_dict()}")

    log.info("Building target set from H0 flow IDs …")
    target = build_target_set(h0_df)
    log.info(f"  {len(target)} canonical keys")

    log.info("Streaming PCAP for pkt3 …")
    flows = stream_pkt3(WED_PCAP, target)

    log.info("Merging with H0 parquet …")
    ext_df = build_extended_df(h0_df, flows)
    pkt3_path = OUT_DIR / "flag_extraction_pkt3.parquet"
    ext_df.to_parquet(pkt3_path, index=False)
    log.info(f"  Extended parquet saved → {pkt3_path}")

    log.info("Computing H9 pre-flight stats …")
    premise_met = preflight_report(ext_df, OUT_DIR)

    import sys
    sys.exit(0 if premise_met else 2)


if __name__ == "__main__":
    main()
