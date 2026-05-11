#!/usr/bin/env python3
"""
H0 TCP Flag Diagnostic — FPR-v3 mandatory pre-flight.

Walk Wednesday-workingHours.pcap ONCE with streaming PcapReader.
For each flow in the FP / TP / TN target set, record first 2 packet flags,
payload length, and direction.  Compute JS divergence FP vs TP and print report.

Output:
  results/xgboost/fpr-v3/H0/flag_extraction.parquet
  results/xgboost/fpr-v3/H0/diagnostic_report.txt
"""

import sys
import time
import json
import argparse
import logging
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from scapy.all import PcapReader, TCP, IP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------- constants -------------------------------------------------------

ALERT_CSV   = Path("/home/emirhan/bitirme/results/xgboost/FINAL_20260510/Wednesday-workingHours/alert_csv.txt")
WED_CSV     = Path("/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv")
WED_PCAP    = Path("/home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap")
OUT_DIR     = Path("/home/emirhan/bitirme/results/xgboost/fpr-v3/H0")

TP_SAMPLE   = 5000
TN_SAMPLE   = 5000

PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "tcp": 6, "udp": 17, "icmp": 1}
IP_MAP    = {"192.168.10.51": "172.16.0.1"}

# TCP flag bit masks (RFC 793)
FLAG_FIN, FLAG_SYN, FLAG_RST = 0x01, 0x02, 0x04
FLAG_PSH, FLAG_ACK, FLAG_URG = 0x08, 0x10, 0x20
FLAG_ECE, FLAG_CWR           = 0x40, 0x80

FLAG_NAMES = {
    FLAG_FIN: "FIN", FLAG_SYN: "SYN", FLAG_RST: "RST",
    FLAG_PSH: "PSH", FLAG_ACK: "ACK", FLAG_URG: "URG",
    FLAG_ECE: "ECE", FLAG_CWR: "CWR",
}


def flags_str(f: int) -> str:
    if f == 0:
        return "None"
    parts = [name for bit, name in sorted(FLAG_NAMES.items()) if f & bit]
    return "+".join(parts)


# ---------- helpers ---------------------------------------------------------

def parse_ip_port(field: str):
    field = field.strip()
    last = field.rfind(":")
    if last == -1:
        return field, 0
    try:
        return field[:last], int(field[last + 1:])
    except ValueError:
        return field[:last], 0


def valid_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("224.", "239.", "ff0", "fe80", "::")) or ":" in ip:
        return False
    if ip == "255.255.255.255":
        return False
    return True


def map_ip(ip: str) -> str:
    return IP_MAP.get(ip, ip)


def canonical_5tuple(src_ip, src_port, dst_ip, dst_port, proto):
    """Bidirectional canonical key: (lo_ip, hi_ip, lo_port, hi_port, proto)."""
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return (dst_ip, src_ip, dst_port, src_port, proto)


# ---------- Step 1: build cohorts from alert CSV + Wednesday CSV ------------

def load_alerted_flow_ids(alert_csv: Path) -> set:
    """Return set of bidirectional CSV flow-ID strings from Snort alert log."""
    fids = set()
    with open(alert_csv) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue
            try:
                proto_str = parts[2].strip()
                src_ip, src_port = parse_ip_port(parts[6])
                dst_ip, dst_port = parse_ip_port(parts[7])
            except (IndexError, ValueError):
                continue
            if not valid_ip(src_ip) or not valid_ip(dst_ip):
                continue
            if src_port == 0 or dst_port == 0:
                continue
            proto_num = PROTO_MAP.get(proto_str, 0)
            src_m, dst_m = map_ip(src_ip), map_ip(dst_ip)
            for si, di in [(src_ip, dst_ip), (src_m, dst_m)]:
                fids.add(f"{di}-{si}-{dst_port}-{src_port}-{proto_num}")
                fids.add(f"{si}-{di}-{src_port}-{dst_port}-{proto_num}")
    return fids


def build_cohorts(alert_fids: set, wed_csv: Path, tp_sample: int, tn_sample: int):
    """
    Returns three dicts of canonical-5tuple → cohort label:
      FP: BENIGN rows alerted
      TP: ATTACK rows alerted  (sampled)
      TN: BENIGN rows NOT alerted (sampled)
    """
    log.info("Loading Wednesday CSV …")
    df = pd.read_csv(wed_csv, low_memory=False, on_bad_lines="skip",
                     encoding="utf-8", encoding_errors="replace")
    df.columns = df.columns.str.strip()

    # normalise label
    df["label_clean"] = df["Label"].str.strip().str.upper()
    df["is_attack"] = df["label_clean"] != "BENIGN"

    # build alerted mask
    df["alerted"] = df["Flow ID"].isin(alert_fids)

    fp_df  = df[ ~df["is_attack"] &  df["alerted"]].copy()
    tp_df  = df[  df["is_attack"] &  df["alerted"]].copy()
    tn_df  = df[ ~df["is_attack"] & ~df["alerted"]].copy()

    log.info(f"  FP rows: {len(fp_df)}, TP rows: {len(tp_df)}, TN rows: {len(tn_df)}")

    # sample TP and TN
    rng = np.random.default_rng(42)
    if len(tp_df) > tp_sample:
        tp_df = tp_df.sample(n=tp_sample, random_state=42)
    if len(tn_df) > tn_sample:
        tn_df = tn_df.sample(n=tn_sample, random_state=42)

    def rows_to_tuple_set(sub_df):
        result = {}
        for _, row in sub_df.iterrows():
            try:
                si = str(row["Source IP"]).strip()
                di = str(row["Destination IP"]).strip()
                sp = int(row["Source Port"])
                dp = int(row["Destination Port"])
                pr = int(row["Protocol"])
                si_m, di_m = map_ip(si), map_ip(di)
                # store both original and mapped so PCAP lookup hits either
                key = canonical_5tuple(si, sp, di, dp, pr)
                result[key] = True
                if si_m != si or di_m != di:
                    result[canonical_5tuple(si_m, sp, di_m, dp, pr)] = True
            except (ValueError, KeyError):
                continue
        return result

    log.info("Building FP 5-tuple set …")
    fp_set = rows_to_tuple_set(fp_df)
    log.info("Building TP 5-tuple set …")
    tp_set = rows_to_tuple_set(tp_df)
    log.info("Building TN 5-tuple set …")
    tn_set = rows_to_tuple_set(tn_df)

    return fp_set, tp_set, tn_set, len(fp_df), len(tp_df), len(tn_df)


# ---------- Step 2: stream PCAP, collect first 2 packets -------------------

def stream_pcap(pcap_path: Path, fp_set: set, tp_set: dict, tn_set: set):
    """
    Single-pass streaming walk.  Returns list of dicts with per-flow flag data.
    """
    target_set = set(fp_set) | set(tp_set) | set(tn_set)
    flows = {}   # canonical_key → {"cohort", "pkts": [(flags, paylen, dir_str)]}

    def cohort_for(key):
        if key in fp_set: return "FP"
        if key in tp_set: return "TP"
        if key in tn_set: return "TN"
        return None

    log.info(f"Target set size: {len(target_set)} flows")
    log.info(f"Streaming {pcap_path} (this will take ~30-60 min) …")

    pkt_count = 0
    matched   = 0
    done      = 0          # flows that already have 2 packets
    t0 = time.time()
    report_every = 1_000_000

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            pkt_count += 1
            if pkt_count % report_every == 0:
                elapsed = time.time() - t0
                log.info(f"  {pkt_count:,} pkts in {elapsed:.0f}s | matched flows: {matched} | done: {done}")

            # early-exit once all target flows are satisfied
            if done == len(target_set):
                log.info("All target flows satisfied — stopping early.")
                break

            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue

            ip  = pkt[IP]
            tcp = pkt[TCP]

            src_ip   = ip.src
            dst_ip   = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport
            proto    = 6

            key = canonical_5tuple(src_ip, src_port, dst_ip, dst_port, proto)
            if key not in target_set:
                # also try mapped IPs
                src_m = map_ip(src_ip)
                dst_m = map_ip(dst_ip)
                if src_m != src_ip or dst_m != dst_ip:
                    key2 = canonical_5tuple(src_m, src_port, dst_m, dst_port, proto)
                    if key2 in target_set:
                        key = key2
                    else:
                        continue
                else:
                    continue

            if key not in flows:
                cohort = cohort_for(key)
                if cohort is None:
                    continue
                flows[key] = {"cohort": cohort, "pkts": []}
                matched += 1

            entry = flows[key]
            if len(entry["pkts"]) >= 2:
                done += 1
                # remove from target_set so early-exit counter is accurate
                target_set.discard(key)
                continue

            flags   = int(tcp.flags)
            paylen  = len(tcp.payload)
            # direction: C2S if src < dst (canonical); we track original direction
            # "client" = whichever side sent SYN; fallback: src_port>1024 = client
            if flags & FLAG_SYN and not (flags & FLAG_ACK):
                direction = "C2S"   # SYN without ACK → initiator
            elif flags & FLAG_SYN and flags & FLAG_ACK:
                direction = "S2C"   # SYN-ACK → server response
            else:
                # use canonical key order: first element of key is "lower" side
                direction = "C2S" if (src_ip, src_port) == (key[0], key[2]) else "S2C"

            entry["pkts"].append((flags, paylen, direction))

    log.info(f"Done streaming. Total pkts: {pkt_count:,}, matched flows: {matched}")
    return flows


# ---------- Step 3: compute statistics + JS divergence ---------------------

def compute_stats(flows: dict):
    records = []
    for key, v in flows.items():
        pkts = v["pkts"]
        if not pkts:
            continue
        p1 = pkts[0]
        p2 = pkts[1] if len(pkts) > 1 else (0, 0, "UNK")
        records.append({
            "flow_id"      : str(key),
            "cohort"       : v["cohort"],
            "pkt1_flags"   : p1[0],
            "pkt1_payload_len": p1[1],
            "pkt1_dir"     : p1[2],
            "pkt2_flags"   : p2[0],
            "pkt2_payload_len": p2[1],
            "pkt2_dir"     : p2[2],
        })

    return pd.DataFrame(records)


def js_divergence(dist_a: dict, dist_b: dict) -> float:
    """JS divergence over joint (pkt1_flags, pkt2_flags) distributions."""
    keys = sorted(set(dist_a) | set(dist_b))
    total_a = sum(dist_a.values()) or 1
    total_b = sum(dist_b.values()) or 1
    p = np.array([dist_a.get(k, 0) / total_a for k in keys], dtype=float)
    q = np.array([dist_b.get(k, 0) / total_b for k in keys], dtype=float)
    # jensenshannon returns sqrt(JS divergence); square to get raw JS
    return float(jensenshannon(p, q) ** 2)


def top_flag_combos(sub_df: pd.DataFrame, n=5):
    combos = sub_df.groupby(["pkt1_flags", "pkt2_flags"]).size()
    total  = len(sub_df)
    combos = combos.sort_values(ascending=False).head(n)
    result = []
    for (f1, f2), cnt in combos.items():
        result.append((flags_str(f1), flags_str(f2), cnt, cnt / total * 100))
    return result


def direction_split(sub_df: pd.DataFrame):
    if len(sub_df) == 0:
        return 0.0, 0.0
    c2s = (sub_df["pkt1_dir"] == "C2S").sum()
    return c2s / len(sub_df) * 100, (1 - c2s / len(sub_df)) * 100


def payload_stats(sub_df: pd.DataFrame, pkt_col: str):
    vals = sub_df[pkt_col]
    return vals.mean(), vals.std(), vals.min(), vals.max()


# ---------- Step 4: write report -------------------------------------------

def write_report(df: pd.DataFrame, out_dir: Path,
                 fp_n: int, tp_n: int, tn_n: int):
    fp_df = df[df["cohort"] == "FP"]
    tp_df = df[df["cohort"] == "TP"]
    tn_df = df[df["cohort"] == "TN"]

    # joint flag distribution dicts
    def joint_dist(sub):
        d = defaultdict(int)
        for _, row in sub.iterrows():
            d[(row["pkt1_flags"], row["pkt2_flags"])] += 1
        return dict(d)

    fp_dist = joint_dist(fp_df)
    tp_dist = joint_dist(tp_df)
    tn_dist = joint_dist(tn_df)

    js_fp_tp = js_divergence(fp_dist, tp_dist)
    js_fp_tn = js_divergence(fp_dist, tn_dist)
    js_tp_tn = js_divergence(tp_dist, tn_dist)

    fp_c2s, fp_s2c = direction_split(fp_df)
    tp_c2s, tp_s2c = direction_split(tp_df)
    tn_c2s, tn_s2c = direction_split(tn_df)

    def fmt_payload(sub, col):
        m, s, mn, mx = payload_stats(sub, col)
        return f"{m:.1f} ± {s:.1f}  (range {mn}..{mx})"

    # decision
    if js_fp_tp >= 0.50:
        decision = "STRONG separation — proceed to H6"
        signal   = "STRONG"
    elif js_fp_tp >= 0.20:
        decision = "WEAK separation — proceed to H6 cautiously"
        signal   = "WEAK"
    else:
        decision = "NO separation — STOP, ask user, consider H8 directly"
        signal   = "NO SIGNAL"

    lines = []
    lines.append("=== TCP Flag Diagnostic — Wednesday FP vs TP cohorts ===")
    lines.append(f"Run date : {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"FP source: FINAL_20260510 alert CSV (BENIGN alerted, n_csv={fp_n}, n_pcap_matched={len(fp_df)})")
    lines.append(f"TP source: Wednesday CSV attack rows sampled {tp_n}, n_pcap_matched={len(tp_df)})")
    lines.append(f"TN source: Wednesday CSV BENIGN non-alerted sampled {tn_n}, n_pcap_matched={len(tn_df)})")
    lines.append("")

    lines.append(f"FP cohort (n={len(fp_df)}):")
    lines.append("  Top 5 (pkt1_flags, pkt2_flags) combos:")
    for f1, f2, cnt, pct in top_flag_combos(fp_df):
        lines.append(f"    {f1:20s}, {f2:20s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append(f"  Direction:  C2S {fp_c2s:.1f}%  |  S2C {fp_s2c:.1f}%")
    lines.append(f"  Payload pkt1:  {fmt_payload(fp_df, 'pkt1_payload_len')}")
    lines.append(f"  Payload pkt2:  {fmt_payload(fp_df, 'pkt2_payload_len')}")
    lines.append("")

    lines.append(f"TP cohort (n={len(tp_df)}):")
    lines.append("  Top 5 (pkt1_flags, pkt2_flags) combos:")
    for f1, f2, cnt, pct in top_flag_combos(tp_df):
        lines.append(f"    {f1:20s}, {f2:20s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append(f"  Direction:  C2S {tp_c2s:.1f}%  |  S2C {tp_s2c:.1f}%")
    lines.append(f"  Payload pkt1:  {fmt_payload(tp_df, 'pkt1_payload_len')}")
    lines.append(f"  Payload pkt2:  {fmt_payload(tp_df, 'pkt2_payload_len')}")
    lines.append("")

    lines.append(f"TN cohort (n={len(tn_df)}) — control:")
    lines.append("  Top 5 (pkt1_flags, pkt2_flags) combos:")
    for f1, f2, cnt, pct in top_flag_combos(tn_df):
        lines.append(f"    {f1:20s}, {f2:20s}  {cnt:5d}  ({pct:.1f}%)")
    lines.append(f"  Direction:  C2S {tn_c2s:.1f}%  |  S2C {tn_s2c:.1f}%")
    lines.append(f"  Payload pkt1:  {fmt_payload(tn_df, 'pkt1_payload_len')}")
    lines.append(f"  Payload pkt2:  {fmt_payload(tn_df, 'pkt2_payload_len')}")
    lines.append("")

    lines.append("Discrimination signal:")
    lines.append(f"  JS divergence FP vs TP  = {js_fp_tp:.4f} / 1.0   ← PRIMARY")
    lines.append(f"  JS divergence FP vs TN  = {js_fp_tn:.4f} / 1.0")
    lines.append(f"  JS divergence TP vs TN  = {js_tp_tn:.4f} / 1.0")
    lines.append(f"  → {signal}: {decision}")

    report = "\n".join(lines)
    print(report)

    report_path = out_dir / "diagnostic_report.txt"
    report_path.write_text(report)
    log.info(f"Report saved → {report_path}")

    # also emit JSON for easy programmatic access
    summary = {
        "js_fp_tp": js_fp_tp,
        "js_fp_tn": js_fp_tn,
        "js_tp_tn": js_tp_tn,
        "signal"  : signal,
        "decision": decision,
        "fp_n_pcap": len(fp_df),
        "tp_n_pcap": len(tp_df),
        "tn_n_pcap": len(tn_df),
    }
    (out_dir / "diagnostic_summary.json").write_text(json.dumps(summary, indent=2))

    return js_fp_tp, signal, decision


# ---------- main ------------------------------------------------------------

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Step 1: loading alerted flow IDs from Snort alert CSV …")
    alert_fids = load_alerted_flow_ids(ALERT_CSV)
    log.info(f"  {len(alert_fids)} alerted flow ID strings")

    log.info("Step 2: building FP / TP / TN cohorts from Wednesday CSV …")
    fp_set, tp_set, tn_set, fp_n, tp_n, tn_n = build_cohorts(
        alert_fids, WED_CSV, TP_SAMPLE, TN_SAMPLE)
    log.info(f"  FP set: {len(fp_set)} keys, TP set: {len(tp_set)} keys, TN set: {len(tn_set)} keys")

    log.info("Step 3: streaming PCAP …")
    flows = stream_pcap(WED_PCAP, fp_set, tp_set, tn_set)

    log.info("Step 4: computing statistics …")
    df = compute_stats(flows)
    log.info(f"  Records: {len(df)} ({df['cohort'].value_counts().to_dict()})")

    parquet_path = OUT_DIR / "flag_extraction.parquet"
    df.to_parquet(parquet_path, index=False)
    log.info(f"  Parquet saved → {parquet_path}")

    log.info("Step 5: writing diagnostic report …")
    js_val, signal, decision = write_report(df, OUT_DIR, fp_n, tp_n, tn_n)

    # exit code hints for automated callers
    if signal == "STRONG":
        sys.exit(0)
    elif signal == "WEAK":
        sys.exit(2)
    else:
        sys.exit(3)


if __name__ == "__main__":
    main()
