#!/usr/bin/env python3
"""Precompute per-scenario PCAP flow IDs + GT confusion stats.

For each scenario PCAP, extract all (src_ip, src_port, dst_ip, dst_port, proto) tuples
that appear in the slice, then intersect with the day's GT CSV to compute:
  - slice_attack_count: total GT attack rows for flows visible in slice
  - slice_benign_count: total GT benign rows for flows visible in slice

The eval at runtime restricts FN/TN math to these slice-local universe counts so
confusion matrix is correct for the slice (not full day).

Writes results into scenario_baselines.json under each scenario's `slice_universe`.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
PCAPS_DIR = HERE / "pcaps"
BASELINES_FILE = HERE / "scenario_baselines.json"

# Local imports
sys.path.insert(0, str(HERE))
from ground_truth import GroundTruthLoader, _make_flow_ids, _is_valid_ip, _map_ip, PROTO_MAP

SCENARIO_PCAP = {
    "dos":        "scenario_dos.new.pcap",
    "ddos":       "scenario_ddos.new.pcap",
    "portscan":   "scenario_portscan.new.pcap",
    "bruteforce": "scenario_bruteforce.new.pcap",
    "bot":        "scenario_bot.new.pcap",
}

SCENARIO_DAY = {
    "dos":        "wednesday",
    "ddos":       "friday",
    "portscan":   "friday",
    "bruteforce": "tuesday",
    "bot":        "friday",
}


def extract_flow_ids_from_pcap(pcap_path: Path) -> set[str]:
    """Use tshark to extract all flow IDs (matching GT CSV format) from a PCAP."""
    print(f"  tshark scanning {pcap_path.name}...", flush=True)
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "ip.proto",
        "-E", "separator=\t",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"  tshark error: {result.stderr[:200]}", file=sys.stderr)
        return set()

    flow_ids: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        src_ip, dst_ip, tcp_sp, tcp_dp, udp_sp, udp_dp, proto = parts[:7]
        if not src_ip or not dst_ip or not proto:
            continue
        try:
            proto_num = int(proto)
        except ValueError:
            continue
        if proto_num == 6:  # TCP
            sp, dp = tcp_sp, tcp_dp
        elif proto_num == 17:  # UDP
            sp, dp = udp_sp, udp_dp
        else:
            continue
        if not sp or not dp:
            continue
        try:
            src_port = int(sp)
            dst_port = int(dp)
        except ValueError:
            continue
        if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
            continue
        if src_port == 0 or dst_port == 0:
            continue

        fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
        mapped_src = _map_ip(src_ip)
        mapped_dst = _map_ip(dst_ip)
        if mapped_src != src_ip or mapped_dst != dst_ip:
            fids.extend(_make_flow_ids(mapped_src, src_port, mapped_dst, dst_port, proto_num))
        flow_ids.update(fids)

    print(f"    extracted {len(flow_ids):,} unique flow IDs", flush=True)
    return flow_ids


def extract_src_ips_from_pcap(pcap_path: Path) -> set[str]:
    """Extract all src IPs seen in PCAP (for IP-level confusion universe)."""
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "ip.src"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ips: set[str] = set()
    for line in result.stdout.splitlines():
        ip = line.strip()
        if not ip or not _is_valid_ip(ip):
            continue
        ips.add(_map_ip(ip))
    return ips


def compute_slice_universe(pcap_path: Path, day: str) -> dict:
    """For a PCAP slice, compute the GT counts restricted to flows in the slice."""
    flow_ids = extract_flow_ids_from_pcap(pcap_path)
    src_ips = extract_src_ips_from_pcap(pcap_path)

    gt = GroundTruthLoader.get_instance(day)
    gt.ensure_loaded()

    # Flow-level slice universe
    slice_attack_rows = 0
    slice_benign_rows = 0
    slice_flow_count = 0
    for fid in flow_ids:
        fd = gt._flow_data.get(fid)
        if fd is None:
            continue
        slice_flow_count += 1
        slice_attack_rows += fd["attack_rows"]
        slice_benign_rows += fd["benign_rows"]

    # IP-level slice universe
    slice_ip_attack = 0
    slice_ip_benign = 0
    for ip in src_ips:
        label = gt._ip_data.get(ip)
        if label == "attack":
            slice_ip_attack += 1
        elif label == "benign":
            slice_ip_benign += 1

    return {
        "flow_level": {
            "matched_gt_flows": slice_flow_count,
            "attack_rows": slice_attack_rows,
            "benign_rows": slice_benign_rows,
        },
        "ip_level": {
            "src_ips_seen": len(src_ips),
            "attack_ips": slice_ip_attack,
            "benign_ips": slice_ip_benign,
        },
    }


def main() -> None:
    with open(BASELINES_FILE) as f:
        baselines = json.load(f)

    for key, pcap_name in SCENARIO_PCAP.items():
        pcap_path = PCAPS_DIR / pcap_name
        if not pcap_path.exists():
            print(f"SKIP {key}: missing {pcap_path}")
            continue
        print(f"\n=== {key} ({pcap_name}) ===", flush=True)
        universe = compute_slice_universe(pcap_path, SCENARIO_DAY[key])
        print(f"  flow-level:  matched={universe['flow_level']['matched_gt_flows']:,}, "
              f"attack_rows={universe['flow_level']['attack_rows']:,}, "
              f"benign_rows={universe['flow_level']['benign_rows']:,}")
        print(f"  ip-level:    src_ips_seen={universe['ip_level']['src_ips_seen']}, "
              f"attack={universe['ip_level']['attack_ips']}, "
              f"benign={universe['ip_level']['benign_ips']}")
        if key in baselines:
            baselines[key]["slice_universe"] = universe

    with open(BASELINES_FILE, "w") as f:
        json.dump(baselines, f, indent=2)
    print(f"\nwrote slice_universe to {BASELINES_FILE}")


if __name__ == "__main__":
    main()
