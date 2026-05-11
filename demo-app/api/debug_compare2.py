import csv
from pathlib import Path

csv_path = "/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"

PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "tcp": 6, "udp": 17, "icmp": 1}
IP_MAP = {"192.168.10.51": "172.16.0.1"}

def _is_valid_ip(ip):
    if not ip: return False
    if ip.startswith("224.") or ip.startswith("239."): return False
    if ip == "255.255.255.255": return False
    if ":" in ip: return False
    return True

def _map_ip(ip):
    return IP_MAP.get(ip, ip)

def _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto):
    fids = []
    fids.append(f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto}")
    fids.append(f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}")
    ms = _map_ip(src_ip)
    md = _map_ip(dst_ip)
    if ms != src_ip or md != dst_ip:
        fids.append(f"{md}-{ms}-{dst_port}-{src_port}-{proto}")
        fids.append(f"{ms}-{md}-{src_port}-{dst_port}-{proto}")
    return fids

print("=== GT flows with 192.168.10.50 as DST ===")
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    header = [h.strip() for h in next(reader)]
    label_idx = next(i for i, h in enumerate(header) if h == "Label")
    fid_idx = next(i for i, h in enumerate(header) if h == "Flow ID")

    count = 0
    for row in reader:
        fid = row[fid_idx]
        if fid.startswith("192.168.10.50-"):
            label = row[label_idx]
            print(f"  GT: {fid} -> {label}")
            count += 1
            if count >= 10: break

print(f"\n=== Alert flows with 192.168.10.50 as DST (non-mapped) ===")
alert_path = Path("/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt")
try:
    with open(alert_path) as f:
        count = 0
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(",")
            if len(parts) < 8: continue

            src_field = parts[6].strip()
            dst_field = parts[7].strip()
            proto_str = parts[2].strip()

            src_sep = src_field.rfind(":")
            dst_sep = dst_field.rfind(":")
            if src_sep == -1 or dst_sep == -1: continue

            src_ip = src_field[:src_sep]
            src_port = int(src_field[src_sep+1:])
            dst_ip = dst_field[:dst_sep]
            dst_port = int(dst_field[dst_sep+1:])

            if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip): continue
            if src_port == 0 or dst_port == 0: continue
            proto_num = PROTO_MAP.get(proto_str.upper(), 0)
            if proto_num == 0: continue

            ms = _map_ip(src_ip)
            md = _map_ip(dst_ip)
            if ms != src_ip or md != dst_ip: continue  # skip if mapped

            fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
            for fid in fids:
                if fid.startswith("192.168.10.50-"):
                    print(f"  Alert (no map): {fid}")
                    count += 1
                    if count >= 10: break
except FileNotFoundError:
    print("  File not found")

print(f"\n=== Alert flows with 192.168.10.50 as DST (mapped) ===")
try:
    with open(alert_path) as f:
        count = 0
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(",")
            if len(parts) < 8: continue

            src_field = parts[6].strip()
            dst_field = parts[7].strip()
            proto_str = parts[2].strip()

            src_sep = src_field.rfind(":")
            dst_sep = dst_field.rfind(":")
            if src_sep == -1 or dst_sep == -1: continue

            src_ip = src_field[:src_sep]
            src_port = int(src_field[src_sep+1:])
            dst_ip = dst_field[:dst_sep]
            dst_port = int(dst_field[dst_sep+1:])

            if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip): continue
            if src_port == 0 or dst_port == 0: continue
            proto_num = PROTO_MAP.get(proto_str.upper(), 0)
            if proto_num == 0: continue

            ms = _map_ip(src_ip)
            md = _map_ip(dst_ip)
            if ms == src_ip and md == dst_ip: continue  # skip if NOT mapped

            fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
            if ms != src_ip or md != dst_ip:
                fids.extend(_make_flow_ids(ms, src_port, md, dst_port, proto_num))
            for fid in fids:
                if fid.startswith("192.168.10.50-"):
                    print(f"  Alert (mapped): {fid}")
                    count += 1
                    if count >= 10: break
except FileNotFoundError:
    print("  File not found")