import csv
import sys
sys.path.insert(0, "/home/emirhan/bitirme/demo-app/api")

from ground_truth import _make_flow_ids, _is_valid_ip, _map_ip, PROTO_MAP

csv_path = "/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"

print("=== GROUND TRUTH FLOW ID SAMPLES ===")
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    count = 0
    for row in reader:
        fid = row.get("Flow ID", "").strip()
        label = row.get(" Label", "").strip()
        if fid and count < 5:
            print(f"  GT: {fid} | {label}")
            count += 1

print("\n=== SAMPLE ALERT CSV FLOW IDs ===")
alert_path = "/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt"
try:
    with open(alert_path) as f:
        count = 0
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue

            src_field = parts[6].strip()
            dst_field = parts[7].strip()
            proto_str = parts[2].strip()

            src_sep = src_field.rfind(":")
            dst_sep = dst_field.rfind(":")
            if src_sep == -1 or dst_sep == -1:
                continue

            src_ip = src_field[:src_sep]
            src_port = int(src_field[src_sep+1:])
            dst_ip = dst_field[:dst_sep]
            dst_port = int(dst_field[dst_sep+1:])

            if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
                continue
            if src_port == 0 or dst_port == 0:
                continue

            proto_num = PROTO_MAP.get(proto_str.upper(), 0)
            if proto_num == 0:
                continue

            mapped_src = _map_ip(src_ip)
            mapped_dst = _map_ip(dst_ip)

            fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
            if mapped_src != src_ip or mapped_dst != dst_ip:
                fids.extend(_make_flow_ids(mapped_src, src_port, mapped_dst, dst_port, proto_num))

            print(f"  Alert: {fids[0]} (src={src_ip}:{src_port} dst={dst_ip}:{dst_port} {proto_str})")
            count += 1
            if count >= 5:
                break
except FileNotFoundError:
    print(f"  File not found: {alert_path}")

print("\n=== CROSS-CHECK: Do alert flow IDs exist in ground truth? ===")
gt_flow_ids = set()
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        fid = row.get("Flow ID", "").strip()
        if fid:
            gt_flow_ids.add(fid)

print(f"  Ground truth has {len(gt_flow_ids):,} unique flow IDs")

alert_fids = set()
alert_path = "/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt"
try:
    with open(alert_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue

            src_field = parts[6].strip()
            dst_field = parts[7].strip()
            proto_str = parts[2].strip()

            src_sep = src_field.rfind(":")
            dst_sep = dst_field.rfind(":")
            if src_sep == -1 or dst_sep == -1:
                continue

            src_ip = src_field[:src_sep]
            src_port = int(src_field[src_sep+1:])
            dst_ip = dst_field[:dst_sep]
            dst_port = int(dst_field[dst_sep+1:])

            if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
                continue
            if src_port == 0 or dst_port == 0:
                continue

            proto_num = PROTO_MAP.get(proto_str.upper(), 0)
            if proto_num == 0:
                continue

            mapped_src = _map_ip(src_ip)
            mapped_dst = _map_ip(dst_ip)

            fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
            if mapped_src != src_ip or mapped_dst != dst_ip:
                fids.extend(_make_flow_ids(mapped_src, src_port, mapped_dst, dst_port, proto_num))

            for fid in fids:
                alert_fids.add(fid)

    print(f"  Alert has {len(alert_fids):,} unique flow IDs")

    in_gt = alert_fids & gt_flow_ids
    not_in_gt = alert_fids - gt_flow_ids
    print(f"  Alert fids IN ground truth: {len(in_gt):,}")
    print(f"  Alert fids NOT in ground truth: {len(not_in_gt):,}")

    if not_in_gt:
        print(f"\n  Sample of flow IDs NOT in ground truth:")
        for fid in list(not_in_gt)[:5]:
            print(f"    {fid}")

    if in_gt:
        print(f"\n  Sample of flow IDs IN ground truth:")
        for fid in list(in_gt)[:5]:
            label = None
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("Flow ID", "").strip() == fid:
                        label = row.get(" Label", "").strip()
                        break
            print(f"    {fid} -> {label}")

except FileNotFoundError:
    print(f"  File not found: {alert_path}")