#!/usr/bin/env python3
"""Debug: replicate the original script's flow ID extraction logic exactly."""

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'tcp': 6, 'udp': 17, 'icmp': 1}
IP_MAP = {'192.168.10.51': '172.16.0.1'}

def parse_ip_port(field):
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
    if not ip:
        return False
    if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
        return False
    if ":" in ip:
        return False
    return True

def map_ip(ip):
    return IP_MAP.get(ip, ip)

def extract_flow_ids_original(alert_file):
    flow_ids = set()
    total = 0
    filtered = 0
    clean = 0

    with open(alert_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            total += 1
            parts = line.split(',')
            if len(parts) < 8:
                filtered += 1
                continue
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

                src_ip_mapped = map_ip(src_ip)
                dst_ip_mapped = map_ip(dst_ip)

                fid1 = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"
                fid2 = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                flow_ids.add(fid1)
                flow_ids.add(fid2)

                if src_ip_mapped != src_ip or dst_ip_mapped != dst_ip:
                    fid3 = f"{dst_ip_mapped}-{src_ip_mapped}-{dst_port}-{src_port}-{proto_num}"
                    fid4 = f"{src_ip_mapped}-{dst_ip_mapped}-{src_port}-{dst_port}-{proto_num}"
                    flow_ids.add(fid3)
                    flow_ids.add(fid4)

                clean += 1
            except (IndexError, ValueError):
                filtered += 1
                continue

    print(f"  Total: {total}, Filtered: {filtered}, Clean: {clean}")
    print(f"  Unique flow IDs: {len(flow_ids)}")
    return flow_ids

# Run on XGBoost alerts
import pandas as pd

alert_file = "/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt"
gt_csv = "/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"

print("=== Original script logic: ===")
flow_ids = extract_flow_ids_original(alert_file)

print("\n=== First 5 flow IDs: ===")
for fid in list(flow_ids)[:5]:
    print(f"  {fid}")

print("\n=== Computing confusion (pandas) ===")
df = pd.read_csv(gt_csv, low_memory=False, on_bad_lines='skip',
    encoding='utf-8', encoding_errors='replace')
df.columns = df.columns.str.strip()

print(f"GT rows: {len(df)}")
print(f"GT columns: {list(df.columns[:5])}")
print(f"GT sample: {df[['Flow ID', 'Label']].head(3)}")

# Predicted column
df['Predicted'] = df['Flow ID'].isin(flow_ids).astype(int)
df['Label_binary'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

tp = ((df['Label_binary'] == 1) & (df['Predicted'] == 1)).sum()
fp = ((df['Label_binary'] == 0) & (df['Predicted'] == 1)).sum()
tn = ((df['Label_binary'] == 0) & (df['Predicted'] == 0)).sum()
fn = ((df['Label_binary'] == 1) & (df['Predicted'] == 0)).sum()

print(f"\nTP={tp}, FP={fp}, TN={tn}, FN={fn}")
print(f"FPR={fp/(fp+tn):.4f}, Recall={tp/(tp+fn):.4f}")

print("\n=== Why does pandas approach work? ===")
# The key difference: pandas checks each ROW individually
# A GT row is predicted as attack if ITS flow ID is in alert_flow_ids
# Multiple rows can have the same flow ID
print(f"GT unique Flow IDs: {df['Flow ID'].nunique()}")
print(f"Alert unique flow IDs: {len(flow_ids)}")
print(f"GT rows matching alert: {df['Predicted'].sum()}")

# What flow IDs in GT are NOT in alert?
gt_flow_ids = set(df['Flow ID'].dropna().unique())
matched = gt_flow_ids & flow_ids
not_matched = gt_flow_ids - flow_ids
print(f"\nGT unique flow IDs in alert: {len(matched)}")
print(f"GT unique flow IDs NOT in alert: {len(not_matched)}")

# Sample GT flow IDs NOT in alert (and their labels)
print("\nSample GT flows NOT in alert:")
for fid in list(not_matched)[:5]:
    label = df[df['Flow ID'] == fid]['Label'].iloc[0]
    print(f"  {fid} -> {label}")

print("\nSample alert flow IDs NOT in GT:")
for fid in list(flow_ids - gt_flow_ids)[:5]:
    print(f"  {fid}")