#!/usr/bin/env python3
from pathlib import Path

# Reset singleton first
import sys
sys.path.insert(0, "/home/emirhan/bitirme/demo-app/api")
import ground_truth
ground_truth.GroundTruthLoader._instance = None
from ground_truth import GroundTruthLoader

CSV_DIR = Path("/home/emirhan/bitirme/data/raw/cicids2017")

loader = GroundTruthLoader(CSV_DIR)
loader.ensure_loaded()

print("=== GT flow ID samples with different IPs ===")
samples = list(loader._flow_lookup.items())[:20]
for fid, label in samples:
    print(f"  {fid} -> {label}")

print("\n=== Count GT flows with 172.16.0.1 as DST ===")
count = sum(1 for fid in loader._flow_lookup if fid.startswith("172.16.0.1-"))
print(f"  {count:,} flows with dst=172.16.0.1")

print("\n=== Count GT flows with 192.168.10.50 as DST ===")
count = sum(1 for fid in loader._flow_lookup if fid.startswith("192.168.10.50-"))
print(f"  {count:,} flows with dst=192.168.10.50")

print("\n=== GT flows with DoS label ===")
dos_count = sum(1 for label in loader._flow_lookup.values() if label != "BENIGN")
print(f"  {dos_count:,} attack flows in GT")

# Show a DoS flow ID
for fid, label in list(loader._flow_lookup.items())[:50]:
    if label != "BENIGN":
        print(f"\n  DoS sample: {fid} -> {label}")
        break

# Check what alert flows look like
print("\n=== Alert flow ID samples (XGBoost) ===")
from ground_truth import extract_flow_ids_from_alert_csv
XGB_PATH = Path("/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt")
alert_ids, _, _ = extract_flow_ids_from_alert_csv(XGB_PATH)
for fid in list(alert_ids)[:10]:
    print(f"  {fid}")

# KEY QUESTION: Does my alert extraction match the original script's output?
# Original: 85781 alerts → 252610 TP + 7679 FP = 260289 GT rows matched
# My module: alert_ids matched GT = ?
matched = alert_ids & set(loader._flow_lookup.keys())
print(f"\nAlert fids matched to GT: {len(matched):,}")
print(f"GT attack flows: {dos_count:,}")
print(f"If all {matched:,} matched are attacks: {len(matched) / dos_count * 100:.1f}% of attacks detected")

# What percentage of matched are attacks?
matched_labels = [loader._flow_lookup.get(fid, "NOT FOUND") for fid in matched]
attack_count = sum(1 for l in matched_labels if l != "BENIGN")
print(f"Of matched fids: {attack_count:,} attacks, {len(matched) - attack_count} benign")

# Try: do the unmatched alert fids have a reversed version in GT?
print("\n=== Checking reversed versions of unmatched alert fids ===")
unmatched = alert_ids - set(loader._flow_lookup.keys())
rev_matched = 0
not_found = 0
for fid in list(unmatched)[:1000]:
    parts = fid.split("-")
    if len(parts) == 5:
        dst_ip, src_ip, dst_port, src_port, proto = parts
        rev = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
        if rev in loader._flow_lookup:
            rev_matched += 1
        else:
            not_found += 1

print(f"  Of first 1000 unmatched: {rev_matched} have reversed in GT, {not_found} don't")
print(f"  If all 1000 are like this: {not_found * len(unmatched) / 1000:.0f} truly not in GT")