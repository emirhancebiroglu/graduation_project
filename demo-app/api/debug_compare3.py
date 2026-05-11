#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, "/home/emirhan/bitirme/demo-app/api")

import ground_truth

# Reset singleton
ground_truth.GroundTruthLoader._instance = None

from ground_truth import extract_flow_ids_from_alert_csv, GroundTruthLoader

XGB_ALERT_PATH = Path("/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt")
CSV_DIR = Path("/home/emirhan/bitirme/data/raw/cicids2017")

print("=== Step 1: Extract flow IDs ===")
flow_ids, total, filtered = extract_flow_ids_from_alert_csv(XGB_ALERT_PATH)
print(f"  Total: {total}, Filtered: {filtered}, Unique: {len(flow_ids)}")

print("\n=== Step 2: Load ground truth directly ===")
loader = GroundTruthLoader(CSV_DIR)
loader.ensure_loaded()
print(f"  GT has {len(loader._flow_lookup):,} flow IDs")

print("\n=== Step 3: Cross-match ===")
in_gt = flow_ids & set(loader._flow_lookup.keys())
not_in_gt = flow_ids - set(loader._flow_lookup.keys())
print(f"  Alert fids IN GT: {len(in_gt):,}")
print(f"  Alert fids NOT in GT: {len(not_in_gt):,}")

print("\n=== Step 4: My module's result ===")
confusion = loader.compute_confusion(flow_ids)
for k in ["TP", "TN", "FP", "FN", "accuracy", "precision", "recall", "fpr"]:
    val = confusion[k]
    if isinstance(val, float):
        print(f"  {k}: {val:.4f}")
    else:
        print(f"  {k}: {val:,}")

print("\n=== Step 5: Original script result ===")
import subprocess
result = subprocess.run(
    ["python3", "/home/emirhan/bitirme/scripts/xgb_flowid_confusion_wednesday.py",
     "--alert-dir", "/home/emirhan/bitirme/results/xgboost",
     "--csv-dir", str(CSV_DIR)],
    capture_output=True,
    text=True,
    cwd="/home/emirhan/bitirme"
)
for line in result.stdout.split("\n"):
    if "TP" in line or "TN" in line or "FP" in line or "FN" in line or "FPR" in line:
        print(f"  {line.strip()}")

print("\n=== Step 6: Why the gap? ===")
# Check: do the non-matching alert fids have reversed version in GT?
count_with_rev = 0
count_without_rev = 0
sample_not_in_gt = list(not_in_gt)[:100]
for fid in sample_not_in_gt:
    parts = fid.split("-")
    if len(parts) == 5:
        dst_ip, src_ip, dst_port, src_port, proto = parts
        rev = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
        if rev in loader._flow_lookup:
            count_with_rev += 1
        else:
            count_without_rev += 1

print(f"  Sample not-in-GT: {count_with_rev} have reverse in GT, {count_without_rev} don't")
print(f"  Implication: reverse matching {'works' if count_with_rev > 0 else 'does NOT work'}")

print("\n=== Step 7: Why does original script work? ===")
# The original script uses pandas to do df['Flow ID'].isin(alert_flows)
# My module uses set intersection
# Are there flow IDs in GT that have different case/spacing?
sample_gt = list(loader._flow_lookup.keys())[:5]
print(f"  GT flow IDs (first 5):")
for fid in sample_gt:
    print(f"    '{fid}' (len={len(fid)})")
    
sample_alert = list(flow_ids)[:5]
print(f"\n  Alert flow IDs (first 5):")
for fid in sample_alert:
    print(f"    '{fid}' (len={len(fid)})")

# Check: is there a case sensitivity issue?
print("\n=== Step 8: Case sensitivity check ===")
sample_not = list(not_in_gt)[:3]
for fid in sample_not:
    parts = fid.split("-")
    dst_ip = parts[0]
    src_ip = parts[1]
    dst_port = parts[2]
    src_port = parts[3]
    proto = parts[4]
    
    # Find GT flows with same dst_ip
    matching = [k for k in loader._flow_lookup.keys() if k.startswith(dst_ip + "-")]
    print(f"\n  Alert: {fid}")
    print(f"  GT flows starting with {dst_ip}: {len(matching)}")
    if matching:
        print(f"  First 2: {matching[:2]}")
    
    # What about src_ip as dst?
    matching2 = [k for k in loader._flow_lookup.keys() if k.startswith(src_ip + "-")]
    print(f"  GT flows starting with {src_ip}: {len(matching2)}")

print("\n=== Step 9: GT flow IDs with DoS Hulk label ===")
count = 0
for fid, label in list(loader._flow_lookup.items()):
    if "DoS Hulk" in str(label):
        print(f"  GT: {fid} -> {label}")
        count += 1
        if count >= 3: break

# What does the alert version look like for DoS Hulk?
print("\n  Alert flow IDs with port 80 (web attack):")
count = 0
for fid in flow_ids:
    if "-80-" in fid and fid.startswith("192.168.10.50"):
        print(f"  Alert: {fid}")
        count += 1
        if count >= 3: break