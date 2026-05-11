#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, "/home/emirhan/bitirme/demo-app/api")
import ground_truth
ground_truth.GroundTruthLoader._instance = None
from ground_truth import GroundTruthLoader, extract_flow_ids_from_alert_csv

CSV_DIR = Path("/home/emirhan/bitirme/data/raw/cicids2017")
XGB_PATH = Path("/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt")

loader = GroundTruthLoader(CSV_DIR)
loader.ensure_loaded()

# Check: what labels are stored?
sample_labels = list(loader._flow_lookup.values())[:5]
print("Sample GT labels (raw values):", sample_labels)

# Count attacks properly
attack_count = sum(1 for v in loader._flow_lookup.values() if v)
benign_count = sum(1 for v in loader._flow_lookup.values() if not v)
print(f"GT attacks: {attack_count:,}, benign: {benign_count:,}")

print("\n=== Extracting alert flow IDs ===")
alert_ids, total, filtered = extract_flow_ids_from_alert_csv(XGB_PATH)
print(f"Alert fids: {len(alert_ids):,} unique out of {total:,} lines")

print("\n=== Cross-match ===")
matched = alert_ids & set(loader._flow_lookup.keys())
unmatched = alert_ids - set(loader._flow_lookup.keys())
print(f"Matched: {len(matched):,}, Unmatched: {len(unmatched):,}")

# Of matched, count attacks
matched_attacks = sum(1 for fid in matched if loader._flow_lookup[fid])
matched_benign = sum(1 for fid in matched if not loader._flow_lookup[fid])
print(f"Of matched: {matched_attacks:,} attacks, {matched_benign:,} benign")

# Compute confusion properly
alert_flow_ids = alert_ids  # all alert flow IDs
total_attacks = attack_count
total_benign = benign_count

predicted_attacks = matched_attacks
predicted_benign_as_attack = matched_benign
true_negatives = total_benign - predicted_benign_as_attack
false_negatives = total_attacks - predicted_attacks
tp = predicted_attacks
tn = true_negatives
fp = predicted_benign_as_attack
fn = false_negatives
total = tp + tn + fp + fn

print(f"\n=== My computed confusion ===")
print(f"TP={tp:,}, TN={tn:,}, FP={fp:,}, FN={fn:,}, Total={total:,}")
print(f"Recall={tp/(tp+fn):.4f}, Precision={tp/(tp+fp):.4f}, FPR={fp/(fp+tn):.4f}")

print("\n=== Original script: ===")
print("TP=252610, TN=432352, FP=7679, FN=62, Total=692703")
print("Recall=0.9998, Precision=0.9705, FPR=0.0175")

# KEY: check unmatched - do they have reversed in GT?
rev_matched_count = 0
for fid in list(unmatched)[:500]:
    parts = fid.split("-")
    if len(parts) == 5:
        dst_ip, src_ip, dst_port, src_port, proto = parts
        rev = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
        if rev in loader._flow_lookup:
            rev_matched_count += 1

print(f"\nUnmatched alert fids: {len(unmatched):,}")
print(f"Of first 500 unmatched, reversed in GT: {rev_matched_count}")
print(f"Estimated reverse matches: {rev_matched_count * len(unmatched) / 500:.0f}")

# Check: are unmatched alert fids in GT but we missed them due to IP mapping?
print("\n=== Check IP mapping effect ===")
# What GT flow IDs have src=192.168.10.50?
gt_src_50 = [fid for fid in loader._flow_lookup if fid.startswith(f"192.168.10.50-") and "-" in fid]
print(f"GT fids with src=192.168.10.50: {len(gt_src_50)}")

# What alert fids have src=192.168.10.50 (non-mapped)?
alert_src_50_nonmapped = [fid for fid in alert_ids if fid.startswith(f"192.168.10.50-")]
print(f"Alert fids (non-mapped) with src=192.168.10.50: {len(alert_src_50_nonmapped)}")

# These alerts have dst=172.16.0.1 (the mapped victim)
# GT should have dst=172.16.0.1 with src=192.168.10.50
gt_dst_172 = [fid for fid in loader._flow_lookup if fid.startswith("172.16.0.1-")]
print(f"GT fids with dst=172.16.0.1: {len(gt_dst_172)}")

# Check: do any of these have src=192.168.10.50?
gt_172_from_50 = [fid for fid in gt_dst_172 if fid.startswith("172.16.0.1-192.168.10.50-")]
print(f"GT fids 172.16.0.1 <- 192.168.10.50: {len(gt_172_from_50)}")
if gt_172_from_50:
    print(f"  First: {gt_172_from_50[0]}")

# Hmm, GT has dst=172.16.0.1 but src varies, not necessarily 192.168.10.50
# The alert has src=192.168.10.50, dst=172.16.0.1
# I generate fid1 = "172.16.0.1-192.168.10.50-80-X-6"
# But GT might have "172.16.0.1-<OTHER>-80-X-6" for attacks from a different src