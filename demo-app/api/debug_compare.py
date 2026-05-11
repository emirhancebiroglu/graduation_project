import csv
import pandas as pd
from pathlib import Path

csv_path = Path("/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv")

print("=== PANDAS VERSION ===")
df = pd.read_csv(csv_path, low_memory=False, on_bad_lines="skip",
    encoding="utf-8", encoding_errors="replace", usecols=["Flow ID", "Label"])
df.columns = df.columns.str.strip()
print("Columns:", list(df.columns))
print("Shape:", df.shape)
print("Sample rows:")
print(df[["Flow ID", "Label"]].head(3))
print()

# Check first few flow IDs
for i, (fid, label) in enumerate(zip(df["Flow ID"].head(3), df["Label"].head(3))):
    print(f"  {repr(fid)} | {repr(label)}")

# Count unique flow IDs
print(f"\nUnique flow IDs (pandas): {df['Flow ID'].nunique()}")
print(f"Unique labels: {df['Label'].nunique()}")
print(f"Label distribution:\n{df['Label'].value_counts().head(10)}")

print("\n=== CSV.DictReader VERSION ===")
gt_flow_ids = {}
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    # Strip keys
    reader.fieldnames = [k.strip() for k in reader.fieldnames]
    for row in reader:
        fid = row.get("Flow ID", "").strip().strip("\r\n")
        label = row.get("Label", "").strip().strip("\r\n")
        if fid:
            gt_flow_ids[fid] = label

print(f"Unique flow IDs (csv): {len(gt_flow_ids)}")
print("Sample entries:")
for i, (fid, label) in enumerate(list(gt_flow_ids.items())[:3]):
    print(f"  {repr(fid)} | {repr(label)}")

# Find common flow IDs
gt_pandas_ids = set(df["Flow ID"].dropna().unique())
gt_csv_ids = set(gt_flow_ids.keys())
common = gt_pandas_ids & gt_csv_ids
print(f"\nCommon flow IDs between pandas and csv: {len(common)}")
print(f"Pandas only: {len(gt_pandas_ids - gt_csv_ids)}")
print(f"CSV only: {len(gt_csv_ids - gt_pandas_ids)}")

# Sample from pandas that are NOT in csv
only_pandas = list(gt_pandas_ids - gt_csv_ids)[:3]
print(f"\nSample pandas-only flow IDs:")
for fid in only_pandas:
    label = df[df["Flow ID"] == fid]["Label"].iloc[0]
    print(f"  {repr(fid)} | {repr(label)}")

# Sample from csv that are NOT in pandas
only_csv = list(gt_csv_ids - gt_pandas_ids)[:3]
print(f"\nSample csv-only flow IDs:")
for fid in only_csv:
    print(f"  {repr(fid)} | {repr(gt_flow_ids[fid])}")