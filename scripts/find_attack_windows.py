#!/usr/bin/env python3
"""Find attack time windows in CIC-IDS2017 CSVs for PCAP slicing."""
import pandas as pd
from pathlib import Path

DATA = Path("/home/emirhan/bitirme/data/raw/cicids2017")

files = {
    "Wednesday": DATA / "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-DDos": DATA / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-PortScan": DATA / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Tuesday": DATA / "Tuesday-WorkingHours.pcap_ISCX.csv",
}

for name, path in files.items():
    df = pd.read_csv(path, usecols=[" Timestamp", " Label"], low_memory=False)
    df.columns = df.columns.str.strip()
    attacks = df[df["Label"] != "BENIGN"]
    if attacks.empty:
        print(f"{name}: NO ATTACKS")
        continue
    counts = attacks["Label"].value_counts()
    print(f"\n=== {name} ===")
    print(counts.to_string())
    print(f"First: {attacks['Timestamp'].iloc[0]}")
    print(f"Last:  {attacks['Timestamp'].iloc[-1]}")
    # Per label window
    for label in counts.index:
        sub = attacks[attacks["Label"] == label]
        print(f"  {label}: {sub['Timestamp'].iloc[0]} -> {sub['Timestamp'].iloc[-1]} ({len(sub)} flows)")
