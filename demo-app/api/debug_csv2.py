import csv

csv_path = "/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    raw = f.read(8192)

lines = raw.split("\n")
print("Header:", repr(lines[0][:300]))
print("Row 1:", repr(lines[1][:300]))
print("Header comma count:", lines[0].count(","))

with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    print("DictReader fieldnames:", reader.fieldnames[:5] if reader.fieldnames else None)

    first_row = next(reader)
    print("First row keys:", list(first_row.keys())[:5])
    print("First row Label:", repr(first_row.get("Label", "KEY NOT FOUND")))

with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    header = next(reader)
    print("\nCSV reader header count:", len(header))
    label_idx = None
    for i, h in enumerate(header):
        if "Label" in h or "label" in h:
            print(f"  Label column at index {i}: {repr(h)}")
            label_idx = i

    first_data = next(reader)
    print("First row label value:", repr(first_data[label_idx] if label_idx else "NOT FOUND"))