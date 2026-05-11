import csv

with open("/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv", newline="", encoding="utf-8", errors="replace") as f:
    r = csv.DictReader(f)
    labels_seen = set()
    for i, row in enumerate(r):
        label = row.get("Label", "")
        labels_seen.add(repr(label))
        if i < 3:
            print(f"Row {i}: label={repr(label)}")
        if i > 100000:
            break
    print(f"\nUnique label values: {sorted(labels_seen)}")
    benign_count = sum(1 for row in open("/home/emirhan/bitirme/data/raw/cicids2017/Wednesday-workingHours.pcap_ISCX.csv") if "BENIGN" in row)
    print(f"\nLines containing 'BENIGN': {benign_count}")