# Check column alignment
lines = open('/tmp/botcl_train_data.txt').readlines()
header = lines[0].strip()
cols = header.split()
print("Header columns:", len(cols))
for i, c in enumerate(cols):
    print(f"  {i}: {c}")

# Check first data line
parts = lines[1].strip().split()
print(f"\nData columns: {len(parts)}")
for i in range(len(parts)):
    print(f"  {i}: {parts[i]}")
