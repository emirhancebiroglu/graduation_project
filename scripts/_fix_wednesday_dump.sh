#!/bin/bash
DUMP="/home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt"
BACKUP="${DUMP}.bak"
cp "$DUMP" "$BACKUP"
echo "Backup: $BACKUP"

# Remove rows with 10.0.0.1 (167772161) — synthetic attacker IP contamination
grep -v '^[^#].*167772161$' "$DUMP" > "${DUMP}.clean"
mv "${DUMP}.clean" "$DUMP"

echo "After fix:"
wc -l "$DUMP"
head -2 "$DUMP"
