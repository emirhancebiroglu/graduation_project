#!/bin/bash
echo "=== Checking for 10.0.0.1 (167772161) contamination in benign dumps ==="
for f in monday_dump.txt wednesday_dump.txt thursday_dump.txt; do
    count=$(awk 'NR>1{print $NF}' /home/emirhan/bitirme/data/snort_dump/bruteforce/$f | grep -c '^167772161$' 2>/dev/null || echo 0)
    echo "  $f: $count rows with 10.0.0.1"
done
