#!/bin/bash
# Check 192.168.10.5 (3232238085) windows in wednesday dump
DUMP="/home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt"
echo "=== 192.168.10.5 windows in wednesday_dump (score col 12) ==="
awk 'NR>1 && $13==3232238085 {print NR, $0}' "$DUMP"
echo "=== count ==="
awk 'NR>1 && $13==3232238085' "$DUMP" | wc -l
