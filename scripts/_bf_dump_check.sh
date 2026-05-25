#!/bin/bash
echo "=== Wednesday dump IPs ==="
awk 'NR>1{print $NF}' /home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt | sort | uniq -c

echo ""
echo "=== Monday dump IPs ==="
awk 'NR>1{print $NF}' /home/emirhan/bitirme/data/snort_dump/bruteforce/monday_dump.txt | sort | uniq -c | head -20
