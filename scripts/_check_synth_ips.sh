#!/bin/bash
for f in /home/emirhan/bitirme/data/snort_dump/bruteforce/synth_*.txt; do
    name=$(basename "$f")
    ips=$(awk 'NR>1 {print $NF}' "$f" | sort -u | tr '\n' ',')
    echo "$name: $ips"
done
