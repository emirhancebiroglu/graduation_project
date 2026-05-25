#!/bin/bash
# Extract FP IPs from alert_csv
for day in Wednesday Monday; do
    outdir="/tmp/bf_fp_${day}"
    csv="$outdir/alert_csv.txt"
    if [ -f "$csv" ]; then
        echo "=== $day FP IPs (from alert_csv) ==="
        cat "$csv"
        echo ""
    else
        echo "=== $day: no alert_csv yet ==="
    fi
done
