#!/bin/bash
set -e
BASE_DIR=/home/emirhan/bitirme
RESULT_DIR=${BASE_DIR}/results/bruteforce
CONFIG=${BASE_DIR}/configs/snort_bruteforce.lua
PLUGIN_PATH=${BASE_DIR}/plugins/bruteforce_inspector/build
PCAP_DIR=${BASE_DIR}/pcaps

declare -A DAY_MAP=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday"]="Thursday-WorkingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

echo "=== Brute Force Multi-Day Benchmark ==="
echo ""

for day in Monday Tuesday Wednesday Thursday Friday; do
    pcap="${DAY_MAP[$day]}"
    outdir="${RESULT_DIR}/${day}"
    mkdir -p "$outdir"
    rm -f "$outdir/alert_csv.txt"

    echo "[${day}] Replaying ${pcap}..."
    cd /usr/local/etc/snort
    snort -c "$CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "${PCAP_DIR}/${pcap}" \
        -A alert_csv \
        -l "$outdir" \
        > "$outdir/snort_output.log" 2>&1

    alerts=$(wc -l < "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
    unique=$(grep -oP 'ALERT: \K[\d.]+' "$outdir/snort_output.log" 2>/dev/null | sort -u | wc -l || echo 0)
    echo "  Alerts: ${alerts} rows, ${unique} unique IPs"
    if [ "$unique" -gt 0 ]; then
        grep -oP 'ALERT: \K[\d.]+' "$outdir/snort_output.log" | sort -u | while read ip; do
            cnt=$(grep -c "$ip" "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
            echo "    ${ip}: ${cnt} alerts"
        done
    fi
    echo ""
done

echo "=== Done ==="
