#!/bin/bash
# run_bot_client_replay.sh — Multi-day bot_client benchmark
# Runs bot_client_inspector against all 5 CICIDS2017 PCAPs

set -e
BASE_DIR=/home/emirhan/bitirme
RESULT_DIR=${BASE_DIR}/results/bot_client
CONFIG=${BASE_DIR}/configs/snort_bot_client.lua
PLUGIN_PATH=${BASE_DIR}/plugins/bot_client_inspector/build
PCAP_DIR=${BASE_DIR}/pcaps

declare -A DAY_MAP=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday"]="Thursday-WorkingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

echo "=== Bot Client Multi-Day Benchmark ==="
echo "Config: ${CONFIG}"
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

    count=$(grep -c 'ALERT' "$outdir/snort_output.log" 2>/dev/null || echo 0)
    alert_count=$(wc -l < "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
    unique=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$outdir/alert_csv.txt" 2>/dev/null | sort -u | wc -l || echo 0)
    echo "  Alerts: ${alert_count} rows, ${unique} unique IPs"
    echo ""
done

echo "=== Done ==="
