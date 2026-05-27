#!/bin/bash
# run_community_replay.sh — Community rules baseline replay
# Runs community config against specific PCAPs to check if community rules
# detect the same attacks our ML models catch.
set -e
BASE_DIR=/home/emirhan/bitirme
CONFIG=${BASE_DIR}/configs/snort_community.lua
PCAP_DIR=${BASE_DIR}/pcaps
RESULT_DIR=${BASE_DIR}/results/community

declare -A DAY_MAP=(
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

echo "=== Community Rules Baseline ==="
echo "Config: ${CONFIG}"
echo ""

for day in Tuesday Wednesday Friday; do
    pcap="${DAY_MAP[$day]}"
    outdir="${RESULT_DIR}/${day}"
    mkdir -p "$outdir"
    rm -f "$outdir/alert_csv.txt" "$outdir/snort_output.log"

    echo "[${day}] Replaying ${pcap}..."
    cd /usr/local/etc/snort
    snort -c "$CONFIG" \
        -r "${PCAP_DIR}/${pcap}" \
        -A alert_csv \
        -l "$outdir" \
        > "$outdir/snort_output.log" 2>&1

    alert_count=$(wc -l < "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
    echo "  Alert CSV rows: ${alert_count}"

    # Count unique alerted IPs (for IP-level comparison)
    unique_ips=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$outdir/alert_csv.txt" 2>/dev/null | sort -u | wc -l || echo 0)
    echo "  Unique alerted IPs: ${unique_ips}"
    echo ""
done

echo "=== Done ==="
