#!/bin/bash
# dump_botcl_features.sh — Phase 1: Dump bot_client features from all PCAPs
# For each PCAP: run snort, collect feature dump → /tmp/botcl_dump/<pcap_name>.txt
set -e
BASE_DIR=/home/emirhan/bitirme
CONFIG=${BASE_DIR}/configs/snort_bot_client.lua
PLUGIN_PATH=${BASE_DIR}/plugins/bot_client_inspector/build
PCAP_DIR=${BASE_DIR}/pcaps
OUTDIR=/tmp/botcl_dump
mkdir -p "$OUTDIR"

# CICIDS2017 PCAPs
declare -A CICIDS=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday"]="Thursday-WorkingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

# MTA PCAPs
declare -A MTAS=(
    ["xworm"]="mta/2026-01-20-Xworm-infection-traffic.pcap"
    ["31jan"]="mta/2026-01-31-traffic-analysis-exercise.pcap"
    ["28feb"]="mta/2026-02-28-traffic-analysis-exercise.pcap"
)

# CTU-13 PCAPs
declare -A CTUS=(
    ["ctu_042219"]="cupid/042219_1000_0.pcapng"
    ["ctu_052419"]="cupid/052419_1504.pcapng"
    ["ctu_060319"]="cupid/060319_1510.pcapng"
    ["ctu_071219"]="cupid/071219_1331.pcapng"
)

process_pcap() {
    local name=$1
    local pcap_rel=$2
    local pcap_path="${PCAP_DIR}/${pcap_rel}"
    local dump_file="${OUTDIR}/${name}.txt"

    if [ ! -f "$pcap_path" ]; then
        echo "[SKIP] ${pcap_path} not found"
        return
    fi

    # Remove previous dump so "a" mode creates a fresh file
    rm -f /tmp/botcl_train_data.txt

    echo "[PROCESS] ${name} (${pcap_rel})..."
    cd /usr/local/etc/snort
    snort -c "$CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$pcap_path" \
        -A alert_csv \
        -l /tmp/snort_tmp \
        > /tmp/snort_tmp/${name}.log 2>&1 || true

    if [ -f /tmp/botcl_train_data.txt ]; then
        cp /tmp/botcl_train_data.txt "$dump_file"
        lines=$(wc -l < "$dump_file")
        echo "  → ${lines} lines dumped to ${dump_file}"
    else
        echo "  → No dump file generated"
    fi
}

# Process all PCAPs
echo "=== CICIDS2017 ==="
for day in Monday Tuesday Wednesday Thursday Friday; do
    process_pcap "cicids_${day}" "${CICIDS[$day]}"
done

echo ""
echo "=== MTA ==="
for name in xworm 31jan 28feb; do
    process_pcap "mta_${name}" "${MTAS[$name]}"
done

echo ""
echo "=== CTU-13 ==="
for name in ctu_042219 ctu_052419 ctu_060319 ctu_071219; do
    process_pcap "${name}" "${CTUS[$name]}"
done

echo ""
echo "=== Done ==="
ls -lh "${OUTDIR}/"*.txt 2>/dev/null | awk '{print $5, $NF}'
