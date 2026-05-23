#!/bin/bash
# dump_bruteforce_features.sh — Dump bruteforce features from all CICIDS PCAPs
set -e
BASE_DIR=/home/emirhan/bitirme
CONFIG=${BASE_DIR}/configs/snort_bruteforce.lua
PLUGIN_PATH=${BASE_DIR}/plugins/bruteforce_inspector/build
PCAP_DIR=${BASE_DIR}/pcaps
OUTDIR=/tmp/bfc_dump
mkdir -p "$OUTDIR" /tmp/snort_tmp

declare -A DAY_MAP=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday"]="Thursday-WorkingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

echo "=== Brute Force Feature Dump ==="
for day in Monday Tuesday Wednesday Thursday Friday; do
    pcap="${DAY_MAP[$day]}"
    dump_file="${OUTDIR}/bfc_${day}.txt"
    echo "[${day}] ${pcap}..."
    rm -f /tmp/bfc_train_data.txt
    cd /usr/local/etc/snort
    snort -c "$CONFIG" --plugin-path "$PLUGIN_PATH" -r "${PCAP_DIR}/${pcap}" -A none -l /tmp/snort_tmp > /tmp/snort_tmp/bfc_${day}.log 2>&1 || true
    if [ -f /tmp/bfc_train_data.txt ]; then
        cp /tmp/bfc_train_data.txt "$dump_file"
        echo "  → $(wc -l < "$dump_file") lines"
    else
        echo "  → No dump generated"
    fi
done
echo "=== Done ==="
ls -lh "${OUTDIR}"/*.txt 2>/dev/null | awk '{print $5, $NF}'
