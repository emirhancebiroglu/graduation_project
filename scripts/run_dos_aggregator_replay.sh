#!/bin/bash
set -e
RESULT_DIR=/home/emirhan/bitirme/results/dos_aggregator
CONFIG=/home/emirhan/bitirme/configs/snort_dos_aggregator.lua
PLUGIN_PATH=/home/emirhan/bitirme/plugins/dos_aggregator/build
PCAP_DIR=/home/emirhan/bitirme/pcaps

declare -A DAY_MAP=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday"]="Thursday-WorkingHours.pcap"
    ["Friday"]="Friday-WorkingHours.pcap"
)

DUMP_BASE="/tmp/dos_train_data.txt"

echo "=== DoS Aggregator Multi-Day (with per-day dumps) ==="
for day in Monday Tuesday Wednesday Thursday Friday; do
    pcap="${DAY_MAP[$day]}"
    outdir="${RESULT_DIR}/${day}"
    mkdir -p "$outdir"
    rm -f "$outdir/alert_csv.txt"
    rm -f "$DUMP_BASE"
    echo "[${day}] $pcap..."
    cd /usr/local/etc/snort
    snort -c "$CONFIG" --plugin-path "$PLUGIN_PATH" -r "${PCAP_DIR}/${pcap}" -A alert_csv -l "$outdir" > "$outdir/snort.log" 2>&1
    cnt=$(wc -l < "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
    echo "  Alerts: $cnt"
    if [ -f "$DUMP_BASE" ]; then
        cp "$DUMP_BASE" "$RESULT_DIR/dos_train_data_${day}.txt"
        echo "  Dump: $(wc -l < "$DUMP_BASE") windows"
    fi
done
echo "=== Done ==="
