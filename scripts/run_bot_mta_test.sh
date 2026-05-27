#!/bin/bash
set -e
BASE_DIR=/home/emirhan/bitirme
PLUGIN_PATH=${BASE_DIR}/plugins/bot_client_inspector/build
CONFIG=${BASE_DIR}/configs/snort_bot_client.lua
RESULTS=${BASE_DIR}/results/bot_client
PCAPS=${BASE_DIR}/pcaps/mta

export LD_LIBRARY_PATH="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib:${LD_LIBRARY_PATH}"

echo "=== MTA Xworm (botnet C2) ==="
outdir="${RESULTS}/mta_xworm"
mkdir -p "$outdir"
rm -f "$outdir/alert_csv.txt"
cd /usr/local/etc/snort
snort -c "$CONFIG" --plugin-path "$PLUGIN_PATH" -r "${PCAPS}/2026-01-20-Xworm-infection-traffic.pcap" -A alert_csv -l "$outdir" > "$outdir/snort_output.log" 2>&1
count=$(grep -c 'ALERT' "$outdir/snort_output.log" 2>/dev/null || echo 0)
echo "  Xworm alerts: ${count}"

echo "=== MTA 31-Jan (malware) ==="
outdir="${RESULTS}/mta_31jan"
mkdir -p "$outdir"
rm -f "$outdir/alert_csv.txt"
cd /usr/local/etc/snort
snort -c "$CONFIG" --plugin-path "$PLUGIN_PATH" -r "${PCAPS}/2026-01-31-traffic-analysis-exercise.pcap" -A alert_csv -l "$outdir" > "$outdir/snort_output.log" 2>&1
count=$(grep -c 'ALERT' "$outdir/snort_output.log" 2>/dev/null || echo 0)
echo "  31-Jan alerts: ${count}"

echo "=== MTA 28-Feb (benign) ==="
outdir="${RESULTS}/mta_28feb"
mkdir -p "$outdir"
rm -f "$outdir/alert_csv.txt"
cd /usr/local/etc/snort
snort -c "$CONFIG" --plugin-path "$PLUGIN_PATH" -r "${PCAPS}/2026-02-28-traffic-analysis-exercise.pcap" -A alert_csv -l "$outdir" > "$outdir/snort_output.log" 2>&1
count=$(grep -c 'ALERT' "$outdir/snort_output.log" 2>/dev/null || echo 0)
echo "  28-Feb alerts: ${count}"

echo "=== Done ==="
