#!/bin/bash
# run_portscan_replay.sh — Friday PCAP replay with PortScan Inspector
# Usage: bash scripts/run_portscan_replay.sh

set -e

SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
CONFIG="$HOME/bitirme/configs/snort_portscan.lua"
PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
PCAP_DIR="$HOME/bitirme/pcaps"
OUTPUT_DIR="$HOME/bitirme/results/portscan"

XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

PCAP_FILE="Friday-WorkingHours.pcap"
PCAP_PATH="$PCAP_DIR/$PCAP_FILE"
ALERT_DIR="$OUTPUT_DIR/Friday-WorkingHours"

echo "============================================="
echo " PortScan Inspector — Friday PCAP Replay"
echo "============================================="
echo "Config:      $CONFIG"
echo "Plugin:      $PLUGIN_PATH"
echo "PCAP:        $PCAP_PATH"
echo "Output:      $ALERT_DIR"
echo ""

if [ ! -f "$PLUGIN_PATH/portscan_inspector.so" ]; then
    echo "ERROR: portscan_inspector.so not found!"
    echo "Build first: cd ~/bitirme/plugins/portscan_inspector && ./build.sh"
    exit 1
fi

if [ ! -f "$XGBOOST_LIB/libxgboost.so" ]; then
    echo "ERROR: libxgboost.so not found: $XGBOOST_LIB"
    exit 1
fi

if [ ! -f "$PCAP_PATH" ]; then
    echo "ERROR: PCAP not found: $PCAP_PATH"
    exit 1
fi

mkdir -p "$ALERT_DIR"
# Clear previous alerts
rm -f "$ALERT_DIR/alert_csv.txt"

echo "Starting Snort replay..."
START_TIME=$(date +%s)

cd "$SNORT_ETC" && $SNORT_BIN \
    -c "$CONFIG" \
    --plugin-path "$PLUGIN_PATH" \
    -r "$PCAP_PATH" \
    -A alert_csv \
    -l "$ALERT_DIR" \
    --warn-all \
    -q \
    2>/dev/null

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

ALERT_FILE="$ALERT_DIR/alert_csv.txt"
if [ -f "$ALERT_FILE" ]; then
    ALERT_COUNT=$(wc -l < "$ALERT_FILE")
    echo "Done: $ALERT_COUNT alerts in ${ELAPSED}s"
else
    echo "Done: 0 alerts in ${ELAPSED}s"
    ALERT_COUNT=0
fi

echo ""
echo "Alert file: $ALERT_FILE"
echo "Alert count: $ALERT_COUNT"