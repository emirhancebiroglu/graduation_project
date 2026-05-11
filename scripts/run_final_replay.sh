#!/bin/bash
# run_final_replay.sh — Final Wednesday replay: t=0.90, mp=2, Rule 3 port filter
set -e

RUN_DIR="/home/emirhan/bitirme/results/xgboost/FINAL_20260510"
ALERT_DIR="${RUN_DIR}/Wednesday-workingHours"
XGBOOST_LIB="/home/emirhan/snort_src/xgboost/lib"

export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p "$ALERT_DIR"

echo "======================================="
echo " Final Wednesday Replay"
echo " threshold=0.90  max_packets=2"
echo " Rule 3: dst_port IN {53,137,389} suppressed"
echo " Run dir: $RUN_DIR"
echo "======================================="

START=$(date +%s)

cd /usr/local/etc/snort && snort \
    -c /home/emirhan/bitirme/configs/snort_xgb.lua \
    --plugin-path /home/emirhan/bitirme/plugins/xgb_inspector/build \
    -r /home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap \
    -A alert_csv \
    -l "$ALERT_DIR" \
    --warn-all \
    -q \
    2>"${RUN_DIR}/snort_stderr.log"

END=$(date +%s)
ELAPSED=$((END - START))

ALERT_FILE="${ALERT_DIR}/alert_csv.txt"
if [ -f "$ALERT_FILE" ]; then
    ALERTS=$(wc -l < "$ALERT_FILE")
else
    ALERTS=0
fi

echo "Done: ${ALERTS} alerts in ${ELAPSED}s"
echo ""

# Confusion matrix (v1 — original methodology)
cd /home/emirhan/bitirme/scripts
python3 xgb_flowid_confusion_wednesday.py \
    --alert-dir "$RUN_DIR" \
    --csv-dir   /home/emirhan/bitirme/data/raw/cicids2017 \
    --output    "${RUN_DIR}/confusion_matrix.txt" \
    2>/dev/null

echo ""
echo "Confusion matrix:"
cat "${RUN_DIR}/confusion_matrix.txt"
