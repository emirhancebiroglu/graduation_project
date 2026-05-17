#!/bin/bash
# run_botnet_c2_replay.sh — Botnet C2 Inspector Friday replay
set -e
RESULT_DIR=/home/emirhan/bitirme/results/botnet_c2/Friday
mkdir -p "$RESULT_DIR"
rm -f "$RESULT_DIR/alert_csv.txt"

cd /usr/local/etc/snort
snort -c ~/bitirme/configs/snort_botnet_c2.lua \
  --plugin-path ~/bitirme/plugins/botnet_c2_inspector/build \
  -r ~/bitirme/pcaps/Friday-WorkingHours.pcap \
  -A alert_csv -l "$RESULT_DIR" \
  > "$RESULT_DIR/snort_output.log" 2>&1

echo "Exit:$?"
echo "Alerts:"
wc -l < "$RESULT_DIR/alert_csv.txt" 2>/dev/null || echo "0"
