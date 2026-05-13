#!/bin/bash
set -e

cd ~/bitirme/plugins/portscan_inspector
export XGBOOST_LIB=$HOME/snort_src/xgboost/lib
export LD_LIBRARY_PATH=${XGBOOST_LIB}:${LD_LIBRARY_PATH}

ALERT_DIR=$HOME/bitirme/results/portscan/Friday-WorkingHours
mkdir -p "$ALERT_DIR"
rm -f "$ALERT_DIR"/alerts.txt "$ALERT_DIR"/alert_fast.txt "$ALERT_DIR"/alert_csv.txt

cd /usr/local/etc/snort
snort -c "$HOME/bitirme/configs/snort_portscan.lua" \
  --plugin-path "$HOME/bitirme/plugins/portscan_inspector/build" \
  -r "$HOME/bitirme/pcaps/Friday-WorkingHours.pcap" \
  -A alert_csv -l "$ALERT_DIR" \
  --warn-all > "$ALERT_DIR/snort_output.log" 2>&1

echo "Exit code: $?"
echo "---"
echo "Cross-flow alerts:"
grep -c 'portscan.*ALERT' "$ALERT_DIR/snort_output.log" 2>/dev/null || echo 0
echo "Per-flow alert CSV lines:"
wc -l < "$ALERT_DIR/alert_csv.txt" 2>/dev/null || echo 0
echo "---"
echo "Sample cross-flow logs:"
grep 'portscan' "$ALERT_DIR/snort_output.log" | tail -20
