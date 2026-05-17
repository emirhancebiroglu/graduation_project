#!/bin/bash
set -e
export XGBOOST_LIB=$HOME/snort_src/xgboost/lib
export LD_LIBRARY_PATH=${XGBOOST_LIB}:${LD_LIBRARY_PATH}
PLUGIN=$HOME/bitirme/plugins/ddos_aggregator/build
CONFIG=$HOME/bitirme/configs/snort_ddos.lua
RESULTS=$HOME/bitirme/results/ddos_aggregator
PCAPS=$HOME/bitirme/pcaps

rm -f /tmp/ddos_train_data.txt

for day in Monday Tuesday Wednesday Thursday Friday; do
  pcap="${day}-WorkingHours.pcap"
  if [ "$day" = "Wednesday" ]; then pcap="Wednesday-workingHours.pcap"; fi
  alert_dir="$RESULTS/${day}-WorkingHours"
  mkdir -p "$alert_dir"
  rm -f "$alert_dir"/alert_csv.txt "$alert_dir"/snort_output.log
  echo "=== $day ==="
  cd /usr/local/etc/snort
  snort -c "$CONFIG" --plugin-path "$PLUGIN" \
    -r "$PCAPS/$pcap" -A alert_csv -l "$alert_dir" \
    --warn-all > "$alert_dir/snort_output.log" 2>&1
  alerts=$(grep -c 'ALERT' "$alert_dir/snort_output.log" 2>/dev/null || echo 0)
  echo "  Alerts: $alerts"
done

echo ""
echo "Training data: $(wc -l < /tmp/ddos_train_data.txt 2>/dev/null || echo 0) rows"
