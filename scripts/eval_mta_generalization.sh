#!/bin/bash
set -e
BASE=/home/emirhan/bitirme
RESULTS=$BASE/results/mta_test
PCAP_DIR=$BASE/pcaps/mta
mkdir -p $RESULTS

PCAPS=(
  "2026-01-20-Xworm-infection-traffic.pcap"
  "2026-01-31-traffic-analysis-exercise.pcap"
  "2026-02-28-traffic-analysis-exercise.pcap"
)

cd /usr/local/etc/snort
for pcap in "${PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  outdir="$RESULTS/$name"
  mkdir -p "$outdir"
  LD_LIBRARY_PATH=/home/emirhan/snort_src/xgboost/lib \
  snort -c $BASE/configs/snort_combined.lua \
    --plugin-path $BASE/plugins/ml_inspector/build \
    --plugin-path $BASE/plugins/dos_inspector/build \
    --plugin-path $BASE/plugins/bot_client_inspector/build \
    -r "$PCAP_DIR/$pcap" \
    -A alert_csv \
    -l "$outdir" \
    -q 2>/dev/null
  count=$(wc -l < "$outdir/alert_csv.txt")
  echo "$name: $count alerts"
done

echo ""
echo "=== DETAILED BREAKDOWN ==="
for pcap in "${PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  alert="$RESULTS/$name/alert_csv.txt"
  if [ -f "$alert" ]; then
    total=$(wc -l < "$alert")
    lstm=$(grep -c " 300:" "$alert" 2>/dev/null || echo 0)
    dos=$(grep -c " 301:" "$alert" 2>/dev/null || echo 0)
    botcl=$(grep -c " 306:" "$alert" 2>/dev/null || echo 0)
    echo "$name: total=$total LSTM=$lstm DoS=$dos BotClient=$botcl"
  fi
done
