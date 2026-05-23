#!/bin/bash
BASE=/home/emirhan/bitirme
OUTDIR="$BASE/results/mta_test/combined_v2"
mkdir -p "$OUTDIR"
PCAPS=(
  "2026-01-20-Xworm-infection-traffic.pcap"
  "2026-01-31-traffic-analysis-exercise.pcap"
  "2026-02-28-traffic-analysis-exercise.pcap"
)
cd /usr/local/etc/snort
for pcap in "${PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  pcap_out="$OUTDIR/$name"
  mkdir -p "$pcap_out"
  LD_LIBRARY_PATH=/home/emirhan/snort_src/xgboost/lib \
  snort -c "$BASE/configs/snort_combined.lua" \
    --plugin-path "$BASE/plugins/ml_inspector/build" \
    --plugin-path "$BASE/plugins/dos_inspector/build" \
    --plugin-path "$BASE/plugins/bot_client_inspector/build" \
    -r "$BASE/pcaps/mta/$pcap" \
    -A alert_csv \
    -l "$pcap_out" 2>"$pcap_out/stderr.log"
  echo "=== $name ==="
  total=$(wc -l < "$pcap_out/alert_csv.txt")
  lstm=0; dos=0; botcl=0
  if [ -f "$pcap_out/alert_csv.txt" ]; then
    lstm=$(grep -c ' 300:' "$pcap_out/alert_csv.txt" 2>/dev/null || echo 0)
    dos=$(grep -c ' 301:' "$pcap_out/alert_csv.txt" 2>/dev/null || echo 0)
    botcl=$(grep -c ' 306:' "$pcap_out/alert_csv.txt" 2>/dev/null || echo 0)
  fi
  echo "  total=$total LSTM=$lstm DoS=$dos BotClient=$botcl"
  grep 'botcl' "$pcap_out/stderr.log" | tail -5
  echo ""
done
