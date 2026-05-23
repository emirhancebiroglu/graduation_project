#!/bin/bash
BASE=/home/emirhan/bitirme
OUTDIR="$BASE/results/mta_test/v4_17f"
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
  snort -c "$BASE/configs/snort_bot_client.lua" \
    --plugin-path "$BASE/plugins/bot_client_inspector/build" \
    -r "$BASE/pcaps/mta/$pcap" \
    -A alert_csv \
    -l "$pcap_out" 2>"$pcap_out/stderr.log"
  alerts=$(wc -l < "$pcap_out/alert_csv.txt")
  echo "$name: $alerts alerts"
  grep '\[botcl\] ALERT' "$pcap_out/stderr.log"
  echo ""
done
