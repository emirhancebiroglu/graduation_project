#!/bin/bash
BASE=/home/emirhan/bitirme
PCAPS=(2026-01-20-Xworm-infection-traffic.pcap 2026-01-31-traffic-analysis-exercise.pcap 2026-02-28-traffic-analysis-exercise.pcap)
cd /usr/local/etc/snort
for pcap in "${PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  outdir="$BASE/results/mta_test/v2/$name"
  mkdir -p "$outdir"
  LD_LIBRARY_PATH=/home/emirhan/snort_src/xgboost/lib \
  snort -c "$BASE/configs/snort_bot_client.lua" \
    --plugin-path "$BASE/plugins/bot_client_inspector/build" \
    -r "$BASE/pcaps/mta/$pcap" \
    -A alert_csv \
    -l "$outdir" 2>"$outdir/snort_stderr.log"
  echo "=== $name ==="
  grep -i 'botcl' "$outdir/snort_stderr.log"
  echo ""
done
