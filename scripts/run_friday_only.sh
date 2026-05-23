#!/bin/bash
OUTDIR=/home/emirhan/bitirme/results/bot_client/Friday_v6
mkdir -p "$OUTDIR"
cd /usr/local/etc/snort
snort -c /home/emirhan/bitirme/configs/snort_bot_client.lua \
  --plugin-path /home/emirhan/bitirme/plugins/bot_client_inspector/build \
  -r /home/emirhan/bitirme/pcaps/Friday-WorkingHours.pcap \
  -A alert_csv -l "$OUTDIR" > "$OUTDIR/snort_output.log" 2>&1
echo "Done: $(wc -l < "$OUTDIR/alert_csv.txt") alerts"
