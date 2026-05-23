#!/bin/bash
OUTDIR=/tmp/botcl_debug
mkdir -p "$OUTDIR"
rm -f "$OUTDIR/alert_csv.txt"
cd /usr/local/etc/snort
snort -c /home/emirhan/bitirme/configs/snort_bot_client.lua \
  --plugin-path /home/emirhan/bitirme/plugins/bot_client_inspector/build \
  -r /tmp/friday_100k.pcap \
  -A alert_csv -l "$OUTDIR" > "$OUTDIR/snort.log" 2>&1
echo "Done"
grep 'INCSYN\|INFER 192.168.10.16' "$OUTDIR/snort.log" | head -20
