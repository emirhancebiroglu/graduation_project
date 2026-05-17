#!/bin/bash
set -e
cd /usr/local/etc/snort
PLUGIN=$HOME/bitirme/plugins/portscan_inspector/build
CONFIG=$HOME/bitirme/configs/snort_portscan.lua
ALERT_DIR=$HOME/bitirme/results/portscan

for scan in syn fin null xmas udp masscan_like; do
  pcap="/tmp/attack_pcaps/${scan}_scan.pcap"
  log="${ALERT_DIR}/attack_${scan}"
  mkdir -p "$log"
  rm -f "$log"/*
  snort -c "$CONFIG" --plugin-path "$PLUGIN" -r "$pcap" -A alert_csv -l "$log" --warn-all > "$log/snort_output.log" 2>&1
  alerts=$(grep -c 'ALERT' "$log/snort_output.log" 2>/dev/null || echo 0)
  echo "${scan}: ${alerts} alerts"
  grep 'ALERT' "$log/snort_output.log" | head -3
done
