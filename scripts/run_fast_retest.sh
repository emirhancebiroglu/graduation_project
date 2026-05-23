#!/bin/bash
# Quick 1-day retest for model improvements
set -e

run_one() {
  local name=$1 pcap=$2 config=$3 plugin=$4 label=$5
  local OUTDIR="/home/emirhan/bitirme/results/${name}/${label}"
  mkdir -p "$OUTDIR"
  rm -f "$OUTDIR/alert_csv.txt"
  cd /usr/local/etc/snort
  snort -c "$config" --plugin-path "$plugin" -r "$pcap" -A alert_csv -l "$OUTDIR" > "$OUTDIR/snort.log" 2>&1
  local alerts=$(wc -l < "$OUTDIR/alert_csv.txt" 2>/dev/null || echo 0)
  echo "[${name}/${label}] ${alerts} alerts"
}

echo "=== Fast Retest ==="
run_one dos_aggregator /home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap \
  /home/emirhan/bitirme/configs/snort_dos_aggregator.lua \
  /home/emirhan/bitirme/plugins/dos_aggregator/build Wednesday_retest &
run_one bruteforce /home/emirhan/bitirme/pcaps/Tuesday-WorkingHours.pcap \
  /home/emirhan/bitirme/configs/snort_bruteforce.lua \
  /home/emirhan/bitirme/plugins/bruteforce_inspector/build Tuesday_retest &
run_one bot_client /home/emirhan/bitirme/pcaps/Friday-WorkingHours.pcap \
  /home/emirhan/bitirme/configs/snort_bot_client.lua \
  /home/emirhan/bitirme/plugins/bot_client_inspector/build Friday_retest &
wait
echo "=== All Done ==="
