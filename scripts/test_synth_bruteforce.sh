#!/bin/bash
# test_synth_bruteforce.sh — Test bruteforce inspector against synthetic PCAPs
BASE_DIR=/home/emirhan/bitirme
CONFIG=${BASE_DIR}/configs/snort_bruteforce.lua
PLUGIN_PATH=${BASE_DIR}/plugins/bruteforce_inspector/build
PCAP_DIR=${BASE_DIR}/pcaps/synthetic_bruteforce
OUTDIR=/tmp/synth_bruteforce_test
mkdir -p "$OUTDIR" /tmp/snort_tmp

echo "=== Synthetic Brute Force Test (10-feature model) ==="
echo ""

for pcap in "$PCAP_DIR"/*.pcap; do
    name=$(basename "$pcap" .pcap)
    pcap_out="$OUTDIR/$name"
    mkdir -p "$pcap_out"
    
    rm -f "$pcap_out/alert_csv.txt"
    cd /usr/local/etc/snort
    snort -c "$CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$pcap" \
        -A alert_csv \
        -l "$pcap_out" \
        > "$pcap_out/snort_output.log" 2>&1
    
    alert_count=$(wc -l < "$pcap_out/alert_csv.txt" 2>/dev/null || echo 0)
    # Get first score line
    score_line=$(grep "score=" "$pcap_out/snort_output.log" 2>/dev/null | head -1)
    info="${name}: ${alert_count} alerts"
    if [ -n "$score_line" ]; then
        score=$(echo "$score_line" | grep -o "score=[0-9.]*" | head -1 | cut -d= -f2)
        info="${info}, score=${score}"
    fi
    echo "${info}"
done

echo ""
echo "=== Done ==="
