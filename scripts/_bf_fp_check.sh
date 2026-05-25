#!/bin/bash
# Check bruteforce FP details on Wednesday and Monday
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
PCAP_DIR="$HOME/bitirme/pcaps"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

for day in Wednesday Monday; do
    pcap="$PCAP_DIR/${day}-WorkingHours.pcap"
    [ "$day" = "Wednesday" ] && pcap="$PCAP_DIR/Wednesday-workingHours.pcap"
    OUT="/tmp/bf_fp_${day}"
    mkdir -p "$OUT"
    rm -f "$OUT/alert_csv.txt"
    echo "=== $day ==="
    cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
        -r "$pcap" -A alert_csv -l "$OUT" -q 2>&1 | \
        grep '\[bruteforce\]' | head -20
    echo "Alerts: $(wc -l < "$OUT/alert_csv.txt" 2>/dev/null || echo 0)"
    echo ""
done
