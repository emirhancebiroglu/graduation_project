#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p /tmp/bf_wed_scores2
rm -f /tmp/bf_wed_scores2/alert_csv.txt

cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Wednesday-workingHours.pcap" \
    -A alert_csv -l /tmp/bf_wed_scores2 2>&1 | \
    grep '\[bfc\]' | grep -v 'Model:\|scaler\|Whitelist' | head -30
