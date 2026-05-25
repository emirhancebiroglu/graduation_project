#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p /tmp/bf_tue_asc
rm -f /tmp/bfc_train_data.txt

cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Tuesday-WorkingHours.pcap" \
    -A alert_csv -l /tmp/bf_tue_asc -q 2>&1 | \
    grep '\[bfc\]'

echo "=== attacker 172.16.0.1 (2886729729) windows ==="
awk 'NR>1 && $13==2886729729 {print NR, "score=" $12, $0}' /tmp/bfc_train_data.txt | head -30
