#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p /tmp/bf_172_diag
rm -f /tmp/bf_172_diag/alert_csv.txt

cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Wednesday-workingHours.pcap" \
    -A alert_csv -l /tmp/bf_172_diag 2>&1 | \
    grep '\[bfc\]' | grep -v 'Model:\|scaler\|Whitelist'
echo "=== alert_csv ==="
cat /tmp/bf_172_diag/alert_csv.txt 2>/dev/null || echo "(empty)"
