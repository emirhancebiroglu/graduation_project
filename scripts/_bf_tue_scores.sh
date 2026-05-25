#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p /tmp/bf_tue_sc
rm -f /tmp/bf_tue_sc/alert_csv.txt /tmp/bfc_train_data.txt

cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Tuesday-WorkingHours.pcap" \
    -A alert_csv -l /tmp/bf_tue_sc -q 2>&1 | \
    grep '\[bfc\]' | grep 'ALERT'

echo "=== alert_csv ==="
cat /tmp/bf_tue_sc/alert_csv.txt 2>/dev/null | head -20

echo "=== attack window scores ==="
awk 'NR>1 && $1==1 {print $12, $0}' /tmp/bfc_train_data.txt 2>/dev/null | sort -rn | head -20
