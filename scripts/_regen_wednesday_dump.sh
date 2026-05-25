#!/bin/bash
# Regenerate wednesday_dump.txt from real CIC Wednesday PCAP
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
PCAP="$HOME/bitirme/pcaps/Wednesday-workingHours.pcap"
DUMP_OUT="$HOME/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

# The C++ plugin dumps to /tmp/bfc_train_data.txt
rm -f /tmp/bfc_train_data.txt

echo "Running Wednesday PCAP through bruteforce inspector to regenerate dump..."
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$PCAP" -A alert_csv -l /tmp/bf_wed_regen -q 2>&1 | \
    grep '\[bfc\]' | grep -v 'Model:\|scaler\|Whitelist\|ALERT' | wc -l

echo "Windows processed."
if [ -f /tmp/bfc_train_data.txt ]; then
    wc -l /tmp/bfc_train_data.txt
    cp /tmp/bfc_train_data.txt "$DUMP_OUT"
    echo "Saved to $DUMP_OUT"
else
    echo "ERROR: /tmp/bfc_train_data.txt not found"
fi
