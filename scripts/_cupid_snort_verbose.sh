#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
CFG="$HOME/bitirme/configs/snort_portscan.lua"
PCAP="$HOME/bitirme/pcaps/cupid/052419_1504.pcapng"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"
mkdir -p /tmp/ps_cupid_dbg
rm -f /tmp/ps_cupid_dbg/alert_csv.txt
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$PCAP" -A alert_csv -l /tmp/ps_cupid_dbg 2>&1 | \
    grep -E '\[portscan\]|ALERT|alert|score|window|inference|ERROR|error' | head -30
echo "---"
echo "alert_csv lines: $(wc -l < /tmp/ps_cupid_dbg/alert_csv.txt 2>/dev/null || echo 0)"
