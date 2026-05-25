#!/bin/bash
# Regression check after ip-sweep heuristic + dst IP fix
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
CFG="$HOME/bitirme/configs/snort_portscan.lua"
PCAP_DIR="$HOME/bitirme/pcaps"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

echo "=== Friday (attack: expect 36/37 scanner windows) ==="
mkdir -p /tmp/ps_reg_fri && rm -f /tmp/ps_reg_fri/alert_csv.txt
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$PCAP_DIR/Friday-WorkingHours.pcap" -A alert_csv -l /tmp/ps_reg_fri -q 2>&1 | \
    grep '\[portscan\] ALERT' | head -10
FRI=$(wc -l < /tmp/ps_reg_fri/alert_csv.txt 2>/dev/null || echo 0)
echo "Friday alerts: $FRI"

echo ""
echo "=== Monday (benign: expect ≤2 FP) ==="
mkdir -p /tmp/ps_reg_mon && rm -f /tmp/ps_reg_mon/alert_csv.txt
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$PCAP_DIR/Monday-WorkingHours.pcap" -A alert_csv -l /tmp/ps_reg_mon -q 2>&1 | \
    grep '\[portscan\] ALERT' | head -5
MON=$(wc -l < /tmp/ps_reg_mon/alert_csv.txt 2>/dev/null || echo 0)
echo "Monday FP: $MON"
