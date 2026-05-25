#!/bin/bash
# eval_portscan_cupid.sh — Cupid PCAP generalization test

SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
CFG="$HOME/bitirme/configs/snort_portscan.lua"
CUPID="$HOME/bitirme/pcaps/cupid"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p /tmp/ps_cupid_scanner /tmp/ps_cupid_benign
rm -f /tmp/ps_cupid_scanner/alert_csv.txt /tmp/ps_cupid_benign/alert_csv.txt

echo "=== Cupid scanner (052419_1504.pcapng) ==="
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$CUPID/052419_1504.pcapng" -A alert_csv -l /tmp/ps_cupid_scanner -q 2>&1 | \
    grep "\[portscan\] ALERT" | head -5
SCANNER_ALERTS=$(wc -l < /tmp/ps_cupid_scanner/alert_csv.txt 2>/dev/null || echo 0)
echo "Alerts: $SCANNER_ALERTS"

echo ""
echo "=== Cupid benign (060319_1510.pcapng) ==="
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$CUPID/060319_1510.pcapng" -A alert_csv -l /tmp/ps_cupid_benign -q 2>&1 | \
    grep "\[portscan\] ALERT" | head -5
BENIGN_ALERTS=$(wc -l < /tmp/ps_cupid_benign/alert_csv.txt 2>/dev/null || echo 0)
echo "FP Alerts: $BENIGN_ALERTS"

echo ""
if [ "$SCANNER_ALERTS" -ge 1 ] && [ "$BENIGN_ALERTS" -eq 0 ]; then
    echo "RESULT: PASS (scanner detected, 0 FP)"
else
    echo "RESULT: FAIL (scanner=$SCANNER_ALERTS, FP=$BENIGN_ALERTS)"
fi
