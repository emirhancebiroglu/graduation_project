#!/bin/bash
# eval_portscan_generalization.sh — Phase 1 generalization test: ProbingDataset PCAPs
# Tests: nmap, hping3, masscan_5k, unicornscan, zmap_tcp, zmap_tcp_5k
# Expected: >= 1 GID:302 alert per scanner PCAP

set -e

SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
CFG="$HOME/bitirme/configs/snort_portscan.lua"
PCAP_DIR="$HOME/bitirme/data/ProbingDataset-v1.0.0/gubertoli-ProbingDataset-134bec8/pcap"

XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

PASS=0
FAIL=0

echo "========================================"
echo " PortScan Generalization Test (Phase 1)"
echo " Config: snort_portscan.lua (v4d, mdp=1)"
echo "========================================"
echo ""

for pcap in nmap.pcapng hping3.pcapng masscan_5k.pcapng unicornscan.pcapng zmap_tcp.pcapng zmap_tcp_5k.pcapng; do
    NAME=$(basename "$pcap" .pcapng)
    OUT="/tmp/ps_gen_${NAME}"
    mkdir -p "$OUT"
    rm -f "$OUT/alert_csv.txt"

    cd "$SNORT_ETC" && snort \
        -c "$CFG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP_DIR/$pcap" \
        -A alert_csv \
        -l "$OUT" \
        -q 2>&1 | grep "\[portscan\] ALERT" | head -3

    ALERTS=$(wc -l < "$OUT/alert_csv.txt" 2>/dev/null || echo 0)
    # Trim whitespace
    ALERTS=$(echo "$ALERTS" | tr -d ' ')

    if [ "$ALERTS" -ge 1 ]; then
        STATUS="PASS"
        PASS=$((PASS + 1))
    else
        STATUS="FAIL"
        FAIL=$((FAIL + 1))
    fi
    echo "  $NAME: $ALERTS alerts → $STATUS"
done

echo ""
echo "========================================"
echo " Results: $PASS PASS, $FAIL FAIL"
echo "========================================"
