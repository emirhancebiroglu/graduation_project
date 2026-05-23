#!/bin/bash
# run_all_portscan_replays.sh — Collect training data from all weekday PCAPs
set -e

export XGBOOST_LIB=$HOME/snort_src/xgboost/lib
export LD_LIBRARY_PATH=${XGBOOST_LIB}:${LD_LIBRARY_PATH}
PLUGIN=$HOME/bitirme/plugins/portscan_inspector/build
CONFIG=$HOME/bitirme/configs/snort_portscan.lua
RESULTS=$HOME/bitirme/results/portscan
PCAPS=$HOME/bitirme/pcaps

declare -A DAYS
DAYS["Monday"]="Monday-WorkingHours.pcap"
DAYS["Tuesday"]="Tuesday-WorkingHours.pcap"
DAYS["Wednesday"]="Wednesday-workingHours.pcap"
DAYS["Thursday"]="Thursday-WorkingHours.pcap"
DAYS["Friday"]="Friday-WorkingHours.pcap"

rm -f /tmp/portscan_train_data.txt

for day in Monday Tuesday Wednesday Thursday Friday; do
    pcap=${DAYS[$day]}
    alert_dir="$RESULTS/${day}-WorkingHours"
    mkdir -p "$alert_dir"
    rm -f "$alert_dir"/alert_csv.txt "$alert_dir"/snort_output.log

    echo "=== Replaying $day ($pcap) ==="
    cd /usr/local/etc/snort
    snort -c "$CONFIG" --plugin-path "$PLUGIN" \
        -r "$PCAPS/$pcap" -A alert_csv -l "$alert_dir" \
        --warn-all > "$alert_dir/snort_output.log" 2>&1

    alerts=$(grep -c 'portscan.*ALERT' "$alert_dir/snort_output.log" 2>/dev/null || echo 0)
    echo "  Alerts: $alerts"
done

echo ""
echo "=== Training data collection complete ==="
echo "Total samples:"
wc -l /tmp/portscan_train_data.txt 2>/dev/null || echo "  (no data)"
echo "Scanner samples:"
grep -c '^1 ' /tmp/portscan_train_data.txt 2>/dev/null || echo 0
echo "Benign samples:"
grep -c '^0 ' /tmp/portscan_train_data.txt 2>/dev/null || echo 0
