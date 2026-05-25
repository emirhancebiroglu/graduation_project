#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bot_client_inspector/build"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

CFG_TMP="/tmp/snort_bot_benign.lua"
cat > "$CFG_TMP" << 'LUAEOF'
HOME_NET     = 'any'
EXTERNAL_NET = 'any'
include 'snort_defaults.lua'
stream = { } stream_ip = { } stream_icmp = { }
stream_tcp = { } stream_udp = { } stream_user = { } stream_file = { }
netflow = { }
wizard = default_wizard
references      = default_references
classifications = default_classifications
ips = {
    variables = default_variables,
    include = '/home/emirhan/bitirme/configs/bot_client_rules.rules',
}
bot_client_inspector = {
    threshold    = 0.85,
    model_path   = "/home/emirhan/bitirme/models/bot_client_v4.json",
    window_sec   = 300,
    min_syns     = 3,
}
alert_csv = { file = true }
LUAEOF

echo "=== Bot Client v4 Benign Day Evaluation (thr=0.85) ==="

for DAY in Monday Tuesday Wednesday Thursday; do
    PCAP="$HOME/bitirme/pcaps/${DAY}-WorkingHours.pcap"
    if [ ! -f "$PCAP" ]; then
        echo "  $DAY: SKIP (no PCAP)"
        continue
    fi
    LOGDIR="/tmp/bot_benign_${DAY}"
    mkdir -p "$LOGDIR"

    LOG=$(cd "$SNORT_ETC" && snort -c "$CFG_TMP" --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP" -A alert_csv -l "$LOGDIR" 2>&1)

    ALERT_IPS=$(echo "$LOG" | grep '\[botcl\] ALERT' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
    COUNT=$(echo "$LOG" | grep -c '\[botcl\] ALERT')

    if [ "$COUNT" -eq 0 ]; then
        echo "  $DAY: PASS (0 FP)"
    else
        echo "  $DAY: FAIL ($COUNT FP alerts) — IPs: $ALERT_IPS"
    fi
done
