#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bot_client_inspector/build"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

CFG="/tmp/snort_bot_debug3.lua"
cat > "$CFG" << 'LUAEOF'
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
    model_path   = "/home/emirhan/bitirme/models/bot_client_model.json",
    window_sec   = 300,
    min_syns     = 3,
}
alert_csv = { file = true }
LUAEOF

mkdir -p /tmp/bot_debug3
rm -f /tmp/bot_debug3/alert_csv.txt

echo "=== Bot debug3: ALERT log lines only ==="
cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Friday-WorkingHours.pcap" \
    -A alert_csv -l /tmp/bot_debug3 -q 2>&1 | \
    grep '\[botcl\] ALERT'

echo ""
echo "=== alert_csv unique src IPs ==="
awk -F', ' '{split($7,a,":"); print a[1]}' /tmp/bot_debug3/alert_csv.txt 2>/dev/null | sort -u
