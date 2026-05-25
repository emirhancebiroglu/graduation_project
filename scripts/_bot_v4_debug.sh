#!/bin/bash
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bot_client_inspector/build"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

CFG_TMP="/tmp/snort_botv4_debug.lua"
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
    threshold    = 0.10,
    model_path   = "/home/emirhan/bitirme/models/bot_client_v4.json",
    window_sec   = 300,
    min_syns     = 3,
}
alert_csv = { file = true }
LUAEOF

mkdir -p /tmp/botv4_debug

echo "=== v4 model debug: threshold=0.10, all [botcl] output ==="
cd "$SNORT_ETC" && snort -c "$CFG_TMP" --plugin-path "$PLUGIN_PATH" \
    -r "$HOME/bitirme/pcaps/Friday-WorkingHours.pcap" \
    -A alert_csv -l /tmp/botv4_debug 2>&1 | \
    grep '\[botcl\]' | head -30
