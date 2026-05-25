#!/bin/bash
# Evaluate bot_client_v4 model on Friday PCAP via log-based parsing
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bot_client_inspector/build"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

# Correct bot IPs from CICIDS Friday ground truth
BOT_IPS="192.168.10.3 192.168.10.5 192.168.10.6 192.168.10.8 192.168.10.9 192.168.10.14 192.168.10.25"

echo "=== Bot Client v4 Evaluation (threshold sweep) ==="
echo ""

for THR in 0.85 0.75 0.70 0.60 0.50; do
    CFG_TMP="/tmp/snort_botv4_${THR//./}.lua"
    cat > "$CFG_TMP" << LUAEOF
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
    threshold    = $THR,
    model_path   = "/home/emirhan/bitirme/models/bot_client_v4.json",
    window_sec   = 300,
    min_syns     = 3,
}
alert_csv = { file = true }
LUAEOF

    mkdir -p "/tmp/botv4_${THR//./}"

    LOG=$(cd "$SNORT_ETC" && snort -c "$CFG_TMP" --plugin-path "$PLUGIN_PATH" \
        -r "$HOME/bitirme/pcaps/Friday-WorkingHours.pcap" \
        -A alert_csv -l "/tmp/botv4_${THR//./}" 2>&1)

    ALERT_IPS=$(echo "$LOG" | grep '\[botcl\] ALERT' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)

    TP=0; FP=0; TP_LIST=""; FP_LIST=""
    for IP in $ALERT_IPS; do
        if echo "$BOT_IPS" | grep -qw "$IP"; then
            TP=$((TP+1)); TP_LIST="$TP_LIST $IP"
        else
            FP=$((FP+1)); FP_LIST="$FP_LIST $IP"
        fi
    done
    RECALL=$(echo "scale=3; $TP / 7" | bc)
    if [ $((TP+FP)) -gt 0 ]; then
        PREC=$(echo "scale=3; $TP / ($TP + $FP)" | bc)
    else
        PREC="N/A"
    fi

    printf "thr=%.2f  TP=%d/7 FP=%d  recall=%s prec=%s\n" $THR $TP $FP "$RECALL" "$PREC"
    [ -n "$TP_LIST" ] && echo "         TP:$TP_LIST"
    [ -n "$FP_LIST" ] && echo "         FP:$FP_LIST"
done
echo "Done."
