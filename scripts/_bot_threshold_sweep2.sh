#!/bin/bash
# Threshold sweep for bot_client_inspector on FULL Friday PCAP
SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bot_client_inspector/build"
PCAP="$HOME/bitirme/pcaps/Friday-WorkingHours.pcap"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

# Known bot client IPs from CIC Friday
BOT_IPS="192.168.10.3 192.168.10.5 192.168.10.6 192.168.10.8 192.168.10.9 192.168.10.14 192.168.10.25"

echo "=== Bot Client Threshold Sweep (Friday-WorkingHours.pcap) ==="
echo "Bot IPs (GT): $BOT_IPS"
echo ""

for THR in 0.85 0.80 0.75 0.70 0.65 0.60 0.50 0.40 0.30; do
    CFG_TMP="/tmp/snort_bot_thr${THR//./}.lua"
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
    model_path   = "/home/emirhan/bitirme/models/bot_client_model.json",
    window_sec   = 300,
    min_syns     = 3,
}
alert_csv = { file = true }
LUAEOF

    LOGDIR="/tmp/bot_sw_${THR//./}"
    mkdir -p "$LOGDIR"
    rm -f "$LOGDIR/alert_csv.txt"

    cd "$SNORT_ETC" && snort -c "$CFG_TMP" --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP" -A alert_csv -l "$LOGDIR" -q 2>&1 > /dev/null

    # Parse alerted source IPs from alert_csv (col 6 = src:port)
    ALERTED_IPS=$(awk -F',' 'NR>0 && /306:1/ {gsub(/ /,"",$6); split($6,a,":"); print a[1]}' \
        "$LOGDIR/alert_csv.txt" 2>/dev/null | sort -u)

    TP=0; FP=0; TP_LIST=""; FP_LIST=""
    for IP in $ALERTED_IPS; do
        if echo "$BOT_IPS" | grep -qw "$IP"; then
            TP=$((TP+1)); TP_LIST="$TP_LIST $IP"
        else
            FP=$((FP+1)); FP_LIST="$FP_LIST $IP"
        fi
    done
    TOTAL_BOT=7
    if [ $TOTAL_BOT -gt 0 ]; then
        RECALL=$(echo "scale=3; $TP / $TOTAL_BOT" | bc)
    else
        RECALL=0
    fi
    if [ $((TP+FP)) -gt 0 ]; then
        PREC=$(echo "scale=3; $TP / ($TP + $FP)" | bc)
    else
        PREC=0
    fi

    echo "thr=$THR  TP=$TP/7 FP=$FP  recall=$RECALL prec=$PREC"
    if [ -n "$FP_LIST" ]; then echo "         FP IPs:$FP_LIST"; fi
    if [ -n "$TP_LIST" ]; then echo "         TP IPs:$TP_LIST"; fi
done

echo ""
echo "Done."
