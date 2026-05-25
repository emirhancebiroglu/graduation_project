#!/bin/bash
# Parse results from already-run threshold sweep
PCAP="$HOME/bitirme/pcaps/Friday-WorkingHours.pcap"
BOT_IPS="192.168.10.3 192.168.10.5 192.168.10.6 192.168.10.8 192.168.10.9 192.168.10.14 192.168.10.25"

echo "=== Bot Client Threshold Sweep Results ==="
echo "GT Bot IPs: $BOT_IPS"
echo ""

for THR in 0.85 0.80 0.75 0.70 0.65 0.60 0.50 0.40 0.30; do
    LOGDIR="/tmp/bot_sw_${THR//./}"
    if [ ! -f "$LOGDIR/alert_csv.txt" ]; then
        echo "thr=$THR  MISSING LOG"
        continue
    fi

    # alert_csv col 7 = src:port (0-indexed: field 7 after splitting on ', ')
    # Format: timestamp, pktnum, proto, type, len, direction, src:port, dst:port, gid, action
    ALERTED_IPS=$(awk -F', ' '{split($7,a,":"); print a[1]}' \
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
    RECALL=$(echo "scale=3; $TP / $TOTAL_BOT" | bc)
    if [ $((TP+FP)) -gt 0 ]; then
        PREC=$(echo "scale=3; $TP / ($TP + $FP)" | bc)
    else
        PREC="N/A"
    fi

    printf "thr=%.2f  TP=%d/7 FP=%d  recall=%s prec=%s\n" $THR $TP $FP "$RECALL" "$PREC"
    if [ -n "$TP_LIST" ]; then echo "         TP:$TP_LIST"; fi
    if [ -n "$FP_LIST" ]; then echo "         FP:$FP_LIST"; fi
done
