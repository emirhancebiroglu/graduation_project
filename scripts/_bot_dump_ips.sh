#!/bin/bash
# Check which bot IPs appear in friday_dump
DUMP="/home/emirhan/bitirme/data/snort_dump/bot_client/friday_dump.txt"
echo "=== Bot IPs in friday_dump (col 25 = src_ip decimal) ==="
# Bot IPs:
# 192.168.10.3  = 3232238083
# 192.168.10.5  = 3232238085
# 192.168.10.6  = 3232238086
# 192.168.10.8  = 3232238088
# 192.168.10.9  = 3232238089
# 192.168.10.14 = 3232238094
# 192.168.10.25 = 3232238105
for IP_DEC in 3232238083 3232238085 3232238086 3232238088 3232238089 3232238094 3232238105; do
    COUNT=$(awk -v ip="$IP_DEC" 'NR>1 && $25==ip' "$DUMP" | wc -l)
    echo "  $IP_DEC: $COUNT windows"
done
echo ""
echo "FP IPs that should NOT be positive:"
for IP_DEC in 3232238092 3232238095 3232238097; do
    COUNT=$(awk -v ip="$IP_DEC" 'NR>1 && $25==ip' "$DUMP" | wc -l)
    echo "  $IP_DEC: $COUNT windows"
done
