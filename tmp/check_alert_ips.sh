#!/bin/bash
log=$1
for ip in 205.174.165.73 52.6.13.28 52.7.235.158 192.168.10.5 192.168.10.8 192.168.10.9 192.168.10.14 192.168.10.15; do
    count=$(grep -c "$ip" "$log" 2>/dev/null || echo 0)
    echo "$ip: $count"
done
echo "---"
echo "Unique dst IPs alerted:"
grep 'ALERT' "$log" | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | head -20
echo "---"
echo "Unique dst IPs in all botc2 logs:"
grep '\[botc2\]' "$log" | grep -oP '(?<= )\d+\.\d+\.\d+\.\d+(?= syns)' | sort -u | head -20
