#!/bin/bash
# check_community_ips.sh — Check if community rules detect our attacker IPs
for day in Tuesday Wednesday Friday; do
  echo "=== $day ==="
  for ip in 172.16.0.1 192.168.10.5 192.168.10.8 192.168.10.9 192.168.10.12 192.168.10.14 192.168.10.15 192.168.10.17 192.168.10.50; do
    f="/home/emirhan/bitirme/results/community/$day/alert_csv.txt"
    if [ -f "$f" ]; then
      c=$(grep -c "$ip" "$f" 2>/dev/null || echo 0)
      if [ "$c" -gt 0 ]; then
        echo "  $ip: $c alerts"
      fi
    fi
  done
done
echo ""
echo "=== Per-GID summary ==="
for day in Tuesday Wednesday Friday; do
  f="/home/emirhan/bitirme/results/community/$day/alert_csv.txt"
  if [ -f "$f" ]; then
    echo "--- $day ---"
    awk -F',' '{gid=$9; gsub(/^[[:space:]]+|[[:space:]]+$/,"",gid); split(gid,a,":"); g=a[1]} {cnt[g]++} END{for(g in cnt) print "  GID "g": "cnt[g]" alerts"}' "$f" | sort
  fi
done
