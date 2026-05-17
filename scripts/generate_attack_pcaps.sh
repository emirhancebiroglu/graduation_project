#!/bin/bash
set -e
# generate_attack_pcaps.sh — Generate real nmap scan PCAPs
# Runs nmap against localhost with tcpdump capturing the traffic.

OUTDIR="/tmp/nmap_pcaps"
mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/*

TARGET="127.0.0.1"
# Ports that are likely closed (avoid common services)
PORTS="1000-2000"

echo "=== SYN SCAN ==="
timeout 30 tcpdump -i lo -w "$OUTDIR/syn_scan.pcap" 'tcp' 2>/dev/null &
TPID=$!
sleep 0.5
nmap -sS -p "$PORTS" "$TARGET" 2>/dev/null || true
sleep 1
kill $TPID 2>/dev/null || true

echo "=== FIN SCAN ==="
timeout 30 tcpdump -i lo -w "$OUTDIR/fin_scan.pcap" 'tcp' 2>/dev/null &
TPID=$!
sleep 0.5
nmap -sF -p "$PORTS" "$TARGET" 2>/dev/null || true
sleep 1
kill $TPID 2>/dev/null || true

echo "=== NULL SCAN ==="
timeout 30 tcpdump -i lo -w "$OUTDIR/null_scan.pcap" 'tcp' 2>/dev/null &
TPID=$!
sleep 0.5
nmap -sN -p "$PORTS" "$TARGET" 2>/dev/null || true
sleep 1
kill $TPID 2>/dev/null || true

echo "=== XMAS SCAN ==="
timeout 30 tcpdump -i lo -w "$OUTDIR/xmas_scan.pcap" 'tcp' 2>/dev/null &
TPID=$!
sleep 0.5
nmap -sX -p "$PORTS" "$TARGET" 2>/dev/null || true
sleep 1
kill $TPID 2>/dev/null || true

echo "=== UDP SCAN ==="
timeout 30 tcpdump -i lo -w "$OUTDIR/udp_scan.pcap" 'udp' 2>/dev/null &
TPID=$!
sleep 0.5
nmap -sU -p 1-500 "$TARGET" 2>/dev/null || true
sleep 1
kill $TPID 2>/dev/null || true

echo "=== Done ==="
ls -lh "$OUTDIR"/*.pcap 2>/dev/null || echo "(no pcaps - check tcpdump permissions)"
for f in "$OUTDIR"/*.pcap; do
  cnt=$(tcpdump -r "$f" 2>/dev/null | wc -l)
  echo "  $(basename $f): $cnt packets"
done
