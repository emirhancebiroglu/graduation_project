#!/bin/bash
PCAP="$HOME/bitirme/pcaps/cupid/052419_1504.pcapng"
echo "=== 10.10.10.13 SYN timing ==="
tshark -r "$PCAP" -Y "ip.src==10.10.10.13 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time_relative 2>/dev/null | awk 'NR==1{print "first: "$0} END{print "last: "$0}'
echo ""
echo "=== Unique dst IPs count ==="
tshark -r "$PCAP" -Y "ip.src==10.10.10.13 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e ip.dst 2>/dev/null | sort -u | wc -l
