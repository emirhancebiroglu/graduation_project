#!/bin/bash
PCAP="$HOME/bitirme/pcaps/cupid/052419_1504.pcapng"
echo "=== 10.10.10.13 packets after t=73s ==="
tshark -r "$PCAP" -Y "ip.src==10.10.10.13 && frame.time_relative >= 73" \
    -T fields -e frame.time_relative -e tcp.flags 2>/dev/null | head -10

echo ""
echo "=== Total PCAP packet count after t=73s ==="
tshark -r "$PCAP" -Y "frame.time_relative >= 73" 2>/dev/null | wc -l

echo ""
echo "=== Window start for 10.10.10.13 (first SYN) ==="
tshark -r "$PCAP" -Y "ip.src==10.10.10.13 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time_relative 2>/dev/null | head -1
echo "(first SYN time)"
