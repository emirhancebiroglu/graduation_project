#!/bin/bash
PCAP="$HOME/bitirme/pcaps/cupid/052419_1504.pcapng"
echo "=== Top SYN senders ==="
tshark -r "$PCAP" -T fields -e ip.src -e tcp.flags 2>/dev/null | grep '0x0002' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
echo ""
echo "=== Unique dst ports per top sender ==="
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags 2>/dev/null | grep '0x0002' | awk '{print $1, $3}' | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head -5
