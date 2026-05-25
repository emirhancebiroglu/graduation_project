#!/bin/bash
PCAP="$HOME/bitirme/pcaps/cupid/052419_1504.pcapng"
echo "=== Scanner 10.10.10.13: dst IPs ==="
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags 2>/dev/null | \
    grep '^10.10.10.13.*0x0002$' | awk '{print $2}' | sort -u | head -10
echo ""
echo "=== Scanner 10.10.10.13: unique dst ports ==="
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags 2>/dev/null | \
    grep '^10.10.10.13.*0x0002$' | awk '{print $3}' | sort -u | wc -l
echo ""
echo "=== Time range of 10.10.10.13 SYNs ==="
tshark -r "$PCAP" -T fields -e frame.time_relative -e ip.src -e tcp.flags 2>/dev/null | \
    grep '^[^ ].* 10.10.10.13 0x0002$' | awk '{print $1}' | sort -n | tail -1
echo "(max time)"
