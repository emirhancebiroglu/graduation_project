#!/bin/bash
# Create demo_composite.pcap from CIC-IDS2017 attack slices
# CIC-IDS2017 CSV timestamps: EDT (UTC-4), displayed as 12-hour without AM/PM
# All PCAPs: UTC timestamps, start ~14:53-14:59 UTC (= ~11 AM EDT)
# Rule: CSV time + 4h = UTC time

set -e

PCAP_DIR="/home/emirhan/bitirme/pcaps"
OUT_DIR="/home/emirhan/bitirme/demo-app/api/pcaps"
TMP_DIR="/tmp/composite_slices"

mkdir -p "$TMP_DIR"

echo "=== Step 1: Wednesday DoS slice (DoS Hulk: 10:43-11:07 EDT = 14:43-15:07 UTC, 30-min window) ==="
editcap -A "2017-07-05 14:40:00" -B "2017-07-05 15:10:00" \
    "$PCAP_DIR/Wednesday-workingHours.pcap" \
    "$TMP_DIR/dos_slice.pcap"
capinfos -c -u "$TMP_DIR/dos_slice.pcap" | grep -E "packets|uration" || true

echo ""
echo "=== Step 2: Friday PortScan slice (1:05-3:23 PM EDT = 17:05-19:23 UTC, take 30 min peak) ==="
editcap -A "2017-07-07 17:00:00" -B "2017-07-07 17:30:00" \
    "$PCAP_DIR/Friday-WorkingHours.pcap" \
    "$TMP_DIR/fri_portscan_raw.pcap"
capinfos -c -u "$TMP_DIR/fri_portscan_raw.pcap" | grep -E "packets|uration" || true

echo ""
echo "=== Step 3: Friday DDoS slice (3:56-4:30 PM EDT = 19:56-20:30 UTC, 40 min) ==="
editcap -A "2017-07-07 19:50:00" -B "2017-07-07 20:35:00" \
    "$PCAP_DIR/Friday-WorkingHours.pcap" \
    "$TMP_DIR/fri_ddos_raw.pcap"
capinfos -c -u "$TMP_DIR/fri_ddos_raw.pcap" | grep -E "packets|uration" || true

echo ""
echo "=== Step 4: Synthetic bruteforce (distributed_brute.pcap — 3 source IPs, triggers GID:307) ==="
# distributed_brute.pcap is Raw IPv4 (no Ethernet header) → convert via scapy
# Also fix timestamps from 1970 epoch to 2017-07-05 21:10:00 UTC
python3 - << 'PYEOF'
from scapy.all import rdpcap, Ether, PcapWriter
import calendar, datetime

INPUT = "/home/emirhan/bitirme/pcaps/synthetic_bruteforce/distributed_brute.pcap"
OUTPUT = "/tmp/composite_slices/tue_bruteforce_raw.pcap"
target_start = calendar.timegm(datetime.datetime(2017, 7, 5, 21, 10, 0).timetuple())
pkts = rdpcap(INPUT)
delta = target_start - float(pkts[0].time)
with PcapWriter(OUTPUT, snaplen=262144, sync=True) as pw:
    for p in pkts:
        new_p = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') / p
        new_p.time = float(p.time) + delta
        pw.write(new_p)
print(f"Converted {len(pkts)} pkts, first ts: {datetime.datetime.utcfromtimestamp(float(pkts[0].time) + delta)}")
PYEOF
capinfos -c -u "$TMP_DIR/tue_bruteforce_raw.pcap" | grep -E "packets|uration" || true

echo ""
echo "=== Step 5: Friday Bot slice (afternoon window 15:00-16:30 UTC = ~11:00-12:30 EDT) ==="
editcap -A "2017-07-07 15:00:00" -B "2017-07-07 15:30:00" \
    "$PCAP_DIR/Friday-WorkingHours.pcap" \
    "$TMP_DIR/fri_bot_raw.pcap"
capinfos -c -u "$TMP_DIR/fri_bot_raw.pcap" | grep -E "packets|uration" || true

echo ""
echo "=== Step 6: Apply timestamp offsets to avoid overlap ==="
# dos_slice: keep original timestamps (base = 0 offset)
cp "$TMP_DIR/dos_slice.pcap" "$TMP_DIR/slice_0_dos.pcap"

# portscan: offset +3600s (1 hour after dos window)
editcap -t +3600 "$TMP_DIR/fri_portscan_raw.pcap" "$TMP_DIR/slice_1_portscan.pcap"

# ddos: offset +7200s (2 hours after dos)
editcap -t +7200 "$TMP_DIR/fri_ddos_raw.pcap" "$TMP_DIR/slice_2_ddos.pcap"

# bruteforce: timestamps already set to 2017-07-05 21:10:00 UTC by python3 converter
cp "$TMP_DIR/tue_bruteforce_raw.pcap" "$TMP_DIR/slice_3_bruteforce.pcap"

# bot: offset +14400s (4 hours after dos)
editcap -t +14400 "$TMP_DIR/fri_bot_raw.pcap" "$TMP_DIR/slice_4_bot.pcap"

echo ""
echo "=== Step 7: Merge all slices ==="
mergecap -w "$TMP_DIR/demo_composite_raw.pcap" \
    "$TMP_DIR/slice_0_dos.pcap" \
    "$TMP_DIR/slice_1_portscan.pcap" \
    "$TMP_DIR/slice_2_ddos.pcap" \
    "$TMP_DIR/slice_3_bruteforce.pcap" \
    "$TMP_DIR/slice_4_bot.pcap"

echo ""
echo "=== Composite PCAP info ==="
capinfos -c -u "$TMP_DIR/demo_composite_raw.pcap"

echo ""
echo "=== Copying to demo-app/api/pcaps/ ==="
cp "$TMP_DIR/demo_composite_raw.pcap" "$OUT_DIR/demo_composite.pcap"
echo "Done: $OUT_DIR/demo_composite.pcap"
