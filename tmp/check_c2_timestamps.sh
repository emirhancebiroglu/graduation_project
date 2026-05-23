#!/bin/bash
echo "=== Flows to 52.6.13.28 ==="
grep "52\.6\.13\.28" ~/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv | awk -F',' '{print $1" | src="$3" dst="$5" synflag="$56" time="$7}'
echo ""
echo "=== Flows to 52.7.235.158 ==="
grep "52\.7\.235\.158" ~/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv | awk -F',' '{print $1" | src="$3" dst="$5" synflag="$56" time="$7}'
echo ""
echo "=== Flows to 205.174.165.73 (comparison) ==="
grep "205\.174\.165\.73" ~/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv | awk -F',' '{print $1" | src="$3" synflag="$56" time="$7}' | head -5
