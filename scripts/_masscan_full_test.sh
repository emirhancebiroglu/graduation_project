#!/bin/bash
cd /usr/local/etc/snort
mkdir -p /tmp/ps_masscan_full
rm -f /tmp/ps_masscan_full/alert_csv.txt
export LD_LIBRARY_PATH=$HOME/snort_src/xgboost/lib:$LD_LIBRARY_PATH
snort -c /home/emirhan/bitirme/configs/snort_portscan.lua \
  --plugin-path /home/emirhan/bitirme/plugins/portscan_inspector/build \
  -r /home/emirhan/bitirme/data/ProbingDataset-v1.0.0/gubertoli-ProbingDataset-134bec8/pcap/masscan.pcapng \
  -A alert_csv -l /tmp/ps_masscan_full -q 2>&1 | grep '\[portscan\] ALERT' | head -5
echo "masscan full alerts: $(wc -l < /tmp/ps_masscan_full/alert_csv.txt 2>/dev/null || echo 0)"
