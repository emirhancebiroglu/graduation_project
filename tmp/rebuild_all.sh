#!/bin/bash
set -e
cd /home/emirhan/bitirme/plugins
for d in dos_inspector portscan_inspector dos_aggregator ddos_aggregator botnet_c2_inspector bot_client_inspector; do
    echo "=== Building $d ==="
    cd "$d"
    chmod +x build.sh 2>/dev/null || true
    ./build.sh 2>&1 | tail -3
    cd ..
done
echo "=== ALL DONE ==="
