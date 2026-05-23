#!/bin/bash
echo "=== Final Results: Alert CSV Row Counts ==="
echo ""
for model in portscan ddos_aggregator dos_aggregator dos_inspector bot_client bruteforce; do
    echo "Model: $model"
    for day in Monday Tuesday Wednesday Thursday Friday; do
        f="/home/emirhan/bitirme/results/$model/$day/alert_csv.txt"
        if [ -f "$f" ]; then
            cnt=$(wc -l < "$f")
            echo "  $day: $cnt"
        else
            echo "  $day: N/A"
        fi
    done
    echo ""
done
