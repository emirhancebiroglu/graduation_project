#!/bin/bash
echo "=== friday_dump label distribution ==="
awk 'NR>1 {print $1}' /home/emirhan/bitirme/data/snort_dump/bot_client/friday_dump.txt | sort | uniq -c

echo "=== friday_dump bot IPs (check col 25=src_ip) ==="
# Find lines labeled 1
awk 'NR>1 && $1==1 {print NR, $25}' /home/emirhan/bitirme/data/snort_dump/bot_client/friday_dump.txt | head -20
echo "labeled 1 count:"
awk 'NR>1 && $1==1' /home/emirhan/bitirme/data/snort_dump/bot_client/friday_dump.txt | wc -l

echo "=== ctu13 positive windows ==="
awk 'NR>1 && $1==1' /home/emirhan/bitirme/data/snort_dump/bot_client/ctu13_s1_dump.txt | wc -l
awk 'NR>1 && $1==1' /home/emirhan/bitirme/data/snort_dump/bot_client/ctu13_s3_dump.txt | wc -l

echo "=== train script ==="
ls /home/emirhan/bitirme/train/train_bot_client*.py 2>/dev/null
