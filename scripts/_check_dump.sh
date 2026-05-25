#!/bin/bash
# 172.16.0.1 = (172<<24)|(16<<16)|(0<<8)|1 = 2886729729
echo "=== 172.16.0.1 windows ==="
grep ' 2886729729$' /home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt | wc -l
grep ' 2886729729$' /home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt | head -10

echo "=== score>0.5 benign windows ==="
awk 'NR>1 && $1==0 && $12>0.5 {print}' /home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt | head -20

echo "=== total lines ==="
wc -l /home/emirhan/bitirme/data/snort_dump/bruteforce/wednesday_dump.txt
