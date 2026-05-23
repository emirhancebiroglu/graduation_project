#!/usr/bin/env python3
import re
with open('/home/emirhan/bitirme/results/portscan/Friday-WorkingHours/snort_output.log') as f:
    for line in f:
        if '172.16.0.1' in line and 'ALERT' not in line:
            m = re.search(r'score=([0-9.]+)', line)
            if m:
                sc = float(m.group(1))
                if 0.50 <= sc < 0.55:
                    syn = re.search(r'syn=(\d+)/', line)
                    s = syn.group(1) if syn else '?'
                    print(f'  score={sc:.4f} syn={s} {line.strip()[:100]}')
