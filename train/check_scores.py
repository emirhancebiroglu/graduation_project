#!/usr/bin/env python3
import re

# Friday scanner score distribution
scanner = []
with open('/home/emirhan/bitirme/results/portscan/Friday-WorkingHours/snort_output.log') as f:
    for line in f:
        if '172.16.0.1' in line and 'ALERT' not in line:
            m = re.search(r'score=([0-9.]+)', line)
            if m: scanner.append(float(m.group(1)))

print('Friday scanner score distribution:')
for s in sorted(set(scanner)):
    c = scanner.count(s)
    mark = ' << ALERT' if s >= 0.55 else ''
    print(f'  score={s:.4f}: {c:3d}x{mark}')

print(f'\nTotal: {len(scanner)} scanner windows')
print(f'Alerted at 0.55: {sum(1 for x in scanner if x >= 0.55)}')
print(f'Missed at 0.55: {sum(1 for x in scanner if x < 0.55)}')
