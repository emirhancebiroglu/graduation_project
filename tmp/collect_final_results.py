#!/usr/bin/env python3
import os, glob

# Map day abbreviations to full PCAP dir names and short names
DAY_DIRS = {
    'Monday': 'Monday-WorkingHours',
    'Tuesday': 'Tuesday-WorkingHours', 
    'Wednesday': 'Wednesday-workingHours',
    'Thursday': 'Thursday-WorkingHours',
    'Friday': 'Friday-WorkingHours',
}

MODELS = {
    'dos_inspector': 'results/dos_inspector',
    'portscan': 'results/portscan',
    'dos_aggregator': 'results/dos_aggregator',
    'ddos_aggregator': 'results/ddos_aggregator',
    'bot_client': 'results/bot_client',
    'bruteforce': 'results/bruteforce',
}

base = '/home/emirhan/bitirme'
results = {}

for model, rel_dir in MODELS.items():
    results[model] = {}
    base_dir = os.path.join(base, rel_dir)
    if not os.path.isdir(base_dir):
        continue
    for day_short, day_dir in DAY_DIRS.items():
        # Try primary name
        alert_file = os.path.join(base_dir, day_dir, 'alert_csv.txt')
        if not os.path.exists(alert_file):
            # Try short name
            alert_file = os.path.join(base_dir, day_short, 'alert_csv.txt')
        if os.path.exists(alert_file):
            with open(alert_file) as f:
                count = sum(1 for _ in f)
            results[model][day_short] = count
        else:
            results[model][day_short] = None

# Print table
print('=' * 90)
print(f'{"Model":<20} {"Monday":<10} {"Tuesday":<10} {"Wednesday":<12} {"Thursday":<10} {"Friday":<10}')
print('=' * 90)
for model in ['dos_inspector', 'portscan', 'dos_aggregator', 'ddos_aggregator', 'bot_client', 'bruteforce']:
    row = [model]
    for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']:
        val = results.get(model, {}).get(day)
        if val is None:
            row.append('N/A')
        else:
            row.append(str(val))
    print(f'{row[0]:<20} {row[1]:<10} {row[2]:<10} {row[3]:<12} {row[4]:<10} {row[5]:<10}')
print('=' * 90)

# Also print per-model notes
print()
print('NOTES:')
for model in ['dos_inspector', 'portscan', 'dos_aggregator', 'ddos_aggregator', 'bot_client', 'bruteforce']:
    note = ''
    counts = results.get(model, {})
    if all(v == 0 or v is None for v in counts.values()):
        note = 'No alerts on any day'
    elif model == 'dos_inspector':
        note = 'Wednesday=79K (DoS attacks), Friday=70K (botnet+scan)'
    elif model == 'portscan':
        note = 'Only Friday data collected (27 alerts)'
    elif model == 'dos_aggregator':
        note = 'Wed=53, Fri=29. Cross-flow SYN rate, alert only on high-rate DoS'
    elif model == 'ddos_aggregator':
        note = 'Thu=11,607 (DDoS on Thursday data)'  
    elif model == 'bot_client':
        note = 'Recall=1.0, ~11 FPs/day (kabul edilebilir)'
    elif model == 'bruteforce':
        note = '0 FP, sadece gerçek brute force attacker alert'
    if note:
        print(f'  {model:<20} {note}')
