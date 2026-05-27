#!/usr/bin/env python3
"""eval_ip_based.py — Generic IP-based evaluation for cross-flow models

Evaluates per-src-IP aggregation models (dos_aggregator, bot_client, bruteforce).
Checks if alerted source IPs match known attacker IPs.

Usage:
    python scripts/eval_ip_based.py \\
        --alert-dir ~/bitirme/results/<model> \\
        --model-name dos_aggregator \\
        --output ~/bitirme/results/<model>/
"""

import pandas as pd
import argparse
import logging
import json
import re
from pathlib import Path
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALERT_SUBDIR_TO_DAY = {
    'Monday-WorkingHours': 'Monday',
    'Tuesday-WorkingHours': 'Tuesday',
    'Wednesday-workingHours': 'Wednesday',
    'Wednesday-WorkingHours': 'Wednesday',
    'Thursday-WorkingHours': 'Thursday',
    'Friday-WorkingHours': 'Friday',
    'Monday': 'Monday',
    'Tuesday': 'Tuesday',
    'Wednesday': 'Wednesday',
    'Thursday': 'Thursday',
    'Friday': 'Friday',
}

KNOWN_ATTACKER_IPS = {
    'dos_aggregator': {
        'Wednesday': ['172.16.0.1'],
        'Friday': ['172.16.0.1'],
        'expected_attack_days': ['Wednesday', 'Friday'],
    },
    'bot_client': {
        'Friday': [
            '192.168.10.5', '192.168.10.8', '192.168.10.9',
            '192.168.10.12', '192.168.10.14', '192.168.10.15', '192.168.10.17',
        ],
        'expected_attack_days': ['Friday'],
    },
    'bruteforce': {
        'Tuesday': ['172.16.0.1'],
        'expected_attack_days': ['Tuesday'],
    },
    'portscan': {
        'Wednesday': ['172.16.0.1'],
        'Friday': ['172.16.0.1'],
        'expected_attack_days': ['Wednesday', 'Friday'],
    },
    'ddos_aggregator': {
        'Wednesday': ['192.168.10.50'],
        'Friday': ['192.168.10.50'],
        'expected_attack_days': ['Wednesday', 'Friday'],
    },
}

GID_PATTERNS = {
    'dos_aggregator': r'303:\d+:\d+',
    'bot_client': r'306:\d+:\d+',
    'bruteforce': r'307:\d+:\d+',
    'ddos_aggregator': r'304:\d+:\d+',
}


def extract_alerted_ips(alert_file, gid_pattern):
    ips = set()
    if not alert_file.exists():
        return ips
    # Cross-flow models queue alerts on the current packet's IP, not the detection IP.
    # Use the Snort log file (snort_output.log or snort.log) which logs "ALERT: <detection_ip>"
    log_dir = alert_file.parent
    for log_name in ['snort_output.log', 'snort.log']:
        log_file = log_dir / log_name
        if log_file.exists():
            with open(log_file, 'r') as f:
                for line in f:
                    m = re.search(r'ALERT:\s+([\d.]+)', line)
                    if m:
                        ips.add(m.group(1))
            break
    return ips


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert-dir', type=str, required=True)
    parser.add_argument('--model-name', type=str, required=True,
                        choices=['dos_aggregator', 'bot_client', 'bruteforce', 'portscan', 'ddos_aggregator'])
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    alert_dir = Path(args.alert_dir).expanduser()
    output_dir = Path(args.output).expanduser() if args.output else alert_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    model = args.model_name
    known_ips = KNOWN_ATTACKER_IPS.get(model, {})
    expected_days = known_ips.get('expected_attack_days', [])
    gid_pattern = GID_PATTERNS.get(model, '')

    all_results = OrderedDict()
    processed_days = set()

    for subdir in sorted(alert_dir.iterdir()):
        if not subdir.is_dir():
            continue
        day = ALERT_SUBDIR_TO_DAY.get(subdir.name)
        if day is None:
            continue
        if day in processed_days:
            continue
        processed_days.add(day)

        alert_file = subdir / "alert_csv.txt"
        if not alert_file.exists():
            # Try other subdir names for this day
            for alt_name, alt_day in ALERT_SUBDIR_TO_DAY.items():
                if alt_day == day:
                    alt_file = alert_dir / alt_name / "alert_csv.txt"
                    if alt_file.exists():
                        alert_file = alt_file
                        break
        alerted_ips = extract_alerted_ips(alert_file, gid_pattern)

        day_known = set(known_ips.get(day, []))
        if day in expected_days:
            tp_ips = alerted_ips & day_known
            fp_ips = alerted_ips - day_known
            fn_ips = day_known - alerted_ips
            total_attackers = len(day_known)
        else:
            tp_ips = set()
            fp_ips = alerted_ips
            fn_ips = set()
            total_attackers = 0

        tp = len(tp_ips)
        fp = len(fp_ips)
        fn = len(fn_ips)

        if total_attackers == 0:
            prec = 1.0 if fp == 0 else 0.0
            rec = 0.0
            f1 = 0.0
        else:
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        all_results[day] = {
            'tp': tp, 'fp': fp, 'fn': fn,
            'precision': round(prec, 4), 'recall': round(rec, 4), 'f1': round(f1, 4),
            'total_alerts': len(alerted_ips),
            'alerted_ips': sorted(alerted_ips),
            'tp_ips': sorted(tp_ips),
            'fp_ips': sorted(fp_ips),
            'fn_ips': sorted(fn_ips),
            'known_attacker_ips': sorted(day_known),
            'is_attack_day': day in expected_days,
        }

        status = "ATTACK" if day in expected_days else "BENIGN"
        print(f"  {day:<12} [{status:<7}] Alerts: {len(alerted_ips):>3} IPs | "
              f"TP={tp} FP={fp} FN={fn} | Prec={prec:.4f} Rec={rec:.4f} F1={f1:.4f}")

    json_file = output_dir / f"eval_{model}.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)

    print(f"\nSaved: {json_file}")

    print(f"\n{'='*70}")
    print(f"Summary: {model}")
    print(f"{'='*70}")
    print(f"{'Day':<12} {'Type':<8} {'Alerts':>7} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>8} {'Rec':>8} {'F1':>8}")
    print(f"{'-'*70}")
    for day, r in all_results.items():
        dtype = "ATTACK" if r['is_attack_day'] else "BENIGN"
        print(f"{day:<12} {dtype:<8} {r['total_alerts']:>7} {r['tp']:>5} {r['fp']:>5} {r['fn']:>5} "
              f"{r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f}")


if __name__ == "__main__":
    main()
