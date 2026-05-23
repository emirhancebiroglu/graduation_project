#!/usr/bin/env python3
"""
evaluate_dos_model.py — Combined evaluation for per-flow + cross-flow DoS.

Per-flow: uses existing confusion matrix (xgb_flowid_confusion_wednesday.py)
Cross-flow: parses dos_aggregator logs for IP-level alert counts.

Outputs unified metrics to results/dos/summary.json
"""

import argparse, json, logging, os, re
from collections import defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

SCANNER_IPS = ['172.16.0.1']
DOS_EVENT = re.compile(r'\[dos_agg\] ([0-9.]+) syns=\d+ .*? score=([0-9.]+)')
DOS_ALERT = re.compile(r'\[dos_agg\] ALERT: ([0-9.]+) score=([0-9.]+)')


def parse_dos_agg(log_root: str):
    """Parse dos_aggregator logs for all days."""
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
    results = {}
    for day in days:
        log_path = Path(log_root) / 'dos_aggregator' / f'{day}-WorkingHours' / 'snort_output.log'
        events = []
        alerts = defaultdict(int)
        if log_path.exists():
            with open(log_path) as f:
                for line in f:
                    m = DOS_ALERT.search(line)
                    if m:
                        alerts[m.group(1)] += 1
                    m = DOS_EVENT.search(line)
                    if m:
                        events.append((m.group(1), float(m.group(2))))
        scanner_wins = sum(1 for ip, sc in events if ip in SCANNER_IPS)
        scanner_al = alerts.get(SCANNER_IPS[0], 0)
        non_scanner = {k: v for k, v in alerts.items() if k not in SCANNER_IPS}
        results[day] = {
            'total_windows': len(events),
            'scanner_windows': scanner_wins,
            'total_alerts': sum(alerts.values()),
            'scanner_alerts': scanner_al,
            'non_scanner_alerts': sum(non_scanner.values()),
            'non_scanner_ips': list(non_scanner.keys())[:5],
        }
    return results


def parse_confusion_matrix():
    """Read the existing Wednesday confusion matrix."""
    cm_path = Path.home() / 'bitirme' / 'results' / 'xgboost' / 'confusion_matrix_wednesday.txt'
    cm = {}
    if cm_path.exists():
        with open(cm_path) as f:
            for line in f:
                m = re.search(r'(Recall|Precision|FPR|F1).*?([0-9.]+)', line)
                if m:
                    cm[m.group(1).strip()] = float(m.group(2))
                m = re.search(r'FP = (\d+)', line)
                if m: cm['fp'] = int(m.group(1))
                m = re.search(r'TP = (\d+)', line)
                if m: cm['tp'] = int(m.group(1))
                m = re.search(r'FN = (\d+)', line)
                if m: cm['fn'] = int(m.group(1))
                m = re.search(r'TN = (\d+)', line)
                if m: cm['tn'] = int(m.group(1))
    return cm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'results'))
    parser.add_argument('--output', type=str,
                        default=str(Path.home() / 'bitirme' / 'results' / 'dos' / 'summary.json'))
    args = parser.parse_args()

    dos = parse_dos_agg(args.log_dir)
    cm = parse_confusion_matrix()

    # Print summary
    print('='*75)
    print('  DOS MODEL EVALUATION')
    print('  Per-flow (GID:301): confusion matrix on Wednesday')
    print('  Cross-flow (GID:303): IP-level aggregation (all days)')
    print('='*75)

    if cm:
        print(f'\n  Per-flow Wednesday Results:')
        print(f'    TP: {cm.get("tp", "?"):>7}  FP: {cm.get("fp", "?"):>7}')
        print(f'    FN: {cm.get("fn", "?"):>7}  TN: {cm.get("tn", "?"):>7}')
        print(f'    Recall:  {cm.get("Recall", 0)*100:.2f}%')
        print(f'    FPR:     {cm.get("FPR", 0)*100:.2f}%')
        print(f'    Precision: {cm.get("Precision", 0):.4f}')

    print(f'\n  Cross-flow Results (all days):')
    print(f'  {"Day":<12} {"Windows":>8} {"Scanner":>9} {"Total":>7} {"Non-IP":>7} {"Scanner":>9}')
    print(f'  {"":<12} {"":>8} {"Wins":>9} {"Alerts":>7} {"Alerts":>7} {"Alerts":>9}')
    print('  ' + '-'*52)

    totals = {'wins': 0, 'sw': 0, 'al': 0, 'fp': 0, 'sa': 0}
    for day in ['Monday','Tuesday','Wednesday','Thursday','Friday']:
        d = dos[day]
        totals['wins'] += d['total_windows']
        totals['sw'] += d['scanner_windows']
        totals['al'] += d['total_alerts']
        totals['fp'] += d['non_scanner_alerts']
        totals['sa'] += d['scanner_alerts']
        fp_mark = '✅' if d['non_scanner_alerts'] == 0 else f'⚠️({d["non_scanner_alerts"]})'
        print(f'  {day:<12} {d["total_windows"]:>8} {d["scanner_windows"]:>9} {d["total_alerts"]:>7} {d["non_scanner_alerts"]:>7} {d["scanner_alerts"]:>9} {fp_mark}')

    print('  ' + '-'*52)
    print(f'  {"TOTAL":<12} {totals["wins"]:>8} {totals["sw"]:>9} {totals["al"]:>7} {totals["fp"]:>7} {totals["sa"]:>9}')
    print('='*75)

    # Save
    output = {
        'per_flow_wednesday': cm,
        'cross_flow_by_day': dos,
        'cross_flow_total': totals,
    }
    out_path = Path(args.output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    logging.info(f'Saved: {out_path}')


if __name__ == '__main__':
    main()
