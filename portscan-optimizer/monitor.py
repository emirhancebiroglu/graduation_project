#!/usr/bin/env python3
"""
monitor.py - Run this in a separate terminal to watch progress live.
Usage: python monitor.py
"""
import json, time, os

TARGETS = {'recall': 0.99, 'precision': 0.98, 'f1': 0.98, 'fpr_max': 0.01}

def check():
    if os.path.exists('results/DONE.txt'):
        print("\n🎯 TARGETS HIT — Check results/DONE.txt")
        return True

    if not os.path.exists('results/metrics.json'):
        print("Waiting for first iteration...")
        return False

    with open('results/metrics.json') as f:
        m = json.load(f)

    history_count = 0
    if os.path.exists('results/history.jsonl'):
        with open('results/history.jsonl') as f:
            history_count = sum(1 for _ in f)

    print(f"\n{'='*50}")
    print(f"Iteration: {m.get('iteration', '?')}  |  Total runs: {history_count}")
    print(f"Change: {m.get('change_made', '?')}")
    print(f"{'='*50}")

    metrics = [
        ('Recall',    m['recall'],    '>=', 0.99, m['recall']    >= 0.99),
        ('Precision', m['precision'], '>=', 0.98, m['precision'] >= 0.98),
        ('F1',        m['f1'],        '>=', 0.98, m['f1']        >= 0.98),
        ('FPR',       m['fpr'],       '<=', 0.01, m['fpr']       <= 0.01),
    ]
    all_hit = True
    for name, val, op, target, hit in metrics:
        status = '✓' if hit else '✗'
        print(f"  {status} {name:<12} {val:.4f}  (target {op}{target})")
        if not hit:
            all_hit = False

    cm = m.get('confusion_matrix')
    if cm:
        print(f"\n  Confusion Matrix:")
        print(f"    TN={cm[0][0]:>7}  FP={cm[0][1]:>7}")
        print(f"    FN={cm[1][0]:>7}  TP={cm[1][1]:>7}")

    if all_hit:
        print("\n🎯 ALL TARGETS HIT!")
        return True
    return False

print("PortScan Loop Monitor — refreshes every 30s. Ctrl+C to stop.")
while True:
    done = check()
    if done:
        break
    time.sleep(30)