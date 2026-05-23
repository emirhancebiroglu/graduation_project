#!/usr/bin/env python3
"""threshold_sweep.py — Score-based threshold optimization for IP-based models

Extracts scores from snort logs, sweeps thresholds, finds best balance.
"""

import re, json, sys
from collections import defaultdict
from pathlib import Path

BASE = Path(r"\\wsl.localhost\Ubuntu-24.04\home\emirhan\bitirme")

MODELS = {
    "bot_client": {
        "log_pattern": r'\[botcl\] ALERT: ([\d.]+) score=([\d.]+)',
        "log_file": "snort_output.log",
        "known_attackers": {
            "Monday": [],
            "Tuesday": [],
            "Wednesday": [],
            "Thursday": [],
            "Friday": [
                "192.168.10.5", "192.168.10.8", "192.168.10.9",
                "192.168.10.12", "192.168.10.14", "192.168.10.15", "192.168.10.17",
            ],
        },
        "attack_days": ["Friday"],
        "alert_dirs": {
            "Monday": "results/bot_client/Monday",
            "Tuesday": "results/bot_client/Tuesday",
            "Wednesday": "results/bot_client/Wednesday",
            "Thursday": "results/bot_client/Thursday",
            "Friday": "results/bot_client/Friday",
        },
    },
    "dos_aggregator": {
        "log_pattern": r'\[dos_agg\] ALERT: ([\d.]+) score=([\d.]+)',
        "log_file": "snort.log",
        "known_attackers": {
            "Monday": [],
            "Tuesday": [],
            "Wednesday": ["172.16.0.1"],
            "Thursday": [],
            "Friday": ["172.16.0.1"],
        },
        "attack_days": ["Wednesday", "Friday"],
        "alert_dirs": {
            "Monday": "results/dos_aggregator/Monday",
            "Tuesday": "results/dos_aggregator/Tuesday",
            "Wednesday": "results/dos_aggregator/Wednesday",
            "Thursday": "results/dos_aggregator/Thursday",
            "Friday": "results/dos_aggregator/Friday",
        },
    },
    "bruteforce": {
        "log_pattern": r'\[bfc\] ALERT: ([\d.]+) score=([\d.]+)',
        "log_file": "snort_output.log",
        "known_attackers": {
            "Monday": [],
            "Tuesday": ["172.16.0.1"],
            "Wednesday": [],
            "Thursday": [],
            "Friday": [],
        },
        "attack_days": ["Tuesday"],
        "alert_dirs": {
            "Monday": "results/bruteforce/Monday",
            "Tuesday": "results/bruteforce/Tuesday",
            "Wednesday": "results/bruteforce/Wednesday",
            "Thursday": "results/bruteforce/Thursday",
            "Friday": "results/bruteforce/Friday",
        },
    },
}

def parse_scores(alert_dir, log_pattern, log_filename):
    log_file = alert_dir / log_filename
    scores = {}
    if not log_file.exists():
        return scores
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            m = re.search(log_pattern, line)
            if m:
                ip = m.group(1)
                score = float(m.group(2))
                if ip not in scores or score > scores[ip]:
                    scores[ip] = score
    return scores

def evaluate_threshold(alerted, known_set):
    tp_ips = alerted & known_set
    fp_ips = alerted - known_set
    fn_ips = known_set - alerted
    return len(tp_ips), len(fp_ips), len(fn_ips), tp_ips, fp_ips, fn_ips

def run_sweep(model_name, config):
    log_pattern = config["log_pattern"]
    log_filename = config["log_file"]
    known = config["known_attackers"]
    attack_days = config["attack_days"]

    all_day_scores = {}
    for day, rel_dir in config["alert_dirs"].items():
        alert_dir = BASE / rel_dir
        all_day_scores[day] = parse_scores(alert_dir, log_pattern, log_filename)
        print(f"  {day}: {len(all_day_scores[day])} IPs alerted")

    results = []
    for thresh_dec in range(5, 100, 5):
        thresh = thresh_dec / 100.0

        total_tp = 0
        total_fp = 0
        total_fn = 0
        attack_day_tp = 0
        attack_day_fn = 0
        benign_fp = 0

        per_day = {}
        for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]:
            scores = all_day_scores.get(day, {})
            alerted = {ip for ip, sc in scores.items() if sc >= thresh}
            known_set = set(known.get(day, []))

            if day in attack_days:
                tp, fp, fn, tp_ips, fp_ips, fn_ips = evaluate_threshold(alerted, known_set)
                attack_day_tp += tp
                attack_day_fn += fn
            else:
                tp = 0
                fp = len(alerted)
                fn = 0

            total_tp += tp
            total_fp += fp
            total_fn += fn
            if day not in attack_days:
                benign_fp += fp
            per_day[day] = {"tp": tp, "fp": fp, "fn": fn}

        # Metrics
        attack_recall = attack_day_tp / (attack_day_tp + attack_day_fn) if (attack_day_tp + attack_day_fn) > 0 else 0
        total_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        total_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        total_f1 = 2 * total_prec * total_recall / (total_prec + total_recall) if (total_prec + total_recall) > 0 else 0

        results.append({
            "threshold": thresh,
            "attack_recall": round(attack_recall, 4),
            "total_precision": round(total_prec, 4),
            "total_recall": round(total_recall, 4),
            "total_f1": round(total_f1, 4),
            "benign_fp": benign_fp,
            "total_fp": total_fp,
            "per_day": per_day,
        })

    return results

def main():
    for model_name, config in MODELS.items():
        print(f"\n{'='*70}")
        print(f"Threshold Sweep: {model_name}")
        print(f"{'='*70}")
        results = run_sweep(model_name, config)

        print(f"\n{'Thresh':<8} {'AttackRec':<10} {'TotalPrec':<10} {'TotalRec':<10} {'TotalF1':<10} {'BenignFP':<10} {'TotalFP':<10}")
        print(f"{'-'*68}")
        for r in results:
            print(f"{r['threshold']:<8.2f} {r['attack_recall']:<10.4f} {r['total_precision']:<10.4f} {r['total_recall']:<10.4f} {r['total_f1']:<10.4f} {r['benign_fp']:<10} {r['total_fp']:<10}")

        # Find best threshold
        best_f1 = max(results, key=lambda r: r['total_f1'])
        best_low_fp = sorted([r for r in results if r['attack_recall'] >= 1.0], key=lambda r: r['benign_fp'])

        print(f"\n  Best by F1: threshold={best_f1['threshold']:.2f} F1={best_f1['total_f1']:.4f} FP={best_f1['benign_fp']}")
        if best_low_fp:
            best = best_low_fp[0]
            print(f"  Best keeping Recall=1.0: threshold={best['threshold']:.2f} FP={best['benign_fp']}")

        # Save results
        out = BASE / f"results/{model_name}/threshold_sweep.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"  Saved: {out}")

if __name__ == "__main__":
    main()
