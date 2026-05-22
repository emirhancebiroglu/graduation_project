#!/usr/bin/env python3
"""analyze_scores.py — Extract and analyze score distributions from snort logs."""

import re, sys
from pathlib import Path

BASE = Path(r"\\wsl.localhost\Ubuntu-24.04\home\emirhan\bitirme")

MODEL_PATTERNS = {
    "bot_client": (r'\[botcl\] ALERT: ([\d.]+) score=([\d.]+)', "snort_output.log",
                   {"Monday": [], "Tuesday": [], "Wednesday": [], "Thursday": [], "Friday": [
                       "192.168.10.5", "192.168.10.8", "192.168.10.9",
                       "192.168.10.12", "192.168.10.14", "192.168.10.15", "192.168.10.17",
                   ]}),
    "dos_aggregator": (r'\[dos_agg\] ALERT: ([\d.]+) score=([\d.]+)', "snort.log",
                       {"Monday": [], "Tuesday": [], "Wednesday": ["172.16.0.1"],
                        "Thursday": [], "Friday": ["172.16.0.1"]}),
    "bruteforce": (r'\[bfc\] ALERT: ([\d.]+) score=([\d.]+)', "snort_output.log",
                   {"Monday": [], "Tuesday": ["172.16.0.1"], "Wednesday": [],
                    "Thursday": [], "Friday": []}),
}

MODEL_DIRS = {
    "bot_client": "results/bot_client/{day}",
    "dos_aggregator": "results/dos_aggregator/{day}",
    "bruteforce": "results/bruteforce/{day}",
}

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

for model_name in ["bot_client", "dos_aggregator", "bruteforce"]:
    pat, logfile, known_ips = MODEL_PATTERNS[model_name]
    dir_tmpl = MODEL_DIRS[model_name]

    print(f"\n{'='*60}")
    print(f"Score Distribution: {model_name}")
    print(f"{'='*60}")

    all_scores = {}
    for day in DAYS:
        log_path = BASE / dir_tmpl.format(day=day) / logfile
        if not log_path.exists():
            continue
        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                m = re.search(pat, line)
                if m:
                    ip = m.group(1)
                    sc = float(m.group(2))
                    if ip not in all_scores or sc > all_scores[ip][0]:
                        all_scores[ip] = (sc, day)

    print(f"\n  {'IP':<20} {'Score':<10} {'Day':<12} {'Type':<12}")
    print(f"  {'-'*54}")
    for ip, (sc, day) in sorted(all_scores.items(), key=lambda x: -x[1][0]):
        known_set = set(known_ips.get(day, []))
        if ip in known_set:
            tag = "ATTACKER_TP"
        elif day in known_ips and known_ips[day]:
            tag = "ATTACKER_FN" if model_name != "bot_client" else "BENIGN_FP"
        else:
            tag = "BENIGN_FP"
        print(f"  {ip:<20} {sc:<10.4f} {day:<12} {tag:<12}")

    # Overall stats
    scores = [sc for ip, (sc, day) in all_scores.items()]
    known_scores = [sc for ip, (sc, day) in all_scores.items()
                    if ip in known_ips.get(day, [])]
    fp_scores = [sc for ip, (sc, day) in all_scores.items()
                 if ip not in known_ips.get(day, [])]

    print(f"\n  Stats:")
    print(f"    Total unique IPs: {len(scores)}")
    if known_scores:
        print(f"    Attacker scores: min={min(known_scores):.4f} max={max(known_scores):.4f} mean={sum(known_scores)/len(known_scores):.4f}")
    if fp_scores:
        print(f"    FP scores:       min={min(fp_scores):.4f} max={max(fp_scores):.4f} mean={sum(fp_scores)/len(fp_scores):.4f}")
