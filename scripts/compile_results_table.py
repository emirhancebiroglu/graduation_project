#!/usr/bin/env python3
"""compile_results_table.py — Compile all model results into a master table."""
import json, sys
from pathlib import Path

BASE = Path("/home/emirhan/bitirme")
OUT = BASE / "results" / "master_performance_table.txt"

def jp(*parts):
    return BASE.joinpath(*parts)

models_info = {
    "dos_inspector (GID:301)": {
        "type": "per-flow XGBoost (11 features)",
        "target": "DoS (Hulk, GoldenEye, Slowloris, Slowhttptest)",
        "eval_file": jp("results", "dos_inspector", "metrics_all_days.json"),
    },
    "portscan_inspector (GID:302)": {
        "type": "cross-flow XGBoost (7 features) + NULL/XMAS heuristic",
        "target": "PortScan (SYN, FIN, NULL, XMAS, UDP)",
        "eval_file": jp("results", "portscan", "eval_portscan.json"),
    },
    "dos_aggregator (GID:303)": {
        "type": "cross-flow XGBoost (7 features, SYN rate)",
        "target": "DoS/DDoS (high SYN rate per src IP)",
        "eval_file": jp("results", "dos_aggregator", "eval_dos_aggregator.json"),
    },
    "bot_client_inspector (GID:306)": {
        "type": "cross-flow XGBoost (7 features, 300s, CIC-only)",
        "target": "Bot client (CIC-2017 Bot v2 — CIC-only, 2x FP reduction)",
        "eval_file": jp("results", "bot_client", "eval_bot_client.json"),
    },
    "bruteforce_inspector (GID:307)": {
        "type": "cross-flow XGBoost (7 features, 60s)",
        "target": "Brute Force (SSH/FTP Patator)",
        "eval_file": jp("results", "bruteforce", "eval_bruteforce.json"),
    },
}

days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
attack_types = {
    "Monday": "BENIGN",
    "Tuesday": "SSH/FTP Patator",
    "Wednesday": "DoS (Hulk, GoldenEye, Slowloris, Slowhttptest)",
    "Thursday": "Web Attacks + Infiltration",
    "Friday": "Botnet + PortScan + DDoS",
}

lines = []
def L(s=""):
    raw = str(s)
    lines.append(raw)
    try:
        sys.stdout.write(raw + "\n")
    except UnicodeEncodeError:
        safe = raw.encode('utf-8', 'replace').decode('ascii', 'replace')
        safe = safe.replace('\ufffd', '-').replace('?', '-')
        sys.stdout.write(safe + "\n")
    sys.stdout.flush()

L("=" * 130)
L("CIC-IDS2017 MODEL PERFORMANCE COMPARISON - PER-DAY CONFUSION MATRIX")
L("=" * 130)
L()
L(f"{'Model':<35} {'Day':<12} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} "
  f"{'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
L("-" * 130)

for model_name, info in models_info.items():
    short = model_name.split(" (")[0]
    ef = info["eval_file"]
    if not ef.exists():
        L(f"{short:<35} {'NO DATA':<12}")
        continue
    data = json.loads(ef.read_text())
    for day in days:
        if day not in data:
            continue
        r = data[day]
        if "tn" in r:  # per-flow model with full CM
            tp, tn, fp, fn = r["tp"], r["tn"], r["fp"], r["fn"]
            acc = r.get("accuracy", round((tp+tn)/(tp+tn+fp+fn), 4) if (tp+tn+fp+fn)>0 else 0)
            prec = r["precision"]
            rec = r["recall"]
            f1 = r["f1"]
            fpr = r["fpr"]
            L(f"{short:<35} {day:<12} {tp:>8} {tn:>8} {fp:>8} {fn:>8} "
              f"{acc:>8.4f} {prec:>8.4f} {rec:>8.4f} {f1:>8.4f} {fpr:>8.4f}")
        else:  # IP-based model
            tp, fp, fn = r["tp"], r["fp"], r["fn"]
            L(f"{short:<35} {day:<12} {tp:>8} {'N/A':>8} {fp:>8} {fn:>8} "
              f"{'N/A':>8} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f} {'N/A':>8}")

L()
L("=" * 130)
L("ATTACK-TYPE DETECTION BREAKDOWN (dos_inspector per-flow)")
L("=" * 130)

dos_file = jp("results", "dos_inspector", "metrics_all_days.json")
if dos_file.exists():
    data = json.loads(dos_file.read_text())
    for day in days:
        if day not in data:
            continue
        ad = data[day].get("attack_details", {})
        if not ad:
            continue
        benign_total = ad.pop("BENIGN", {}).get("total", 0) if "BENIGN" in ad else 0
        L(f"\n  {day} ({attack_types[day]}):")
        L(f"    {'Attack Type':<35} {'Detected/Total':<20} {'Rate':>8}")
        L(f"    {'-'*65}")
        for label, d in sorted(ad.items()):
            if label == "BENIGN":
                continue
            rate = d["detected"] / d["total"] * 100 if d["total"] > 0 else 0
            L(f"    {label[:35]:<35} {d['detected']:>6}/{d['total']:<6}        {rate:>6.1f}%")
        if benign_total > 0:
            L(f"    {'BENIGN (non-attack)':<35} {'-':>6}/{benign_total:<6}")

L()
L("=" * 130)
L("IP-LEVEL DETECTION (cross-flow models)")
L("=" * 130)

for model_name, info in models_info.items():
    short = model_name.split(" (")[0]
    if short == "dos_inspector":
        continue
    ef = info["eval_file"]
    if not ef.exists():
        continue
    data = json.loads(ef.read_text())
    L(f"\n  {short} - Target: {info['target']}")
    L(f"    {'Day':<12} {'Type':<10} {'Alerted IPs':>12} {'TP':>6} {'FP':>6} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    L(f"    {'-'*72}")
    for day in days:
        if day not in data:
            continue
        r = data[day]
        dtype = "Attack" if r["is_attack_day"] else "Benign"
        L(f"    {day:<12} {dtype:<10} {r['total_alerts']:>12} {r['tp']:>6} {r['fp']:>6} "
          f"{r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f}")
    friday = data.get("Friday", {})
    if friday.get("tp_ips"):
        L(f"    TP IPs (Fri): {', '.join(friday['tp_ips'])}")
    if friday.get("fp_ips"):
        L(f"    FP IPs (Fri): {', '.join(friday['fp_ips'])}")

L()
L("=" * 130)
L("PORTSCAN DETAILED METRICS (window-level from metrics JSON)")
L("=" * 130)
portscan_dir = BASE / "results" / "portscan"
for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]:
    mf = portscan_dir / f"metrics_{day.lower()}.json"
    if not mf.exists():
        continue
    m = json.loads(mf.read_text())
    L(f"\n  {day}:")
    L(f"    Scanner IP detected: {m['scanner_ips']['detected']}/{m['scanner_ips']['total']}")
    L(f"    Window recall: {m['window_level']['window_recall']:.2%} "
      f"({m['window_level']['alerted_scanner_windows']}/{m['window_level']['total_scanner_windows']})")
    L(f"    SYN coverage: {m['packet_coverage']['syn_coverage']:.2%}")
    L(f"    FP (non-scanner): {m['false_positives']['total_non_scanner_alerts']}")

OUT.write_text("\n".join(lines), encoding="utf-8")
L(f"\nSaved: {OUT}")
