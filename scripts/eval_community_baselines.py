#!/usr/bin/env python3
"""
eval_community_baselines.py — Compute correct community rule baselines per scenario day.

Uses GID:1-only alerts from combined alert_csv files (no GID:116 codec noise).
Outputs corrected scenario_baselines community blocks + eval_all_models_report community_baseline.

Usage:
    python3 scripts/eval_community_baselines.py
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

REPO = Path.home() / "bitirme"
GT_DIR = REPO / "data/raw/cicids2017"
COMBINED_DIR = REPO / "results/combined"

IP_MAP = {"192.168.10.51": "172.16.0.1"}

PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "tcp": 6, "udp": 17, "icmp": 1}


def parse_ip_port(field: str):
    field = field.strip()
    last = field.rfind(":")
    if last == -1:
        return field, 0
    try:
        return field[:last], int(field[last + 1:])
    except ValueError:
        return field[:last], 0


def load_gt(csv_paths: list[str]) -> pd.DataFrame:
    frames = []
    for p in csv_paths:
        df = pd.read_csv(p, low_memory=False)
        df.columns = df.columns.str.strip()
        df["Label"] = df["Label"].str.strip()
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def get_attack_ips(df: pd.DataFrame) -> set[str]:
    att = df[df["Label"] != "BENIGN"]
    ips: set[str] = set()
    for col in ("Source IP", "Destination IP"):
        ips |= set(att[col].str.strip().dropna().unique())
    return {IP_MAP.get(ip, ip) for ip in ips}


def parse_alert_csv(path: str, gid_filter: set[str] | None = None):
    """
    Yield (src_ip, dst_ip, src_port, dst_port, proto_num, flow_id_fwd, flow_id_rev)
    for each alert line that passes the gid_filter.
    """
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 9:
                continue
            try:
                gid_sid_rev = parts[8].strip()
                gid = gid_sid_rev.split(":")[0]
                if gid_filter and gid not in gid_filter:
                    continue
                proto_str = parts[2].strip()
                src_ip, src_port = parse_ip_port(parts[6])
                dst_ip, dst_port = parse_ip_port(parts[7])
                if not src_ip or src_ip.startswith("224.") or src_ip.startswith("239."):
                    continue
                src_ip = IP_MAP.get(src_ip, src_ip)
                dst_ip = IP_MAP.get(dst_ip, dst_ip)
                proto_num = PROTO_MAP.get(proto_str, 0)
                fwd = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_num}"
                rev = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto_num}"
                yield src_ip, dst_ip, src_port, dst_port, proto_num, fwd, rev
            except Exception:
                continue


def community_stats(alert_path: str, attack_ips: set[str]) -> dict:
    """
    Compute community-rule stats using GID:1 only.
    Returns total_alerts, on_attack_ips, benign_alerts, alert_noise_pct,
    alerted_flow_ids (set, both directions).
    """
    total = 0
    on_attack = 0
    alerted = set()

    for src_ip, dst_ip, *_, fwd, rev in parse_alert_csv(alert_path, gid_filter={"1"}):
        total += 1
        if src_ip in attack_ips or dst_ip in attack_ips:
            on_attack += 1
        alerted.add(fwd)
        alerted.add(rev)

    benign = total - on_attack
    noise_pct = benign / total if total > 0 else 0.0
    return {
        "total_gid1_alerts": total,
        "on_attack_ips": on_attack,
        "benign_alerts": benign,
        "alert_noise_pct": round(noise_pct, 4),
        "alerted_flow_ids": alerted,
    }


def flow_confusion(df: pd.DataFrame, alerted_flow_ids: set[str]) -> dict:
    """Standard flow-level confusion matrix vs GT."""
    df = df.copy()
    df["Label_binary"] = (df["Label"] != "BENIGN").astype(int)
    df["Alerted"] = df["Flow ID"].isin(alerted_flow_ids).astype(int)
    TP = int(((df["Label_binary"] == 1) & (df["Alerted"] == 1)).sum())
    FP = int(((df["Label_binary"] == 0) & (df["Alerted"] == 1)).sum())
    TN = int(((df["Label_binary"] == 0) & (df["Alerted"] == 0)).sum())
    FN = int(((df["Label_binary"] == 1) & (df["Alerted"] == 0)).sum())
    benign_total = FP + TN
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    fpr = FP / benign_total if benign_total > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
    }


def ml_ip_confusion(alert_path: str, gid_filter: set[str], attack_ips: set[str], df_gt: pd.DataFrame) -> dict:
    """
    IP-level confusion for window-based inspectors:
    TP = attack IPs that generated at least one alert
    FP = benign IPs that generated at least one alert
    FN = attack IPs with no alert
    TN = benign IPs with no alert
    """
    alerted_ips: set[str] = set()
    for src_ip, dst_ip, *_ in parse_alert_csv(alert_path, gid_filter=gid_filter):
        alerted_ips.add(src_ip)

    all_src_ips = set(df_gt["Source IP"].str.strip().dropna().unique())
    all_src_ips = {IP_MAP.get(ip, ip) for ip in all_src_ips}

    TP = len(attack_ips & alerted_ips)
    FP = len((all_src_ips - attack_ips) & alerted_ips)
    FN = len(attack_ips - alerted_ips)
    TN = len((all_src_ips - attack_ips) - alerted_ips)
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "alerted_ips": sorted(alerted_ips & attack_ips),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
    }


DAY_CONFIG = {
    "Tuesday": {
        "gt_csvs": [str(GT_DIR / "Tuesday-WorkingHours.pcap_ISCX.csv")],
        "combined_alert": str(COMBINED_DIR / "Tuesday-WorkingHours/alert_csv.txt"),
    },
    "Wednesday": {
        "gt_csvs": [str(GT_DIR / "Wednesday-workingHours.pcap_ISCX.csv")],
        "combined_alert": str(COMBINED_DIR / "Wednesday-workingHours/alert_csv.txt"),
    },
    "Friday": {
        "gt_csvs": [
            str(GT_DIR / "Friday-WorkingHours-Morning.pcap_ISCX.csv"),
            str(GT_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
            str(GT_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"),
        ],
        "combined_alert": str(COMBINED_DIR / "Friday-WorkingHours/alert_csv.txt"),
    },
}

# GID filters per ML engine
RESULTS = REPO / "results"

# Per-inspector alert files (authoritative; combined files are old and missing newer GIDs)
ML_ENGINE_ALERTS = {
    "xgboost": {
        "mode": "flow",
        "days": {
            "Wednesday": str(RESULTS / "dos_inspector/Wednesday-workingHours/alert_csv.txt"),
        },
    },
    "bruteforce": {
        "mode": "ip",
        "days": {
            "Tuesday": str(RESULTS / "bruteforce/Tuesday/alert_csv.txt"),
        },
    },
    "bot": {
        "mode": "ip",
        "days": {
            "Friday": str(RESULTS / "bot_client/Friday-WorkingHours/alert_csv.txt"),
        },
    },
    "portscan": {
        "mode": "ip",
        "days": {
            "Friday": str(RESULTS / "portscan/Friday/alert_csv.txt"),
        },
    },
    "dos_agg": {
        "mode": "ip",
        "days": {
            "Friday": str(RESULTS / "dos_aggregator/Friday/alert_csv.txt"),
        },
    },
    "ddos": {
        "mode": "ip",
        "days": {
            "Friday": str(RESULTS / "ddos_aggregator/Friday-WorkingHours/alert_csv.txt"),
        },
    },
}


def main():
    results = {}

    for day, cfg in DAY_CONFIG.items():
        print(f"\n{'='*60}")
        print(f"DAY: {day}")
        print(f"{'='*60}")

        df_gt = load_gt(cfg["gt_csvs"])
        attack_ips = get_attack_ips(df_gt)
        print(f"GT: {len(df_gt):,} flows | benign={int((df_gt['Label']=='BENIGN').sum()):,} | attack={int((df_gt['Label']!='BENIGN').sum()):,}")
        print(f"Attack IPs: {sorted(attack_ips)[:6]}")

        comm = community_stats(cfg["combined_alert"], attack_ips)
        cf = flow_confusion(df_gt, comm["alerted_flow_ids"])

        print(f"\nCommunity (GID:1 only):")
        print(f"  Total GID:1 alerts: {comm['total_gid1_alerts']:,}")
        print(f"  On attack IPs:      {comm['on_attack_ips']:,}")
        print(f"  On benign IPs:      {comm['benign_alerts']:,}")
        print(f"  Alert noise %:      {comm['alert_noise_pct']*100:.1f}%")
        print(f"  Flow-level → TP={cf['TP']}, FP={cf['FP']}, TN={cf['TN']}, FN={cf['FN']}")
        print(f"  Precision={cf['precision']:.4f}  Recall={cf['recall']:.4f}  FPR={cf['fpr']:.4f}  F1={cf['f1']:.4f}")

        results[day] = {
            "gt": {
                "total_flows": len(df_gt),
                "benign_flows": int((df_gt["Label"] == "BENIGN").sum()),
                "attack_flows": int((df_gt["Label"] != "BENIGN").sum()),
                "attack_ips": sorted(attack_ips),
            },
            "community": {
                "total_gid1_alerts": comm["total_gid1_alerts"],
                "on_attack_ips": comm["on_attack_ips"],
                "benign_alerts": comm["benign_alerts"],
                "alert_noise_pct": comm["alert_noise_pct"],
                "flow_confusion": cf,
            },
            "ml": {},
        }

        # ML engines for this day — use per-inspector alert files
        for eng, ecfg in ML_ENGINE_ALERTS.items():
            if day not in ecfg["days"]:
                continue
            alert_path = ecfg["days"][day]
            if not Path(alert_path).exists():
                print(f"\nML [{eng}]: alert file missing: {alert_path}")
                continue
            if ecfg["mode"] == "flow":
                alerted = set()
                count = 0
                for src_ip, dst_ip, sp, dp, proto, fwd, rev in parse_alert_csv(alert_path):
                    alerted.add(fwd); alerted.add(rev); count += 1
                ml_cf = flow_confusion(df_gt, alerted)
                ml_cf["alert_count"] = count
                print(f"\nML [{eng}] (flow): alerts={count:,}  TP={ml_cf['TP']} FP={ml_cf['FP']} TN={ml_cf['TN']} FN={ml_cf['FN']}")
                print(f"  Prec={ml_cf['precision']:.4f}  Rec={ml_cf['recall']:.4f}  FPR={ml_cf['fpr']:.4f}  F1={ml_cf['f1']:.4f}")
            else:
                # IP-level: parse_alert_csv without gid_filter (file is single-inspector)
                alerted_ips: set[str] = set()
                count = 0
                for src_ip, *_ in parse_alert_csv(alert_path):
                    alerted_ips.add(src_ip); count += 1
                all_src_ips = {IP_MAP.get(ip, ip) for ip in df_gt["Source IP"].str.strip().dropna().unique()}
                TP = len(attack_ips & alerted_ips)
                FP = len((all_src_ips - attack_ips) & alerted_ips)
                FN = len(attack_ips - alerted_ips)
                TN = len((all_src_ips - attack_ips) - alerted_ips)
                prec = TP/(TP+FP) if (TP+FP)>0 else 0.0
                rec = TP/(TP+FN) if (TP+FN)>0 else 0.0
                fpr_val = FP/(FP+TN) if (FP+TN)>0 else 0.0
                f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
                ml_cf = {"alert_count": count, "TP": TP, "FP": FP, "TN": TN, "FN": FN,
                         "alerted_ips": sorted(alerted_ips & attack_ips),
                         "precision": round(prec,4), "recall": round(rec,4),
                         "fpr": round(fpr_val,4), "f1": round(f1,4)}
                print(f"\nML [{eng}] (ip): alerts={count}  TP_ips={TP} FP_ips={FP} FN_ips={FN}")
                print(f"  alerted_attack_ips={ml_cf['alerted_ips']}")
                print(f"  Prec={prec:.4f}  Rec={rec:.4f}  FPR={fpr_val:.4f}  F1={f1:.4f}")

            results[day]["ml"][eng] = ml_cf

    # Save results
    out_path = REPO / "results/community_baseline_corrected.json"
    # Remove non-serializable alerted_flow_ids before saving
    out = {}
    for day, d in results.items():
        out[day] = {
            "gt": d["gt"],
            "community": {k: v for k, v in d["community"].items() if k != "flow_ids"},
            "ml": d["ml"],
        }
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\n\nSaved → {out_path}")

    # Print summary table
    print("\n\n" + "="*80)
    print("CORRECTED COMMUNITY BASELINES (GID:1 only, no codec noise)")
    print("="*80)
    print(f"{'Day':<12} {'GID:1 alerts':>14} {'on_attack':>11} {'benign':>11} {'noise%':>8} {'FPR':>8} {'Recall':>8}")
    for day, d in out.items():
        c = d["community"]
        cf = c["flow_confusion"]
        print(f"{day:<12} {c['total_gid1_alerts']:>14,} {c['on_attack_ips']:>11,} {c['benign_alerts']:>11,} {c['alert_noise_pct']*100:>7.1f}% {cf['fpr']:>8.4f} {cf['recall']:>8.4f}")


if __name__ == "__main__":
    main()
