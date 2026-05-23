#!/usr/bin/env python3
"""Threshold optimization for bot_client model."""
import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score

DUMP_DIR = "/tmp/botcl_dump"

def int_to_ip(ip_int):
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def load_and_label(fname, bot_ips=None, label=0):
    path = f"{DUMP_DIR}/{fname}"
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path, comment='#', sep='\\s+',
                     names=['lb', 'syn_cnt', 'dst_ips', 'dst_ports', 'iat_cv', 
                            'entropy', 'port_ratio', 'rate', 'ip_conc', 'ip_ratio',
                            'ip_ent', 'iat_q90', 'time_den', 'p_ip_r', 'hshake',
                            'inc_r', 'data_d', 'rst_r', 'int_ratio', 'score', 'src_ip'])
    df['src_ip_str'] = df['src_ip'].apply(int_to_ip)
    if bot_ips:
        df['label'] = df['src_ip_str'].isin(bot_ips).astype(int)
    else:
        df['label'] = label
    return df

import os

print("="*70)
print("  THRESHOLD OPTIMIZATION")
print("="*70)

# Load data
all_data = []

# Friday: bot IPs = CICIDS bot clients
friday = load_and_label("cicids_Friday.txt",
    bot_ips={'192.168.10.5','192.168.10.8','192.168.10.9','192.168.10.12','192.168.10.14','192.168.10.15','192.168.10.17'})
if friday is not None:
    all_data.append(friday)
    print(f"Friday: {len(friday)} rows, {friday['label'].sum()} bot")

# Monday-Thursday: all benign
for day in ["Monday", "Tuesday", "Wednesday", "Thursday"]:
    df = load_and_label(f"cicids_{day}.txt", label=0)
    if df is not None:
        all_data.append(df)

# Xworm: bot
xworm = load_and_label("mta_xworm.txt", label=1)
if xworm is not None:
    all_data.append(xworm)
    print(f"Xworm: {len(xworm)} rows, bot")

# 31-Jan: bot
jan31 = load_and_label("mta_31jan.txt", label=1)
if jan31 is not None:
    all_data.append(jan31)
    print(f"31-Jan: {len(jan31)} rows, bot")

# 28-Feb: benign  
feb28 = load_and_label("mta_28feb.txt", label=0)
if feb28 is not None:
    all_data.append(feb28)
    print(f"28-Feb: {len(feb28)} rows")

# CTU-13: bot
for ctu_file in ["ctu_042219.txt", "ctu_060319.txt"]:
    ctu = load_and_label(ctu_file, label=1)
    if ctu is not None:
        all_data.append(ctu)

print(f"\nTotal datasets: {len(all_data)}")

combined = pd.concat(all_data, ignore_index=True)
print(f"Total rows: {len(combined)}")
print(f"Bot: {combined['label'].sum()}, Benign: {(~combined['label'].astype(bool)).sum()}")

# Check score distribution
print("\nScore distribution:")
for day_name in ["cicids_Friday", "cicids_Monday", "mta_xworm", "mta_31jan", "mta_28feb", "ctu_042219"]:
    df = load_and_label(f"{day_name}.txt", label=None)  
    if df is not None and len(df) > 0:
        print(f"  {day_name}: score range [{df['score'].min():.4f}, {df['score'].max():.4f}], mean={df['score'].mean():.4f}")

# Threshold sweep
print("\n" + "="*70)
print("  SWEEP: threshold vs Friday + Xworm detection")
print("="*70)
print(f"{'Threshold':<12} {'FP':<8} {'FN':<8} {'Prec':<8} {'Rec':<8} {'F1':<8} {'XwormOK':<8}")
print("-"*60)

X_SCORE = xworm['score'].values[0] if xworm is not None and len(xworm) > 0 else 0
print(f"  Xworm score: {X_SCORE:.4f}")

friday_data = friday.copy() if friday is not None else pd.DataFrame()
for thr in [0.01, 0.02, 0.05, 0.07, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
    # Friday eval
    if len(friday_data) > 0:
        y_true_fri = friday_data['label']
        y_pred_fri = (friday_data['score'] > thr).astype(int)
        tp = ((y_true_fri == 1) & (y_pred_fri == 1)).sum()
        fp = ((y_true_fri == 0) & (y_pred_fri == 1)).sum()
        fn = ((y_true_fri == 1) & (y_pred_fri == 0)).sum()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    else:
        tp = fp = fn = 0; prec = rec = f1 = 0
    
    xworm_ok = (X_SCORE > thr)
    
    print(f"{thr:<12.2f} {fp:<8} {fn:<8} {prec:<8.3f} {rec:<8.3f} {f1:<8.3f} {'YES' if xworm_ok else 'NO':<8}")
