#!/usr/bin/env python3
"""Phase 1 Diagnostic: Analyze bot_client feature distributions and scores."""

import pandas as pd
import numpy as np
from collections import defaultdict
import os

# Known bot IPs from CICIDS Friday
BOT_IPS = {
    '192.168.10.5', '192.168.10.8', '192.168.10.9',
    '192.168.10.12', '192.168.10.14', '192.168.10.15', '192.168.10.17'
}

# Known FP IPs from evaluation
FP_IPS = {'172.16.0.1', '192.168.10.19', '192.168.10.25', '192.168.10.51'}

# Benign IPs (from Monday, not in bot/FP lists)
BENIGN_IPS = {'192.168.10.16', '192.168.10.3', '192.168.10.2'}

def ip_to_int(ip_str):
    """Convert dotted IP to integer."""
    parts = [int(p) for p in ip_str.split('.')]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(ip_int):
    """Convert integer IP to dotted string."""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def load_dump(path):
    """Load a dump file into DataFrame."""
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path, comment='#', sep='\s+', 
                     names=['lb', 'syn_cnt', 'dst_ips', 'dst_ports', 'iat_cv', 
                            'entropy', 'port_ratio', 'rate', 'ip_conc', 'ip_ratio',
                            'ip_ent', 'iat_q90', 'time_den', 'p_ip_r', 'hshake',
                            'inc_r', 'data_d', 'rst_r', 'score', 'src_ip'])
    df['src_ip_str'] = df['src_ip'].apply(int_to_ip)
    df['is_bot'] = df['src_ip_str'].isin(BOT_IPS)
    df['is_fp'] = df['src_ip_str'].isin(FP_IPS)
    return df

def analyze_scores(df, name):
    """Analyze score distribution for different IP classes."""
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    print(f"  Total rows: {len(df)}")
    
    # Score stats by class
    for cls, mask, label in [
        (BOT_IPS, df['is_bot'], 'Bot IPs'),
        (FP_IPS, df['is_fp'], 'FP IPs'),
        (None, (~df['is_bot']) & (~df['is_fp']), 'Other (benign)')
    ]:
        subset = df[mask]
        if len(subset) == 0:
            continue
        print(f"\n  {label}: {len(subset)} rows, {subset['src_ip_str'].nunique()} unique IPs")
        print(f"    Score: mean={subset['score'].mean():.4f}, std={subset['score'].std():.4f}")
        print(f"    Score: min={subset['score'].min():.4f}, max={subset['score'].max():.4f}")
        print(f"    Score > 0.95: {(subset['score'] > 0.95).sum()} ({(subset['score'] > 0.95).mean()*100:.1f}%)")
        print(f"    Score < 0.50: {(subset['score'] < 0.50).sum()} ({(subset['score'] < 0.50).mean()*100:.1f}%)")

def analyze_features(df, name):
    """Analyze feature distributions."""
    print(f"\n{'='*60}")
    print(f"  FEATURE ANALYSIS: {name}")
    print(f"{'='*60}")
    
    feature_cols = ['syn_cnt', 'dst_ips', 'dst_ports', 'iat_cv', 'entropy', 
                    'port_ratio', 'rate', 'ip_conc', 'ip_ratio', 'ip_ent']
    
    # Compare bot vs benign
    bot_df = df[df['is_bot']]
    benign_df = df[(~df['is_bot']) & (~df['is_fp'])]
    
    if len(bot_df) > 0 and len(benign_df) > 0:
        print("\n  Feature means (Bot vs Benign):")
        print(f"  {'Feature':<15} {'Bot':>10} {'Benign':>10} {'Ratio':>10}")
        print(f"  {'-'*47}")
        for col in feature_cols:
            bot_mean = bot_df[col].mean()
            ben_mean = benign_df[col].mean()
            ratio = bot_mean / ben_mean if ben_mean > 0 else float('inf')
            print(f"  {col:<15} {bot_mean:>10.3f} {ben_mean:>10.3f} {ratio:>10.2f}")

def check_constant_features(df, name):
    """Check which features are constant."""
    print(f"\n{'='*60}")
    print(f"  CONSTANT FEATURE CHECK: {name}")
    print(f"{'='*60}")
    
    feature_cols = ['hshake', 'inc_r', 'data_d', 'rst_r']
    for col in feature_cols:
        unique_vals = df[col].nunique()
        mean_val = df[col].mean()
        status = "CONSTANT" if unique_vals == 1 else "VARIES"
        print(f"  {col:<10}: {unique_vals} unique values, mean={mean_val:.4f} [{status}]")

def main():
    print("="*60)
    print("  BOT CLIENT PHASE 1 DIAGNOSTIC")
    print("="*60)
    
    # Load all dumps
    dumps = {
        'Friday (attack)': '/tmp/botcl_dump/cicids_Friday.txt',
        'Monday (benign)': '/tmp/botcl_dump/cicids_Monday.txt',
        'Tuesday (benign)': '/tmp/botcl_dump/cicids_Tuesday.txt',
        'Wednesday (benign)': '/tmp/botcl_dump/cicids_Wednesday.txt',
        'Thursday (benign)': '/tmp/botcl_dump/cicids_Thursday.txt',
        'Xworm (MTA)': '/tmp/botcl_dump/mta_xworm.txt',
        '31-Jan (MTA)': '/tmp/botcl_dump/mta_31jan.txt',
        '28-Feb (MTA)': '/tmp/botcl_dump/mta_28feb.txt',
        'CTU-13 #1': '/tmp/botcl_dump/ctu_042219.txt',
        'CTU-13 #2': '/tmp/botcl_dump/ctu_060319.txt',
    }
    
    all_data = {}
    for name, path in dumps.items():
        df = load_dump(path)
        if df is not None:
            all_data[name] = df
    
    # 1. Score analysis
    for name, df in all_data.items():
        analyze_scores(df, name)
    
    # 2. Feature analysis on key datasets
    for name in ['Friday (attack)', 'Monday (benign)', 'Xworm (MTA)']:
        if name in all_data:
            analyze_features(all_data[name], name)
    
    # 3. Constant feature check
    for name, df in all_data.items():
        check_constant_features(df, name)
    
    # 4. Xworm deep dive
    print("\n" + "="*60)
    print("  XWORM DEEP DIVE")
    print("="*60)
    if 'Xworm (MTA)' in all_data:
        xworm = all_data['Xworm (MTA)']
        print(f"\n  Xworm rows: {len(xworm)}")
        print(f"  Xworm unique IPs: {xworm['src_ip_str'].nunique()}")
        print(f"  Xworm IPs: {xworm['src_ip_str'].unique().tolist()}")
        print(f"\n  Xworm feature values:")
        for col in xworm.columns:
            if col not in ['src_ip', 'src_ip_str']:
                print(f"    {col}: {xworm[col].values}")
    
    # 5. Score distribution histogram data
    print("\n" + "="*60)
    print("  SCORE DISTRIBUTION (binned)")
    print("="*60)
    for name, df in all_data.items():
        bins = [0, 0.5, 0.8, 0.9, 0.95, 0.99, 1.0]
        hist, _ = np.histogram(df['score'], bins=bins)
        print(f"\n  {name}:")
        for i, (lo, hi) in enumerate(zip(bins[:-1], bins[1:])):
            print(f"    [{lo:.2f}-{hi:.2f}]: {hist[i]}")

if __name__ == '__main__':
    main()
