#!/usr/bin/env python3
"""
bot_client_v2_training.py — Phase 1c/2: Label dump files and train XGBoost model
"""
import os
import glob
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
import json

BASE_DIR = "/home/emirhan/bitirme"
DUMP_DIR = "/tmp/botcl_dump"
GT_DIR = f"{BASE_DIR}/data/raw/cicids2017"

# Known bot IPs per PCAP (for non-CICIDS)
# For CTU-13: all internal IPs are bots (victims), but the attacker IPs vary
# We label ALL internal IPs from CTU-13 as bot since they're botnet captures
KNOWN_BOTS = {
    "mta_xworm": {"10.1.14.128"},
    "mta_31jan": {"10.1.21.58"},
    "mta_28feb": set(),  # All benign
}

# Known hard-negatives (frequent false positive IPs)
# These patterns should be learned as EXTRA benign
HARD_NEGATIVE_IPS = {
    "192.168.10.16", "192.168.10.19", "192.168.10.25",
    "192.168.10.3", "192.168.10.50", "192.168.10.51",
    "172.16.0.1", "10.2.28.88",
}
CTU13_AS_BOT = {"ctu_042219", "ctu_060319"}

# CICIDS specific bot client IPs (Friday has Bot-labeled flows from these IPs)
CICIDS_BOT_CLIENT_IPS = {
    "Monday": set(),
    "Tuesday": set(),
    "Wednesday": set(),
    "Thursday": set(),
    "Friday": {"192.168.10.5", "192.168.10.8", "192.168.10.9",
               "192.168.10.12", "192.168.10.14", "192.168.10.15", "192.168.10.17"},
}

def get_attacker_ips_from_csv(day_name):
    """
    Read ground truth CSV and extract bot client source IPs.
    For Friday: uses Friday-WorkingHours-Morning.pcap_ISCX.csv which has 'Bot' labeled flows.
    """
    csv_files = {
        "Monday": "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday": "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday": "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Friday": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    }
    
    if day_name not in csv_files:
        return set()
    
    csv_path = os.path.join(GT_DIR, csv_files[day_name])
    if not os.path.exists(csv_path):
        print(f"  CSV not found: {csv_path}")
        return set()
    
    print(f"  Reading {csv_path}...")
    attacker_ips = set()
    try:
        df = pd.read_csv(csv_path, usecols=["Source IP", "Label"], low_memory=False)
        attacker_mask = df["Label"] != "BENIGN"
        attacker_ips = set(df.loc[attacker_mask, "Source IP"].unique())
        print(f"  Found {len(attacker_ips)} attacker IPs in CSV")
    except Exception as e:
        print(f"  Error reading CSV: {e}")
    
    return attacker_ips

def load_dump_file(filepath):
    """Load a dump file into a DataFrame"""
    rows = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 25:
                continue
            # Columns: lb syn_cnt dst_ips dst_ports iat_cv entropy port_ratio rate ip_conc 
            #          ip_ratio ip_entropy iat_q90 time_density port_ip_ratio handshake 
            #          inc_ratio data_density rst_rate internal_ip_ratio
            #          incoming_bytes fin_ratio push_ratio tcp_win score src_ip
            row = {
                "lb": int(parts[0]),
                "syn_cnt": float(parts[1]),
                "dst_ips": float(parts[2]),
                "dst_ports": float(parts[3]),
                "iat_cv": float(parts[4]),
                "entropy": float(parts[5]),
                "port_ratio": float(parts[6]),
                "rate": float(parts[7]),
                "ip_conc": float(parts[8]),
                "ip_ratio": float(parts[9]),
                "ip_entropy": float(parts[10]),
                "iat_q90": float(parts[11]),
                "time_density": float(parts[12]),
                "port_ip_ratio": float(parts[13]),
                "handshake": float(parts[14]),
                "inc_ratio": float(parts[15]),
                "data_density": float(parts[16]),
                "rst_rate": float(parts[17]),
                "internal_ip_ratio": float(parts[18]),
                "incoming_bytes": float(parts[19]),
                "fin_ratio": float(parts[20]),
                "push_ratio": float(parts[21]),
                "tcp_win": float(parts[22]),
                "score": float(parts[23]),
                "src_ip": int(parts[24]),
            }
            rows.append(row)
    return pd.DataFrame(rows)

def ip_to_str(ip_int):
    """Convert integer IP to dotted string"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def main():
    print("=== Bot Client V2 Training ===")
    print(f"Dump directory: {DUMP_DIR}")
    
    # Collect all data
    all_data = []
    
    dump_files = sorted(glob.glob(os.path.join(DUMP_DIR, "*.txt")))
    print(f"Found {len(dump_files)} dump files")
    
    for dump_file in dump_files:
        basename = os.path.basename(dump_file).replace(".txt", "")
        print(f"\nProcessing {basename}...")
        
        df = load_dump_file(dump_file)
        if df.empty:
            print(f"  Empty dump, skipping")
            continue
        
        print(f"  Loaded {len(df)} rows")
        
        # Determine attacker IPs for this PCAP
        attacker_ips = set()
        
        if basename.startswith("cicids_"):
            day = basename.replace("cicids_", "")
            # Use hardcoded bot client IPs (from CICIDS literature)
            attacker_ips = CICIDS_BOT_CLIENT_IPS.get(day, set())
            print(f"  Day={day}, {len(attacker_ips)} bot IPs: {sorted(attacker_ips)}")
        elif basename in KNOWN_BOTS:
            attacker_ips = KNOWN_BOTS[basename]
            print(f"  Known bots: {attacker_ips}")
        elif basename in CTU13_AS_BOT:
            # CTU-13 botnet captures: ALL internal IPs are bot clients
            df["src_ip_str"] = df["src_ip"].apply(ip_to_str)
            df["label"] = 1
            print(f"  CTU-13 botnet: labeling all {len(df)} rows as bot")
            all_data.append(df)
            continue
        else:
            print(f"  Unknown PCAP type ({basename}), assuming all benign")
        
        # Convert src_ip to string for matching
        df["src_ip_str"] = df["src_ip"].apply(ip_to_str)
        
        # Label: 1 if src_ip is in attacker_ips, else 0
        df["label"] = df["src_ip_str"].apply(lambda x: 1 if x in attacker_ips else 0)
        
        print(f"  Labeled: {df['label'].sum()} bot windows, {(~df['label'].astype(bool)).sum()} benign windows")
        
        all_data.append(df)
    
    if not all_data:
        print("No data collected!")
        return
    
    # Combine all data
    combined = pd.concat(all_data, ignore_index=True)
    print(f"\n=== Combined Dataset ===")
    print(f"Total rows: {len(combined)}")
    print(f"Bot windows: {combined['label'].sum()} ({100*combined['label'].mean():.1f}%)")
    print(f"Benign windows: {(~combined['label'].astype(bool)).sum()}")
    
    # Balance classes: downsample benign to 3x bot count
    bot_mask = combined["label"] == 1
    benign_mask = combined["label"] == 0
    n_bot = bot_mask.sum()
    n_benign = benign_mask.sum()
    
    if n_bot > 0 and n_benign > n_bot * 3:
        print(f"\n=== Downsampling benign from {n_benign} to {n_bot * 3} ===")
        benign_sample = combined[benign_mask].sample(n=n_bot * 3, random_state=42)
        combined = pd.concat([combined[bot_mask], benign_sample], ignore_index=True)
        print(f"After downsampling: {len(combined)} total")
        print(f"  Bot: {combined['label'].sum()}, Benign: {(~combined['label'].astype(bool)).sum()}")
    
    # Production training: use ALL data (no validation split)
    # Max capacity model for deployment
    feature_cols = [
        "syn_cnt", "dst_ips", "dst_ports", "iat_cv", "entropy", "port_ratio", "rate",
        "ip_conc", "ip_ratio", "ip_entropy", "iat_q90", "time_density", "port_ip_ratio",
        "handshake", "inc_ratio", "data_density", "rst_rate", "internal_ip_ratio",
        "incoming_bytes", "fin_ratio", "push_ratio", "tcp_win"
    ]
    
    X = combined[feature_cols].values
    y = combined["label"].values
    
    # Create sample weights: hard-negatives get 3x weight to reduce FPs
    sample_weight = np.ones(len(combined))
    hard_neg_mask = combined["src_ip_str"].isin(HARD_NEGATIVE_IPS) & (~combined["label"].astype(bool))
    sample_weight[hard_neg_mask] = 3.0
    print(f"\nHard-negative mining: {hard_neg_mask.sum()} FP windows weighted 3x")
    
    print(f"\nFull dataset: {len(X)} ({y.sum()} bot, {len(y)-y.sum()} benign)")
    print(f"Feature matrix shape: {X.shape}")
    
    if y.sum() == 0:
        print("ERROR: No positive samples! Check labeling logic.")
        return
    
    print("\n=== Training XGBoost (production) ===")
    n_pos = y.sum()
    n_neg = len(y) - n_pos
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1.0
    print(f"Class balance: {n_neg} benign, {n_pos} bot, scale_pos_weight={scale_pos_weight:.1f}")
    
    model = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        eval_metric="logloss",
    )
    
    model.fit(X, y, sample_weight=sample_weight)
    
    # Evaluate on full data
    from sklearn.metrics import classification_report, confusion_matrix
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]
    
    print("\n=== Training Results ===")
    print(confusion_matrix(y, y_pred))
    print(classification_report(y, y_pred, digits=4))
    print(f"\nScore range: [{y_proba.min():.4f}, {y_proba.max():.4f}]")
    
    # Score distribution
    bot_scores = y_proba[y == 1]
    ben_scores = y_proba[y == 0]
    print(f"Bot mean score: {bot_scores.mean():.4f}")
    print(f"Benign mean score: {ben_scores.mean():.4f}")
    print(f"Bot score range: [{bot_scores.min():.4f}, {bot_scores.max():.4f}]")
    print(f"Benign score range: [{ben_scores.min():.4f}, {ben_scores.max():.4f}]")
    
    # Feature importance
    print("\n=== Feature Importance ===")
    for feat, imp in sorted(zip(feature_cols, model.feature_importances_), key=lambda x: -x[1])[:10]:
        print(f"  {feat}: {imp:.4f}")
    
    # Save model
    model_path = os.path.join(BASE_DIR, "models", "bot_client_v2.json")
    model.save_model(model_path)
    print(f"\nModel saved to {model_path}")
    
    # Save feature columns for C++ scaler update
    feature_json = {
        "feature_columns": feature_cols,
        "training_samples": int(len(combined)),
        "bot_samples": int(combined["label"].sum()),
        "benign_samples": int((~combined["label"].astype(bool)).sum()),
    }
    with open(model_path.replace(".json", "_meta.json"), "w") as f:
        json.dump(feature_json, f, indent=2)
    print(f"Metadata saved to {model_path.replace('.json', '_meta.json')}")
    
    # Compute new scaler params (median/IQR from TRAINING data only)
    print("\n=== Computing Scaler Params ===")
    medians = np.median(X, axis=0)
    q1 = np.percentile(X, 25, axis=0)
    q3 = np.percentile(X, 75, axis=0)
    iqr = q3 - q1
    
    print("Medians:", medians)
    print("IQRs:", iqr)
    
    # Save scaler params for C++ (keys must match scaler_loader.h: "median" and "iqr")
    scaler_json = {
        "median": medians.tolist(),
        "iqr": iqr.tolist(),
    }
    with open(model_path.replace(".json", "_scaler.json"), "w") as f:
        json.dump(scaler_json, f, indent=2)
    print(f"Scaler params saved to {model_path.replace('.json', '_scaler.json')}")

if __name__ == "__main__":
    main()
