#!/usr/bin/env python3
"""SHAP analysis for bot_client model."""

import json
import numpy as np
import xgboost as xgb
import shap
import os

# Load model and scaler
MODEL_PATH = '/home/emirhan/bitirme/models/bot_client_model.json'
SCALER_PATH = '/home/emirhan/bitirme/models/bot_client_model_scaler.json'

def load_model(path):
    """Load XGBoost model."""
    model = xgb.XGBClassifier()
    model.load_model(path)
    return model

def load_scaler(path):
    """Load scaler params."""
    with open(path) as f:
        return json.load(f)

def preprocess(features, scaler):
    """Apply log1p + robust scaling."""
    median = np.array(scaler['median'])
    iqr = np.array(scaler['iqr'])
    
    # log1p transform
    features_log = np.log1p(features)
    
    # Robust scaling
    features_scaled = np.zeros_like(features_log)
    for i in range(len(median)):
        if iqr[i] != 0:
            features_scaled[:, i] = (features_log[:, i] - median[i]) / iqr[i]
        else:
            features_scaled[:, i] = 0.0
    
    return features_scaled

def load_friday_data():
    """Load Friday dump data for SHAP analysis."""
    import pandas as pd
    
    BOT_IPS = {
        '192.168.10.5', '192.168.10.8', '192.168.10.9',
        '192.168.10.12', '192.168.10.14', '192.168.10.15', '192.168.10.17'
    }
    FP_IPS = {'172.16.0.1', '192.168.10.19', '192.168.10.25', '192.168.10.51'}
    
    def int_to_ip(ip_int):
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    
    df = pd.read_csv('/tmp/botcl_dump/cicids_Friday.txt', comment='#', sep='\\s+',
                     names=['lb', 'syn_cnt', 'dst_ips', 'dst_ports', 'iat_cv', 
                            'entropy', 'port_ratio', 'rate', 'ip_conc', 'ip_ratio',
                            'ip_ent', 'iat_q90', 'time_den', 'p_ip_r', 'hshake',
                            'inc_r', 'data_d', 'rst_r', 'score', 'src_ip'])
    
    df['src_ip_str'] = df['src_ip'].apply(int_to_ip)
    df['is_bot'] = df['src_ip_str'].isin(BOT_IPS)
    df['is_fp'] = df['src_ip_str'].isin(FP_IPS)
    
    return df

def main():
    print("="*60)
    print("  BOT CLIENT SHAP ANALYSIS")
    print("="*60)
    
    # Load model
    print("\n[1] Loading model...")
    model = load_model(MODEL_PATH)
    scaler = load_scaler(SCALER_PATH)
    print(f"  Model loaded: {MODEL_PATH}")
    print(f"  Scaler: {len(scaler['median'])} features")
    
    # Feature names
    FEATURE_NAMES = ['syn_cnt', 'dst_ips', 'dst_ports', 'iat_cv', 'entropy', 
                     'port_ratio', 'rate', 'ip_conc', 'ip_ratio', 'ip_ent',
                     'iat_q90', 'time_den', 'p_ip_r', 'hshake', 'inc_r', 
                     'data_d', 'rst_r']
    
    # Load data
    print("\n[2] Loading Friday data...")
    df = load_friday_data()
    
    # Extract features (excluding lb, score, src_ip)
    feature_cols = FEATURE_NAMES
    X = df[feature_cols].values
    y = df['is_bot'].astype(int).values
    
    print(f"  Total samples: {len(X)}")
    print(f"  Bot samples: {y.sum()} ({y.mean()*100:.1f}%)")
    
    # Preprocess
    print("\n[3] Preprocessing...")
    X_scaled = preprocess(X, scaler)
    
    # Sample for SHAP (use subset for speed)
    print("\n[4] Computing SHAP values (sampling 500 background + 200 eval)...")
    np.random.seed(42)
    
    # Background samples (for TreeExplainer)
    bg_idx = np.random.choice(len(X_scaled), min(500, len(X_scaled)), replace=False)
    X_bg = X_scaled[bg_idx]
    
    # Evaluation samples
    eval_idx = np.random.choice(len(X_scaled), min(200, len(X_scaled)), replace=False)
    X_eval = X_scaled[eval_idx]
    y_eval = y[eval_idx]
    
    # SHAP analysis
    print("\n[5] Running TreeExplainer...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_eval)
    
    # SHAP summary
    print("\n[6] SHAP Feature Importance (mean |SHAP|):")
    mean_shap = np.abs(shap_values).mean(axis=0)
    importance_order = np.argsort(mean_shap)[::-1]
    
    print(f"\n  {'Rank':<5} {'Feature':<15} {'Mean|SHAP|':>12} {'Relative':>10}")
    print(f"  {'-'*44}")
    max_shap = mean_shap[importance_order[0]]
    for rank, idx in enumerate(importance_order[:15], 1):
        rel = mean_shap[idx] / max_shap * 100
        print(f"  {rank:<5} {FEATURE_NAMES[idx]:<15} {mean_shap[idx]:>12.6f} {rel:>9.1f}%")
    
    # SHAP for bot vs FP vs benign
    print("\n" + "="*60)
    print("  SHAP BY CLASS")
    print("="*60)
    
    bot_mask = y_eval == 1
    benign_mask = y_eval == 0
    
    if bot_mask.sum() > 0:
        print("\n  Bot class (true positives):")
        bot_shap = np.abs(shap_values[bot_mask]).mean(axis=0)
        bot_order = np.argsort(bot_shap)[::-1]
        for rank, idx in enumerate(bot_order[:5], 1):
            print(f"    {rank}. {FEATURE_NAMES[idx]}: {bot_shap[idx]:.6f}")
    
    if benign_mask.sum() > 0:
        print("\n  Benign class (true negatives):")
        ben_shap = np.abs(shap_values[benign_mask]).mean(axis=0)
        ben_order = np.argsort(ben_shap)[::-1]
        for rank, idx in enumerate(ben_order[:5], 1):
            print(f"    {rank}. {FEATURE_NAMES[idx]}: {ben_shap[idx]:.6f}")
    
    # SHAP dependence plots (text version)
    print("\n" + "="*60)
    print("  FEATURE EFFECT ANALYSIS")
    print("="*60)
    
    # For top 3 features, show how SHAP varies with feature value
    for feat_idx in importance_order[:3]:
        feat_name = FEATURE_NAMES[feat_idx]
        feat_vals = X_eval[:, feat_idx]
        shap_vals = shap_values[:, feat_idx]
        
        # Bin feature values
        bins = np.percentile(feat_vals, [0, 25, 50, 75, 100])
        print(f"\n  {feat_name}:")
        print(f"    Value range: [{feat_vals.min():.3f}, {feat_vals.max():.3f}]")
        
        for i in range(len(bins)-1):
            mask = (feat_vals >= bins[i]) & (feat_vals <= bins[i+1])
            if mask.sum() > 0:
                mean_shap_val = shap_vals[mask].mean()
                print(f"    [{bins[i]:.3f}-{bins[i+1]:.3f}]: mean SHAP = {mean_shap_val:+.4f} (n={mask.sum()})")
    
    print("\n" + "="*60)
    print("  KEY INSIGHTS")
    print("="*60)
    
    # Check constant features
    print("\n  Constant features (should have near-zero SHAP):")
    for idx, name in enumerate(FEATURE_NAMES):
        if name in ['hshake', 'inc_r', 'data_d', 'rst_r']:
            print(f"    {name}: mean|SHAP| = {mean_shap[idx]:.6f}")
    
    # Top discriminative features
    print("\n  Top 5 discriminative features:")
    for rank, idx in enumerate(importance_order[:5], 1):
        print(f"    {rank}. {FEATURE_NAMES[idx]}")
    
    print("\n  Recommendation:")
    print("    - Remove constant features (hshake, inc_r, data_d, rst_r)")
    print("    - Add internal_ip_ratio to separate internal scanning from external C2")
    print("    - Focus on top features for threshold optimization")

if __name__ == '__main__':
    main()
