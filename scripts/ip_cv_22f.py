#!/usr/bin/env python3
"""IP-based cross-validation for 22-feature model."""
import os, glob, json
import pandas as pd, numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix

DUMP_DIR = "/tmp/botcl_dump"

def ip_to_str(ip_int):
    return f"{(ip_int>>24)&0xFF}.{(ip_int>>16)&0xFF}.{(ip_int>>8)&0xFF}.{ip_int&0xFF}"

def load_data():
    rows = []
    for fpath in sorted(glob.glob(os.path.join(DUMP_DIR, "*.txt"))):
        with open(fpath) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                p = line.strip().split()
                if len(p) < 25:
                    continue
                rows.append({
                    "lb": int(p[0]),
                    "src_ip": int(p[24]),
                    "f": [float(p[i]) for i in range(1, 23)],
                })
    df = pd.DataFrame(rows)
    # Label based on known bot IPs
    bot_ips = {'192.168.10.5','192.168.10.8','192.168.10.9','192.168.10.12','192.168.10.14','192.168.10.15','192.168.10.17',
               '10.1.14.128','10.1.21.58'}
    df["ip_str"] = df["src_ip"].apply(ip_to_str)
    df["label"] = df["ip_str"].isin(bot_ips).astype(int)
    # Also label CTU-13 as bot
    df.loc[df["ip_str"].str.startswith("192.168.1."), "label"] = 1
    return df

df = load_data()
print(f"Total: {len(df)} rows, {df['ip_str'].nunique()} IPs")
print(f"Bot: {df['label'].sum()}, Benign: {(~df['label'].astype(bool)).sum()}")

# IP-based CV
from sklearn.model_selection import train_test_split
unique_ips = list(df["ip_str"].unique())
train_ips, val_ips = train_test_split(unique_ips, test_size=0.2, random_state=42)
train = df[df["ip_str"].isin(train_ips)]
val = df[df["ip_str"].isin(val_ips)]

X_train = np.vstack(train["f"].values)
y_train = train["label"].values
X_val = np.vstack(val["f"].values)
y_val = val["label"].values

print(f"\nTrain: {len(X_train)} ({y_train.sum()} bot, {len(train_ips)} IPs)")
print(f"Val: {len(X_val)} ({y_val.sum()} bot, {len(val_ips)} IPs)")

model = XGBClassifier(n_estimators=500, max_depth=6, learning_rate=0.05,
    subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
    scale_pos_weight=(len(y_train)-y_train.sum())/y_train.sum(),
    random_state=42, eval_metric="logloss")
model.fit(X_train, y_train)

y_pred = model.predict(X_val)
y_proba = model.predict_proba(X_val)[:, 1]
print(f"\n=== IP-Based CV Results ===")
print(confusion_matrix(y_val, y_pred))
print(classification_report(y_val, y_pred, digits=4))
print(f"Score range: [{y_proba.min():.4f}, {y_proba.max():.4f}]")
print(f"Bot mean: {y_proba[y_val==1].mean():.4f}")
print(f"Benign mean: {y_proba[y_val==0].mean():.4f}")
