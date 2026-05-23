#!/usr/bin/env python3
"""Train bruteforce model from C++ dump files (10 features, IP-based CV)."""
import os, glob, json
import numpy as np, pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix

DUMP_DIR = "/tmp/bfc_dump"

BF_ATTACKER_IP = "172.16.0.1"
HARD_NEGATIVE_IPS = {"192.168.10.25"}

def ip_to_str(ip_int):
    return f"{(ip_int>>24)&0xFF}.{(ip_int>>16)&0xFF}.{(ip_int>>8)&0xFF}.{ip_int&0xFF}"

def load_dump(path):
    """Load a bruteforce dump file."""
    rows = []
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) < 12:  # lb + 10 feats + score + src_ip = 13
                continue
            src_ip = int(parts[-1])
            ip_str = ip_to_str(src_ip)
            rows.append({
                "ip_str": ip_str,
                "src_ip": src_ip,
                "f": [float(parts[i]) for i in range(1, 11)],  # 10 features
                "score": float(parts[-2]),
            })
    return pd.DataFrame(rows)

# Load all dumps
all_data = []
for fpath in sorted(glob.glob(os.path.join(DUMP_DIR, "*.txt"))):
    name = os.path.basename(fpath).replace("bfc_", "").replace(".txt", "")
    df = load_dump(fpath)
    if df.empty:
        continue
    # Label: 172.16.0.1 is the known bruteforce attacker
    df["label"] = (df["ip_str"] == BF_ATTACKER_IP).astype(int)
    all_data.append(df)
    print(f"{name}: {len(df)} rows, {df['label'].sum()} attacker")

combined = pd.concat(all_data, ignore_index=True)
print(f"\nTotal: {len(combined)} rows, {combined['label'].sum()} attacker")

# ─── Augment with synthetic slow-rate attacker samples ───────────────
# The model misses slow bruteforce (3-7 SYNs/120s). Add synthetic samples.
slow_synths = []
for n_syns in [3, 4, 5, 6, 7]:  # slow windows
    for i in range(50):  # 50 per size
        # hshake = 1.0 (all SYNs get SYN-ACK)
        # rst_ah = 1.0 (all handshakes end with RST)
        # bytes = 0 (no data payload in bruteforce)
        slow_synths.append({
            "ip_str": "10.0.0.1",
            "src_ip": 0x0A000001,
            "f": [
                float(n_syns),           # syn_count (3-7)
                1.0,                      # dst_ips (1 target)
                1.0,                      # dst_ports (1 port, SSH)
                1.0 / max(n_syns, 1),    # port_ratio
                1.0,                      # single_port_score (all to one port)
                float(n_syns) / 120.0,    # rate (SYN/120s)
                0.8 + np.random.random() * 0.4,  # iat_cv (regular timing)
                1.0,                      # hshake_ratio (all complete)
                1.0,                      # rst_after_hshake (all fail auth)
                0.0,                      # bytes_per_syn (no data)
            ],
            "score": 0.0,
        })
df = pd.DataFrame(slow_synths)
df["label"] = 1
combined = pd.concat([combined, df], ignore_index=True)
print(f"After augmentation: {len(combined)} rows, {combined['label'].sum()} attacker (+{len(slow_synths)} synth)")

# Feature matrix
feature_cols = [f"f{i}" for i in range(10)]
X = np.vstack(combined["f"].values)
y = combined["label"].values
ip_strs = combined["ip_str"].values

# IP-based CV split
unique_ips = list(combined["ip_str"].unique())
from sklearn.model_selection import train_test_split
train_ips, val_ips = train_test_split(unique_ips, test_size=0.2, random_state=42)

train_mask = combined["ip_str"].isin(train_ips)
val_mask = combined["ip_str"].isin(val_ips)

X_train, y_train = X[train_mask], y[train_mask]
X_val, y_val = X[val_mask], y[val_mask]

print(f"\nTrain: {len(X_train)} ({y_train.sum()} attacker, {len(train_ips)} IPs)")
print(f"Val: {len(X_val)} ({y_val.sum()} attacker, {len(val_ips)} IPs)")

if y_val.sum() == 0:
    print("WARNING: No attacker IP in validation set!")
    # Fall back to window-based split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Fallback window split: train={len(X_train)}, val={len(X_val)}")

# Scale log1p
from sklearn.preprocessing import RobustScaler
scaler_raw = RobustScaler(quantile_range=(25, 75))
X_train_s = scaler_raw.fit_transform(np.log1p(X_train))
X_val_s = scaler_raw.transform(np.log1p(X_val))

# Train
ratio = (len(y_train) - y_train.sum()) / y_train.sum() if y_train.sum() > 0 else 1.0
print(f"\nTraining (scale_pos_weight={ratio:.2f})...")

model = XGBClassifier(
    n_estimators=200, max_depth=4, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
    scale_pos_weight=ratio, random_state=42, eval_metric="logloss",
)
model.fit(X_train_s, y_train)

# Evaluate
y_pred = model.predict(X_val_s)
y_proba = model.predict_proba(X_val_s)[:, 1]
print(f"\n=== IP-Based CV Results ===")
print(confusion_matrix(y_val, y_pred))
print(classification_report(y_val, y_pred, digits=4))
print(f"Score range: [{y_proba.min():.4f}, {y_proba.max():.4f}]")
if y_val.sum() > 0:
    print(f"Attacker mean: {y_proba[y_val==1].mean():.4f}")
print(f"Benign mean: {y_proba[y_val==0].mean():.4f}")

# Feature importance
FEAT_NAMES = ['syn_count','dst_ips','dst_ports','port_ratio','sps','rate','iat_cv','hshake','rst_ah','bytes']
print(f"\nFeature importance:")
for name, imp in sorted(zip(FEAT_NAMES, model.feature_importances_), key=lambda x: -x[1]):
    print(f"  {name}: {imp:.4f}")

# Save model
model_path = "/home/emirhan/bitirme/models/bruteforce_model.json"
model.save_model(model_path)
print(f"\nModel saved: {model_path}")

# Save scaler params
median = scaler_raw.center_.tolist()
iqr = scaler_raw.scale_.tolist()
scaler_json = {"median": median, "iqr": iqr}
scaler_path = model_path.replace(".json", "_scaler.json")
with open(scaler_path, "w") as f:
    json.dump(scaler_json, f, indent=2)
print(f"Scaler saved: {scaler_path}")

print(f"\nC++ scaler params:")
print(f"  {{ {', '.join(f'{v:.6f}' for v in median)} }},")
print(f"  {{ {', '.join(f'{v:.6f}' for v in iqr)} }}")
