"""
Iteration 0 - Baseline
XGBoost default params, Friday-only, binary PortScan vs rest
"""
import pandas as pd
import numpy as np
import json
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier

# ── Load data ──────────────────────────────────────────────────────────────
df = pd.read_csv('data/friday_portscan.csv')
df.columns = df.columns.str.strip()
df['Label'] = df['Label'].str.strip()

drop_cols = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']
df = df.drop(columns=[c for c in drop_cols if c in df.columns])

# Binary label
df['Label'] = (df['Label'] == 'PortScan').astype(int)

# Clean infinities and NaNs
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['Label'].value_counts()}")

# ── Locked test split ──────────────────────────────────────────────────────
X = df.drop('Label', axis=1)
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")
print(f"Train positives: {y_train.sum()}, Test positives: {y_test.sum()}")

# ── Train ──────────────────────────────────────────────────────────────────
model = XGBClassifier(
    n_estimators=100,
    random_state=42,
    eval_metric='logloss',
    use_label_encoder=False,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Evaluate ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)

cm = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()

recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0

result = {
    "iteration": 0,
    "recall": round(recall, 4),
    "precision": round(precision, 4),
    "f1": round(f1, 4),
    "fpr": round(fpr, 4),
    "TP": int(TP), "FP": int(FP), "TN": int(TN), "FN": int(FN),
    "confusion_matrix": [[int(TN), int(FP)], [int(FN), int(TP)]],
    "change_made": "Baseline: XGBoost default, Friday-only, binary",
    "model_path": "models/model_iter_0.pkl"
}

# ── Save model ─────────────────────────────────────────────────────────────
import os
os.makedirs('models', exist_ok=True)
os.makedirs('results', exist_ok=True)
joblib.dump(model, result["model_path"])

# ── Write metrics ──────────────────────────────────────────────────────────
with open('results/metrics.json', 'w') as f:
    json.dump(result, f, indent=2)

with open('results/history.jsonl', 'a') as f:
    f.write(json.dumps(result) + '\n')

print("\n" + "="*50)
print(json.dumps(result, indent=2))
print("="*50)
print(f"\nRecall:    {recall:.4f}  (target >=0.99)  {'✓' if recall >= 0.99 else '✗'}")
print(f"Precision: {precision:.4f}  (target >=0.98)  {'✓' if precision >= 0.98 else '✗'}")
print(f"F1:        {f1:.4f}  (target >=0.98)  {'✓' if f1 >= 0.98 else '✗'}")
print(f"FPR:       {fpr:.4f}  (target <=0.01)  {'✓' if fpr <= 0.01 else '✗'}")
print("\nMETRICS WRITTEN TO results/metrics.json")