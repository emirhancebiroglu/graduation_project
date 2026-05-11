"""
H4 Step 1 — Cost-sensitive fine-tune sweep.

Variants: scale_pos_weight x {0.5, 0.7} × min_child_weight x {5, 10, 20} = 6 models.
Each fine-tunes from models/fine_tuned_xgb_model.json (v1, 250 trees),
20 rounds, learning_rate=0.05, on the full CIC-IDS2017 training split (same
10% random slice used in the original fine_tune_xgboost.py).

Saves each model to models/fine_tuned_xgb_v2_h4_spw{spw}_mcw{mcw}.json.
Does NOT run Snort — that is handled by fprv2_h4_replay.sh per variant.

Usage:
    python scripts/fprv2_h4_sweep.py
"""

import pickle
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.model_selection import train_test_split

ROOT       = Path(__file__).resolve().parents[1]
CIC_DIR    = ROOT / "data" / "raw" / "cicids2017"
MODELS_DIR = ROOT / "models"
BASE_MODEL = MODELS_DIR / "fine_tuned_xgb_model.json"
SCALER_PKL = MODELS_DIR / "scaler.pkl"

FEATURE_MAP = {
    'Flow Duration': 'dur', 'Total Fwd Packets': 'spkts',
    'Total Backward Packets': 'dpkts', 'Total Length of Fwd Packets': 'sbytes',
    'Total Length of Bwd Packets': 'dbytes', 'Fwd Packet Length Mean': 'smeansz',
    'Bwd Packet Length Mean': 'dmeansz', 'Init_Win_bytes_forward': 'swin',
    'Init_Win_bytes_backward': 'dwin', 'Fwd IAT Mean': 'sintpkt',
    'Bwd IAT Mean': 'dintpkt',
}
FEATURE_ORDER = ['dur','spkts','dpkts','sbytes','dbytes',
                 'smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']
LOG_COLS = ['sbytes','dbytes','spkts','dpkts','dur','sintpkt','dintpkt']

SPW_VALUES = [0.5, 0.7]
MCW_VALUES = [5, 10, 20]

# ── Load and preprocess CIC data (same pipeline as fine_tune_xgboost.py) ─────
print("Loading CIC-IDS2017 CSVs...")
frames = []
for f in sorted(CIC_DIR.glob("*.csv")):
    df = pd.read_csv(f, low_memory=False, on_bad_lines='skip', encoding='latin-1')
    df.columns = df.columns.str.strip()
    frames.append(df)
df = pd.concat(frames, ignore_index=True)
df.columns = df.columns.str.strip()

required = list(FEATURE_MAP.keys()) + ['Label']
df = df[required].copy()
df.rename(columns=FEATURE_MAP, inplace=True)
df['dur']     = df['dur']     / 1e6
df['sintpkt'] = df['sintpkt'] / 1000.0
df['dintpkt'] = df['dintpkt'] / 1000.0
df.replace([float('inf'), float('-inf')], float('nan'), inplace=True)
df.dropna(inplace=True)
df['label'] = df['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
df.drop(columns=['Label'], inplace=True)
for col in LOG_COLS:
    df[col] = np.log1p(df[col])

X = df[FEATURE_ORDER].values
y = df['label'].values

# Same 10% fine-tune split as original script
X_train_ft, _, y_train_ft, _ = train_test_split(
    X, y, test_size=0.90, random_state=42, stratify=y)
print(f"Fine-tune set: {X_train_ft.shape}  pos={y_train_ft.sum():,}  neg={(y_train_ft==0).sum():,}")

with open(SCALER_PKL, "rb") as f:
    scaler = pickle.load(f)
X_scaled = scaler.transform(X_train_ft)

# ── Sweep ─────────────────────────────────────────────────────────────────────
variants = [(spw, mcw) for spw in SPW_VALUES for mcw in MCW_VALUES]
print(f"\nSweep: {len(variants)} variants — spw∈{SPW_VALUES} × mcw∈{MCW_VALUES}\n")

for spw, mcw in variants:
    tag = f"spw{str(spw).replace('.','')}_mcw{mcw}"
    out_path = MODELS_DIR / f"fine_tuned_xgb_v2_h4_{tag}.json"

    print(f"Training spw={spw} mcw={mcw} → {out_path.name}")
    model = xgb.XGBClassifier(
        n_estimators=20,
        learning_rate=0.05,
        scale_pos_weight=spw,
        min_child_weight=mcw,
        random_state=42,
        eval_metric="logloss",
    )
    model.fit(X_scaled, y_train_ft, xgb_model=str(BASE_MODEL))
    model.save_model(str(out_path))
    print(f"  Saved: {out_path.name}")

print("\nAll variants trained. Run fprv2_h4_replay.sh to score each via Snort.")
