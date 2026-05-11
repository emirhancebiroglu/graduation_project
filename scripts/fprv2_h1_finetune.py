"""
H1 Step 2 — Fine-tune + UNSW sanity check.

Loads cohort built by fprv2_h1_build_cohort.py, scales with production scaler,
fine-tunes from production model with 20 rounds at lr=0.05, then immediately
runs UNSW sanity check. Stops and reports if UNSW Recall < 0.95.

Output: models/fine_tuned_xgb_v2_h1_w3.json
"""

import pickle
import sys
import numpy as np
import xgboost as xgb
from pathlib import Path
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
COHORT_DIR  = ROOT / "results" / "xgboost" / "fpr-v2" / "H1"
MODELS_DIR  = ROOT / "models"
DATA_DIR    = ROOT / "data" / "processed"

PROD_MODEL  = MODELS_DIR / "fine_tuned_xgb_model.json"
SCALER_PKL  = MODELS_DIR / "scaler.pkl"
OUT_MODEL   = MODELS_DIR / "fine_tuned_xgb_v2_h1_w3.json"

UNSW_RECALL_FLOOR = 0.95   # hard stop if below this

# ── load cohort ───────────────────────────────────────────────────────────────
print("Loading cohort...")
X = np.load(COHORT_DIR / "cohort_X.npy")   # already log1p'd
y = np.load(COHORT_DIR / "cohort_y.npy")
w = np.load(COHORT_DIR / "cohort_w.npy")
print(f"  X: {X.shape}  label=0: {(y==0).sum():,}  label=1: {(y==1).sum():,}")
print(f"  weight=3.0: {(w==3.0).sum():,}  weight=1.0: {(w==1.0).sum():,}")

# ── scale with production scaler ─────────────────────────────────────────────
print("\nApplying production RobustScaler...")
with open(SCALER_PKL, "rb") as f:
    scaler = pickle.load(f)
X_scaled = scaler.transform(X)

# ── fine-tune ─────────────────────────────────────────────────────────────────
print(f"\nFine-tuning from {PROD_MODEL.name}")
print(f"  n_estimators=20  learning_rate=0.05  sample_weight=3.0/1.0")

model = xgb.XGBClassifier(
    n_estimators=20,
    learning_rate=0.05,
    random_state=42,
    eval_metric="logloss",
)
model.fit(X_scaled, y, sample_weight=w, xgb_model=str(PROD_MODEL))

model.save_model(str(OUT_MODEL))
print(f"  Saved: {OUT_MODEL.name}")

# ── UNSW sanity check ─────────────────────────────────────────────────────────
print("\n" + "=" * 55)
print("UNSW SANITY CHECK")
print("=" * 55)

X_unsw = np.load(DATA_DIR / "X_test.npy")
y_unsw = np.load(DATA_DIR / "y_test.npy")
print(f"UNSW test set: {X_unsw.shape}  positives: {y_unsw.sum():,}")

# UNSW processed data was scaled with the same scaler during training
# X_test.npy is already scaled — do NOT re-scale
y_pred = model.predict(X_unsw)

cm = confusion_matrix(y_unsw, y_pred)
tn, fp, fn, tp = cm.ravel()

recall    = tp / (tp + fn)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
fpr_unsw  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

print(f"\nConfusion matrix:")
print(f"  TN={tn:,}  FP={fp:,}")
print(f"  FN={fn:,}  TP={tp:,}")
print(f"\nRecall    = {recall:.4f}")
print(f"Precision = {precision:.4f}")
print(f"FPR       = {fpr_unsw:.4f}")
print(f"F1        = {f1:.4f}")

if recall < UNSW_RECALL_FLOOR:
    print(f"\n*** STOP: UNSW Recall {recall:.4f} < floor {UNSW_RECALL_FLOOR} ***")
    print("    Model integrity compromised. Do NOT proceed to Wednesday replay.")
    print("    Investigate cohort composition before retrying.")
    sys.exit(1)

print(f"\nUNSW sanity PASSED (Recall={recall:.4f} >= {UNSW_RECALL_FLOOR})")
print("=== STEP 2 COMPLETE — awaiting approval before Wednesday replay ===")
