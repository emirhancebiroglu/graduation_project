#!/usr/bin/env python3
"""evaluate dos_model.json against UNSW-NB15 test set (X_test.npy / y_test.npy)

X_test.npy is ALREADY preprocessed (log1p + RobustScaler) by prepare_dataset.py.
We evaluate in 3 modes:
  A) Direct: no additional preprocessing (X_test already preprocessed)
  B) C++ scaler: use hardcoded C++ scaler (for production-match check)
  C) scaler.pkl: load the actual scaler used by training pipeline

Usage:
    python scripts/eval_dos_model_unsw.py
"""
import numpy as np
import xgboost as xgb
import json, logging, pickle
from pathlib import Path
from sklearn.metrics import precision_recall_fscore_support

BASE = Path("/home/emirhan/bitirme")
MODEL_PATH = BASE / "models" / "dos_model.json"
X_TEST = BASE / "data" / "processed" / "X_test.npy"
Y_TEST = BASE / "data" / "processed" / "y_test.npy"
SCALER_PKL = BASE / "models" / "scaler.pkl"

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Hardcoded scaler from dos_inspector.cc lines 44-48
# These are the C++ production scaler params
CPP_MEDIAN = np.array([0.0157, 2.5649, 2.5649, 7.2937, 7.5071,
                        73.0, 89.0, 255.0, 255.0, 0.3841, 0.3472])
CPP_IQR = np.array([0.1935, 2.7081, 2.6626, 2.7623, 4.4214,
                    72.0, 496.0, 255.0, 255.0, 2.1158, 1.9696])
LOG1P_FEATS = {0, 1, 2, 3, 4, 9, 10}  # same as flow_tracker.h

THRESHOLD = 0.90

def evaluate(X, y, model, label, threshold=THRESHOLD):
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= threshold).astype(np.int32)

    tp = int(np.sum((y_pred == 1) & (y == 1)))
    tn = int(np.sum((y_pred == 0) & (y == 0)))
    fp = int(np.sum((y_pred == 1) & (y == 0)))
    fn = int(np.sum((y_pred == 0) & (y == 1)))

    total = len(y)
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"  {label:<14}  TP={tp:>7,}  FP={fp:>7,}  FN={fn:>7,}  "
          f"Rec={rec:.4f}  Prec={prec:.4f}  F1={f1:.4f}  FPR={fpr:.4f}")
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4)}


def main():
    logging.info(f"Loading model: {MODEL_PATH}")
    model = xgb.XGBClassifier()
    model.load_model(str(MODEL_PATH))
    n_trees = len(model.get_booster().get_dump())
    logging.info(f"Model loaded: {n_trees} trees")

    logging.info(f"Loading test data: {X_TEST}")
    X_raw = np.load(str(X_TEST)).astype(np.float64)  # already log1p + RobustScaler
    y = np.load(str(Y_TEST)).astype(np.int32)
    logging.info(f"X shape: {X_raw.shape}, attack_rate: {y.mean():.4f}")

    print()
    print("=" * 70)
    print(f"dos_model.json — UNSW-NB15 Generalization Test")
    print(f"  Model: {MODEL_PATH.name} ({n_trees} trees)")
    print(f"  Test:  {X_raw.shape[0]:,} samples ({y.sum():,} attack, {(y==0).sum():,} benign)")
    print(f"  Threshold: {THRESHOLD}")
    print("=" * 70)

    # Mode A: Direct — X_test is already preprocessed
    print()
    print("Mode A — Direct (X_test already preprocessed):")
    res_a = evaluate(X_raw, y, model, "Direct")

    # Mode B: Use C++ hardcoded scaler on RAW UNSW
    # Need raw features for this — we don't have them saved.
    # Instead, we can reverse the scaler.pkl transform then re-apply C++ scaler,
    # but that's error-prone. Let's just note the scaler difference.
    print()
    print("Mode B — C++ hardcoded scaler vs scaler.pkl:")
    if SCALER_PKL.exists():
        with open(SCALER_PKL, "rb") as f:
            scaler = pickle.load(f)
        print(f"  scaler.pkl median: {np.array2string(scaler.center_, precision=4, suppress_small=True)}")
        print(f"  C++ hardcoded   median: {np.array2string(CPP_MEDIAN, precision=4)}")
        print(f"  scaler.pkl iqr:    {np.array2string(scaler.scale_, precision=4, suppress_small=True)}")
        print(f"  C++ hardcoded   iqr:    {np.array2string(CPP_IQR, precision=4)}")
        diff_median = np.max(np.abs(scaler.center_ - CPP_MEDIAN))
        diff_iqr = np.max(np.abs(scaler.scale_ - CPP_IQR))
        print(f"  Max scaler diff — median: {diff_median:.4f}, iqr: {diff_iqr:.4f}")
        if diff_median > 0.01 or diff_iqr > 0.01:
            print(f"  ⚠️  SCALER MISMATCH! C++ scaler differs from training scaler.pkl.")
            print(f"     This means C++ production may produce different scores than Python.")
    else:
        print(f"  scaler.pkl not found — cannot compare")

    # Mode C: Check per-threshold behavior
    print()
    print("Threshold sweep (Direct mode):")
    print(f"  {'thr':>6}  {'TP':>7}  {'FP':>7}  {'FN':>7}  {'Rec':>8}  {'Prec':>8}  {'F1':>8}  {'FPR':>8}")
    print(f"  {'-'*55}")
    y_prob = model.predict_proba(X_raw)[:, 1]
    for thr in [0.01, 0.05, 0.10, 0.20, 0.30, 0.50, 0.70, 0.90, 0.95]:
        yp = (y_prob >= thr).astype(np.int32)
        tp = np.sum((yp == 1) & (y == 1))
        fp = np.sum((yp == 1) & (y == 0))
        fn = np.sum((yp == 0) & (y == 1))
        tn = np.sum((yp == 0) & (y == 0))
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"  {thr:>6.2f}  {tp:>7,}  {fp:>7,}  {fn:>7,}  {rec:>8.4f}  {prec:>8.4f}  {f1:>8.4f}  {fpr:>8.4f}")

    # Save results
    out = {
        "model": "dos_model.json",
        "dataset": "UNSW-NB15 test (X_test.npy, already preprocessed)",
        "threshold": THRESHOLD,
        "n_trees": n_trees,
        "n_samples": int(X_raw.shape[0]),
        "n_attack": int(y.sum()),
        "n_benign": int((y == 0).sum()),
        "direct_mode": res_a,
    }
    out_path = BASE / "results" / "dos_inspector" / "unsw_generalization.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    logging.info(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
