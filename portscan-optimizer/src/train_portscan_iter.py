#!/usr/bin/env python3
"""
train_portscan_iter.py — PortScan specialist training script
Called by executor each iteration with different hyperparams/strategies.

Usage:
    python src/train_portscan_iter.py \
        --iteration 0 \
        --threshold 0.50 \
        --n-estimators 200 \
        --max-depth 6 \
        --learning-rate 0.1 \
        --scale-pos-weight 1.0 \
        --use-smote false \
        --add-wednesday-samples false \
        --output-model ~/bitirme/models/portscan_model.json \
        --output-scaler ~/bitirme/models/portscan_scaler.pkl

Outputs:
    - models/portscan_model.json         (XGBoost model for Snort plugin)
    - models/portscan_scaler.pkl         (scaler for reference)
    - results/portscan/scaler_params.json (median/IQR for C++ patching)
    - results/portscan/offline_metrics.json (offline train/test metrics)
"""

import argparse
import json
import logging
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ROOT = Path(__file__).resolve().parents[1]

# Feature mapping: CICIDS column name → UNSW/plugin feature name
FEATURE_MAPPING = {
    'Flow Duration':              'dur',
    'Total Fwd Packets':          'spkts',
    'Total Backward Packets':     'dpkts',
    'Total Length of Fwd Packets':'sbytes',
    'Total Length of Bwd Packets':'dbytes',
    'Fwd Packet Length Mean':     'smeansz',
    'Bwd Packet Length Mean':     'dmeansz',
    'Init_Win_bytes_forward':     'swin',
    'Init_Win_bytes_backward':    'dwin',
    'Fwd IAT Mean':               'sintpkt',
    'Bwd IAT Mean':               'dintpkt',
}

FEATURE_ORDER = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
                 'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt']

LOG_COLS = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'sintpkt', 'dintpkt']

# Unit conversion: CICIDS → UNSW units (same as fine_tune_xgboost.py)
UNIT_CONVERSIONS = {
    'dur':     1e-6,    # microseconds → seconds
    'sintpkt': 1e-3,    # microseconds → milliseconds
    'dintpkt': 1e-3,
}


def load_friday_csv(csv_dir: Path) -> pd.DataFrame:
    friday_files = [
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    ]
    dfs = []
    for fname in friday_files:
        fpath = csv_dir / fname
        if not fpath.exists():
            logging.warning(f"Not found, skipping: {fpath}")
            continue
        logging.info(f"Loading {fname}...")
        df = pd.read_csv(fpath, low_memory=False, on_bad_lines='skip')
        df.columns = df.columns.str.strip()
        df['Label'] = df['Label'].str.strip()
        dfs.append(df)
    combined = pd.concat(dfs, ignore_index=True)
    logging.info(f"Friday combined: {combined.shape}, labels: {combined['Label'].value_counts().to_dict()}")
    return combined


def load_wednesday_csv(csv_dir: Path) -> pd.DataFrame:
    fpath = csv_dir / 'Wednesday-workingHours.pcap_ISCX.csv'
    if not fpath.exists():
        logging.warning(f"Wednesday CSV not found: {fpath}")
        return pd.DataFrame()
    df = pd.read_csv(fpath, low_memory=False, on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    df['Label'] = df['Label'].str.strip()
    logging.info(f"Wednesday loaded: {df.shape}, labels: {df['Label'].value_counts().to_dict()}")
    return df


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    required = list(FEATURE_MAPPING.keys()) + ['Label']
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    out = df[required].copy()
    out.rename(columns=FEATURE_MAPPING, inplace=True)

    # Unit conversions
    for col, factor in UNIT_CONVERSIONS.items():
        out[col] = out[col] * factor

    # Clean
    out.replace([np.inf, -np.inf], np.nan, inplace=True)
    out.dropna(inplace=True)

    return out


def apply_log1p(df: pd.DataFrame) -> pd.DataFrame:
    for col in LOG_COLS:
        if col in df.columns:
            df[col] = np.log1p(df[col].clip(lower=0))
    return df


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    TN, FP, FN, TP = cm.ravel()
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0
    return {
        'TP': int(TP), 'FP': int(FP), 'TN': int(TN), 'FN': int(FN),
        'precision': round(precision, 4),
        'recall':    round(recall, 4),
        'f1':        round(f1, 4),
        'fpr':       round(fpr, 4),
        'confusion_matrix': [[int(TN), int(FP)], [int(FN), int(TP)]],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iteration',           type=int,   default=0)
    parser.add_argument('--threshold',           type=float, default=0.50)
    parser.add_argument('--n-estimators',        type=int,   default=200)
    parser.add_argument('--max-depth',           type=int,   default=6)
    parser.add_argument('--learning-rate',       type=float, default=0.1)
    parser.add_argument('--scale-pos-weight',    type=float, default=1.0)
    parser.add_argument('--use-smote',           type=str,   default='false')
    parser.add_argument('--add-wednesday',       type=str,   default='false')
    parser.add_argument('--wednesday-sample-frac', type=float, default=0.3)
    parser.add_argument('--finetune-from',       type=str,   default=None,
                        help='Path to base model JSON for fine-tuning (transfer learning)')
    parser.add_argument('--csv-dir',             type=str,
                        default=str(ROOT.parent / 'data' / 'raw' / 'cicids2017'))
    parser.add_argument('--output-model',        type=str,
                        default=str(ROOT.parent / 'models' / 'portscan_model.json'))
    parser.add_argument('--output-scaler',       type=str,
                        default=str(ROOT.parent / 'models' / 'portscan_scaler.pkl'))
    parser.add_argument('--results-dir',         type=str,
                        default=str(ROOT.parent / 'results' / 'portscan'))
    args = parser.parse_args()

    use_smote     = args.use_smote.lower() == 'true'
    add_wednesday = args.add_wednesday.lower() == 'true'

    csv_dir     = Path(args.csv_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    Path(args.output_model).parent.mkdir(parents=True, exist_ok=True)

    logging.info(f"=== PortScan Training Iteration {args.iteration} ===")
    logging.info(f"Params: threshold={args.threshold}, n_estimators={args.n_estimators}, "
                 f"max_depth={args.max_depth}, lr={args.learning_rate}, "
                 f"scale_pos_weight={args.scale_pos_weight}, "
                 f"smote={use_smote}, add_wednesday={add_wednesday}")

    # ── Load Friday data ──────────────────────────────────────────
    friday_raw = load_friday_csv(csv_dir)
    friday_df  = prepare_features(friday_raw)
    friday_df  = apply_log1p(friday_df)

    # Label: PortScan=1, everything else=0
    friday_df['label'] = (friday_df['Label'] == 'PortScan').astype(int)
    friday_df.drop(columns=['Label'], inplace=True)

    # Optionally add Wednesday DoS samples as extra negatives
    if add_wednesday:
        wed_raw = load_wednesday_csv(csv_dir)
        if not wed_raw.empty:
            wed_df = prepare_features(wed_raw)
            wed_df = apply_log1p(wed_df)
            wed_df['label'] = 0  # All Wednesday = negative for PortScan model
            wed_df.drop(columns=['Label'], inplace=True)
            # Sample fraction to avoid overwhelming Friday data
            n_sample = int(len(wed_df) * args.wednesday_sample_frac)
            wed_sample = wed_df.sample(n=min(n_sample, len(wed_df)), random_state=42)
            friday_df = pd.concat([friday_df, wed_sample], ignore_index=True)
            logging.info(f"Added {len(wed_sample)} Wednesday samples. Total: {len(friday_df)}")

    X = friday_df[FEATURE_ORDER].values
    y = friday_df['label'].values

    logging.info(f"Dataset: {X.shape}, positives: {y.sum()}, negatives: {(y==0).sum()}")

    # ── Locked test split ─────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logging.info(f"Train: {X_train.shape}, Test: {X_test.shape}")

    # ── Scale ────────────────────────────────────────────────────
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # Save scaler
    with open(args.output_scaler, 'wb') as f:
        pickle.dump(scaler, f)

    # Extract median/IQR for C++ patch
    median_vals = scaler.center_.tolist()
    iqr_vals    = scaler.scale_.tolist()

    scaler_params = {
        'median': median_vals,
        'iqr':    iqr_vals,
        'feature_order': FEATURE_ORDER,
    }
    scaler_json_path = results_dir / 'scaler_params.json'
    with open(scaler_json_path, 'w') as f:
        json.dump(scaler_params, f, indent=2)
    logging.info(f"Scaler params saved: {scaler_json_path}")
    logging.info(f"Median: {[round(v,6) for v in median_vals]}")
    logging.info(f"IQR:    {[round(v,6) for v in iqr_vals]}")

    # ── Optional SMOTE ───────────────────────────────────────────
    if use_smote:
        try:
            from imblearn.over_sampling import SMOTE
            sm = SMOTE(random_state=42)
            X_train_scaled, y_train = sm.fit_resample(X_train_scaled, y_train)
            logging.info(f"After SMOTE: {X_train_scaled.shape}, positives: {y_train.sum()}")
        except ImportError:
            logging.warning("imbalanced-learn not installed, skipping SMOTE")

    # ── Train ────────────────────────────────────────────────────
    model_kwargs = dict(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        scale_pos_weight=args.scale_pos_weight,
        objective='binary:logistic',
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )

    model = xgb.XGBClassifier(**model_kwargs)

    if args.finetune_from and Path(args.finetune_from).exists():
        logging.info(f"Fine-tuning from: {args.finetune_from}")
        model.fit(X_train_scaled, y_train,
                  xgb_model=args.finetune_from,
                  eval_set=[(X_test_scaled, y_test)],
                  verbose=False)
    else:
        model.fit(X_train_scaled, y_train,
                  eval_set=[(X_test_scaled, y_test)],
                  verbose=False)

    # ── Threshold search on validation set ───────────────────────
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    # Try the requested threshold first
    y_pred = (y_proba >= args.threshold).astype(int)
    metrics = compute_metrics(y_test, y_pred)
    metrics['threshold_used'] = args.threshold

    # Also find optimal threshold (maximize F1 on test)
    best_f1 = 0
    best_thresh = args.threshold
    for t in np.arange(0.1, 0.95, 0.05):
        y_t = (y_proba >= t).astype(int)
        m   = compute_metrics(y_test, y_t)
        if m['f1'] > best_f1:
            best_f1    = m['f1']
            best_thresh = t
    logging.info(f"Best threshold by F1 on test set: {best_thresh:.2f} (F1={best_f1:.4f})")

    # Save model
    model.save_model(args.output_model)
    logging.info(f"Model saved: {args.output_model}")

    # Save offline metrics
    metrics['iteration']    = args.iteration
    metrics['best_offline_threshold'] = round(float(best_thresh), 2)
    metrics['model_path']   = args.output_model
    metrics['scaler_path']  = args.output_scaler

    offline_path = results_dir / 'offline_metrics.json'
    with open(offline_path, 'w') as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "="*55)
    print(f"OFFLINE METRICS (threshold={args.threshold})")
    print(json.dumps(metrics, indent=2))
    print("="*55)
    print(f"\nBest offline threshold by F1: {best_thresh:.2f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"FPR:       {metrics['fpr']:.4f}")
    print(f"\nScaler median: {[round(v,6) for v in median_vals]}")
    print(f"Scaler IQR:    {[round(v,6) for v in iqr_vals]}")
    print("\nOFFLINE TRAINING COMPLETE — run patch_and_build.sh next")


if __name__ == "__main__":
    main()