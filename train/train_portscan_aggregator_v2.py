#!/usr/bin/env python3
"""
train_portscan_aggregator_v2.py -- Train XGBoost v2 on combined Friday+Wednesday data

Key improvements vs v1:
  - scale_pos_weight: handles class imbalance (~1.2% positive rate)
  - early_stopping_rounds: prevents overfitting on small positive set
  - threshold sweep on val (not test) to pick best threshold
  - Final eval on held-out test set
  - Saves scaler sidecar JSON for C++ plugin auto-loading

Output: models/portscan_aggregator_model_v2.json
"""

import argparse
import json
import logging
import pickle
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.metrics import confusion_matrix, roc_auc_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(f1, 4), 'fpr': round(fpr, 4),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v2'))
    parser.add_argument('--output-model', type=str,
                        default=str(Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model_v2.json'))
    parser.add_argument('--n-estimators', type=int, default=400)
    parser.add_argument('--max-depth', type=int, default=5)
    parser.add_argument('--learning-rate', type=float, default=0.05)
    parser.add_argument('--early-stopping', type=int, default=30)
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_model = Path(args.output_model)

    logging.info(f"Loading data from {data_dir}")
    X_train = np.load(data_dir / 'X_train.npy')
    y_train = np.load(data_dir / 'y_train.npy')
    X_val = np.load(data_dir / 'X_val.npy')
    y_val = np.load(data_dir / 'y_val.npy')
    X_test = np.load(data_dir / 'X_test.npy')
    y_test = np.load(data_dir / 'y_test.npy')

    logging.info(f"Train: {X_train.shape}, pos={y_train.sum()}/{len(y_train)}")
    logging.info(f"Val:   {X_val.shape}, pos={y_val.sum()}/{len(y_val)}")
    logging.info(f"Test:  {X_test.shape}, pos={y_test.sum()}/{len(y_test)}")

    # scale_pos_weight compensates for imbalance: neg/pos ratio
    pos_count = int(y_train.sum())
    neg_count = len(y_train) - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1.0
    logging.info(f"scale_pos_weight = {spw:.2f} (neg={neg_count}, pos={pos_count})")

    model = xgb.XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        scale_pos_weight=spw,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        reg_lambda=1.0,
        reg_alpha=0.1,
        objective='binary:logistic',
        tree_method='hist',
        eval_metric='aucpr',
        early_stopping_rounds=args.early_stopping,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    try:
        logging.info(f"Best iteration: {model.best_iteration}")
    except AttributeError:
        pass

    # Threshold sweep on VAL set to find best operating point
    val_proba = model.predict_proba(X_val)[:, 1]
    try:
        val_auc = roc_auc_score(y_val, val_proba)
        logging.info(f"Val AUCPR: {val_auc:.4f}")
    except Exception:
        pass

    best_f1_val = 0.0
    best_t_val = 0.40
    print("\nThreshold sweep on VAL set:")
    for t in [x / 100 for x in range(5, 96, 5)]:
        y_pred = (val_proba >= t).astype(int)
        m = compute_metrics(y_val, y_pred)
        if m['tp'] + m['fn'] > 0:
            print(f"  t={t:.2f}  Rec={m['recall']:.3f}  Prec={m['precision']:.3f}  F1={m['f1']:.3f}  FP={m['fp']}")
        if m['f1'] > best_f1_val:
            best_f1_val = m['f1']
            best_t_val = t

    logging.info(f"Best threshold by F1 on val: {best_t_val:.2f} (F1={best_f1_val:.4f})")

    # Final eval on held-out TEST set
    test_proba = model.predict_proba(X_test)[:, 1]
    y_pred_test = (test_proba >= best_t_val).astype(int)
    metrics = compute_metrics(y_test, y_pred_test)

    print("\n" + "=" * 55)
    print("PORTSCAN MODEL V2 -- TEST SET RESULTS")
    print(f"Threshold (from val sweep): {best_t_val:.2f}")
    print(f"TP: {metrics['tp']}  FP: {metrics['fp']}  TN: {metrics['tn']}  FN: {metrics['fn']}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"FPR:       {metrics['fpr']:.4f}")
    print("=" * 55)

    model.save_model(str(output_model))
    logging.info(f"Model saved: {output_model}")

    # Load scaler and save sidecar JSON for C++ plugin
    with open(data_dir / 'scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    sidecar = {
        'median': [round(v, 10) for v in scaler.center_.tolist()],
        'iqr': [round(v, 10) for v in scaler.scale_.tolist()],
    }
    sidecar_path = output_model.with_name(output_model.stem + '_scaler.json')
    with open(sidecar_path, 'w') as f:
        json.dump(sidecar, f, indent=2)
    logging.info(f"Scaler sidecar saved: {sidecar_path}")

    print("\nScaler params for C++ hardcoded fallback:")
    print(f"median = {sidecar['median']}")
    print(f"iqr    = {sidecar['iqr']}")

    # Save results
    results_dir = Path.home() / 'bitirme' / 'results' / 'portscan_v2'
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / 'test_metrics.json', 'w') as f:
        json.dump({
            'threshold': best_t_val,
            'metrics': metrics,
            'scale_pos_weight': spw,
        }, f, indent=2)
    logging.info(f"Results saved: {results_dir}/test_metrics.json")


if __name__ == '__main__':
    main()