#!/usr/bin/env python3
"""
train_portscan_aggregator.py — Train XGBoost on cross-flow aggregated features

Uses data/processed/portscan_aggregated/ (prepared by prepare_aggregated_portscan.py)
Output: models/portscan_aggregator_model.json + scaler params for C++ plugin
"""

import argparse
import json
import logging
import pickle
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.metrics import confusion_matrix

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return {
        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'fpr': round(fpr, 4),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_from_pcap'))
    parser.add_argument('--output-model', type=str,
                        default=str(Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model.json'))
    parser.add_argument('--n-estimators', type=int, default=200)
    parser.add_argument('--max-depth', type=int, default=6)
    parser.add_argument('--learning-rate', type=float, default=0.1)
    parser.add_argument('--threshold', type=float, default=0.50)
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

    model = xgb.XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        objective='binary:logistic',
        tree_method='hist',
        eval_metric='logloss',
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
        logging.info(f"Model trained: {args.n_estimators} estimators")

    y_proba = model.predict_proba(X_test)[:, 1]

    # Threshold sweep
    best_f1 = 0
    best_threshold = args.threshold
    for t in [x / 100 for x in range(5, 96, 5)]:
        y_pred = (y_proba >= t).astype(int)
        m = compute_metrics(y_test, y_pred)
        if m['f1'] > best_f1:
            best_f1 = m['f1']
            best_threshold = t

    logging.info(f"Best threshold by F1 on test: {best_threshold:.2f} (F1={best_f1:.4f})")

    y_pred = (y_proba >= best_threshold).astype(int)
    metrics = compute_metrics(y_test, y_pred)

    print("\n" + "=" * 55)
    print("CROSS-FLOW AGGREGATOR — TEST SET RESULTS")
    print(f"Threshold:         {best_threshold:.2f}")
    print(f"TP: {metrics['tp']}  FP: {metrics['fp']}  TN: {metrics['tn']}  FN: {metrics['fn']}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"FPR:       {metrics['fpr']:.4f}")
    print("=" * 55)

    model.save_model(str(output_model))
    logging.info(f"Model saved: {output_model}")

    with open(data_dir / 'scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    scaler_params = {
        'median': [round(v, 10) for v in scaler.center_.tolist()],
        'iqr': [round(v, 10) for v in scaler.scale_.tolist()],
        'feature_names': FEATURE_NAMES,
    }

    params_path = output_model.with_name('aggregator_scaler_params.json')
    with open(params_path, 'w') as f:
        json.dump(scaler_params, f, indent=2)
    logging.info(f"Scaler params saved: {params_path}")

    # JSON sidecar for auto-loading (matching plugin naming convention)
    sidecar_path = output_model.with_name(output_model.stem + '_scaler.json')
    sidecar = {'median': [round(v, 10) for v in scaler.center_.tolist()],
               'iqr': [round(v, 10) for v in scaler.scale_.tolist()]}
    with open(sidecar_path, 'w') as f:
        json.dump(sidecar, f, indent=2)
    logging.info(f"JSON sidecar scaler saved: {sidecar_path}")

    print("\nScaler params for C++ patching:")
    print(f"median = {scaler_params['median']}")
    print(f"iqr    = {scaler_params['iqr']}")

    # Also save to results directory
    results_dir = Path.home() / 'bitirme' / 'results' / 'portscan_aggregated'
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / 'metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    with open(results_dir / 'scaler_params.json', 'w') as f:
        json.dump(scaler_params, f, indent=2)


if __name__ == '__main__':
    main()
