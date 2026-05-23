#!/usr/bin/env python3
"""Train XGBoost on C++ plugin training data dump (perfect feature match)."""
import logging, json, pickle, sys
from pathlib import Path
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

FEATURE_NAMES = ['total_syns', 'unique_dst_ports', 'unique_dst_ips',
                 'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate']

def load_dump(path):
    data = np.loadtxt(path, comments='#')
    y = data[:, 0].astype(int)
    X_raw = data[:, 1:-1]  # exclude score
    scores = data[:, -1]
    return X_raw, y, scores

def main():
    data, y, scores = load_dump('/tmp/portscan_train_data.txt')
    logging.info(f"Loaded {len(data)} samples ({y.sum()} scanner, {(1-y).sum()} benign)")

    X = data.astype(np.float64)
    log1p_cols = ['total_syns', 'unique_dst_ports', 'unique_dst_ips', 'syn_rate']
    for i, name in enumerate(FEATURE_NAMES):
        if name in log1p_cols:
            X[:, i] = np.log1p(X[:, i])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logging.info(f"Train: {X_train_s.shape}, pos={y_train.sum()}/{len(y_train)}")
    logging.info(f"Test:  {X_test_s.shape}, pos={y_test.sum()}/{len(y_test)}")

    model = xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                              objective='binary:logistic', tree_method='hist',
                              random_state=42, n_jobs=-1)
    model.fit(X_train_s, y_train, eval_set=[(X_test_s, y_test)], verbose=50)

    proba = model.predict_proba(X_test_s)[:, 1]

    best_f1, best_t = 0, 0.5
    for t in [x/100 for x in range(5, 96, 5)]:
        y_p = (proba >= t).astype(int)
        tn = ((y_test == 0) & (y_p == 0)).sum()
        fp = ((y_test == 0) & (y_p == 1)).sum()
        fn = ((y_test == 1) & (y_p == 0)).sum()
        tp = ((y_test == 1) & (y_p == 1)).sum()
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0
        rec = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1 = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
        print(f"  t={t:.2f}: TP={tp} FP={fp} FN={fn} TN={tn}  Prec={prec:.3f} Rec={rec:.3f} F1={f1:.3f}")
        if f1 > best_f1:
            best_f1, best_t = f1, t

    y_p = (proba >= best_t).astype(int)
    tp = ((y_test == 1) & (y_p == 1)).sum()
    fn = ((y_test == 1) & (y_p == 0)).sum()
    fp = ((y_test == 0) & (y_p == 1)).sum()
    tn = ((y_test == 0) & (y_p == 0)).sum()
    print(f"\nBest t={best_t:.2f}: TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Recall={tp/(tp+fn):.4f}  Precision={tp/(tp+fp):.4f}  FPR={fp/(fp+tn):.4f}")

    model.save_model(str(Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model.json'))
    scaler_params = {
        'median': [round(v, 10) for v in scaler.center_.tolist()],
        'iqr': [round(v, 10) for v in scaler.scale_.tolist()],
    }
    with open(Path.home() / 'bitirme' / 'models' / 'aggregator_scaler_params.json', 'w') as f:
        json.dump(scaler_params, f, indent=2)
    print(f"\nScaler median: {[round(v,10) for v in scaler.center_.tolist()]}")
    print(f"Scaler iqr:    {[round(v,10) for v in scaler.scale_.tolist()]}")

if __name__ == '__main__':
    main()
