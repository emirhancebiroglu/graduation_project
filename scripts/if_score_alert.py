#!/usr/bin/env python3
"""IsolationForest anomaly scorer for dos_inspector alerts (v3b schema, 15 features).

Usage (standalone):
    python3 scripts/if_score_alert.py \
        --features 0.015,2.5,1.1,7.3,7.5,73,89,0.38,0.35,58,0,0,2,1,0.0

Returns JSON: {"if_score": -0.42, "is_anomaly": true, "threshold": -0.5951}
"""
import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'dos_if_anomaly_v3b.pkl'
META_PATH   = BASE / 'models' / 'dos_if_anomaly_v3b_meta.json'
SCALER_PATH = BASE / 'models' / 'dos_fpr_opt_v3b_scaler.json'

FEATURE_NAMES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'smeansz', 'dmeansz',
    'sintpkt', 'dintpkt', 'fwd_pkt_mean', 'bwd_pkt_mean',
    'fin_cnt', 'ack_cnt', 'syn_cnt', 'bwd_iat',
]
N_FEATURES = 15

_clf    = None
_meta   = None
_scaler = None


def _load():
    global _clf, _meta, _scaler
    if _clf is None:
        with open(MODEL_PATH, 'rb') as f:
            _clf = pickle.load(f)
    if _meta is None:
        with open(META_PATH) as f:
            _meta = json.load(f)
    if _scaler is None:
        with open(SCALER_PATH) as f:
            _scaler = json.load(f)


def preprocess(raw_features: list[float]) -> np.ndarray:
    """Apply v3b log1p + RobustScaler preprocessing."""
    _load()
    x = np.array(raw_features, dtype=np.float64)
    median     = np.array(_scaler['median'])
    iqr        = np.array(_scaler['iqr'])
    log1p_idx  = set(_scaler['log1p_indices'])
    for i in log1p_idx:
        x[i] = np.log1p(max(x[i], 0.0))
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return ((x - median) / iqr_safe).reshape(1, -1)


def score(raw_features: list[float]) -> dict:
    """Score a single flow feature vector.

    Args:
        raw_features: 15 raw (unscaled) feature values in v3b FEATURE_NAMES order.

    Returns:
        dict with if_score, is_anomaly, threshold, label.
    """
    _load()
    if len(raw_features) != N_FEATURES:
        return {'error': f'Expected {N_FEATURES} features, got {len(raw_features)}'}
    threshold = _meta['threshold_p5']
    X = preprocess(raw_features)
    if_score = float(_clf.score_samples(X)[0])
    is_anomaly = if_score < threshold
    return {
        'if_score':   round(if_score, 6),
        'is_anomaly': is_anomaly,
        'threshold':  round(threshold, 6),
        'label':      'anomaly_candidate' if is_anomaly else 'known_pattern',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--features', required=True,
                        help='Comma-separated 15 raw feature values: ' + ','.join(FEATURE_NAMES))
    args = parser.parse_args()

    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)

    result = score(raw)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
