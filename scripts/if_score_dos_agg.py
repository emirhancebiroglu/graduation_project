#!/usr/bin/env python3
"""IsolationForest anomaly scorer for dos_aggregator windows.

Usage (standalone):
    python3 scripts/if_score_dos_agg.py \
        --features 150,2,1,0.5,200,0.013,2.5

Returns JSON: {"if_score": -0.42, "is_anomaly": true, "threshold": -0.5579}
"""
import argparse, json, pickle, sys
from pathlib import Path

import numpy as np

BASE       = Path('/home/emirhan/bitirme')
MODEL_PATH = BASE / 'models' / 'dos_agg_if_anomaly.pkl'
META_PATH  = BASE / 'models' / 'dos_agg_if_anomaly_meta.json'
SCALER_PATH = BASE / 'models' / 'dos_aggregator_model_scaler.json'

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]
N_FEATURES  = 7
LOG1P_COLS  = [0, 1, 2, 6]

_clf = _meta = _scaler = None


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


def preprocess(raw: list) -> np.ndarray:
    _load()
    x = np.array(raw, dtype=np.float64)
    for i in LOG1P_COLS:
        x[i] = np.log1p(max(x[i], 0.0))
    median  = np.array(_scaler['median'])
    iqr     = np.array(_scaler['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return ((x - median) / iqr_safe).reshape(1, -1)


def score(raw_features: list) -> dict:
    """Score a single dos_aggregator window.

    Args:
        raw_features: 7 raw feature values in FEATURE_NAMES order.

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
                        help='Comma-separated 7 raw feature values: ' + ','.join(FEATURE_NAMES))
    args = parser.parse_args()
    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)
    print(json.dumps(score(raw)))


if __name__ == '__main__':
    main()
