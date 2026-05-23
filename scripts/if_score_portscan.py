#!/usr/bin/env python3
"""IsolationForest anomaly scorer for portscan_inspector windows.

Preprocessing: log1p(all 7 features) then RobustScaler (portscan_aggregator_model_v4d_scaler.json).
This matches the C++ portscan_flow_tracker.h preprocess() exactly.

Usage (standalone):
    python3 scripts/if_score_portscan.py \
        --features 997,997,1,9.96,200,1.0,16.6

Returns JSON: {"if_score": -0.65, "is_anomaly": true, "threshold": -0.6213}
"""
import argparse, json, pickle, sys
from pathlib import Path

import numpy as np

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'portscan_if_anomaly.pkl'
META_PATH   = BASE / 'models' / 'portscan_if_anomaly_meta.json'
SCALER_PATH = BASE / 'models' / 'portscan_aggregator_model_v4d_scaler.json'

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]
N_FEATURES = 7

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
    """log1p(all 7) then RobustScaler — matches C++ portscan_flow_tracker.h."""
    _load()
    x = np.array(raw, dtype=np.float64)
    x = np.log1p(np.maximum(x, 0.0))
    median   = np.array(_scaler['median'])
    iqr      = np.array(_scaler['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return ((x - median) / iqr_safe).reshape(1, -1)


def score(raw_features: list) -> dict:
    """Score a single portscan window.

    Args:
        raw_features: 7 raw (unscaled) feature values in FEATURE_NAMES order.

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
