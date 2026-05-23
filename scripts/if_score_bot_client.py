#!/usr/bin/env python3
"""IsolationForest anomaly scorer for bot_client_inspector windows.

Preprocessing: raw RobustScaler (no log1p) — matches C++ bot_client_inspector.cc preprocess().

Usage (standalone):
    python3 scripts/if_score_bot_client.py \
        --features 5,1,1,3.2,0,0.2,0.0167,1.0,0.2,0.0,0.0,1.0,1.0,0,0,0,0,1.0,0,0,0,8192

Returns JSON: {"if_score": -0.55, "is_anomaly": true, "threshold": -0.5477}
"""
import argparse, json, pickle, sys
from pathlib import Path

import numpy as np

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'bot_client_if_anomaly.pkl'
META_PATH   = BASE / 'models' / 'bot_client_if_anomaly_meta.json'
SCALER_PATH = BASE / 'models' / 'bot_client_model_scaler.json'

FEATURE_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'iat_cv', 'port_entropy', 'port_ratio', 'rate',
    'ip_concentration', 'dst_ip_ratio', 'ip_entropy',
    'iat_q90_q10_ratio', 'time_density', 'port_to_ip_ratio',
    'handshake_ratio', 'incoming_ratio', 'data_density', 'rst_rate',
    'internal_ip_ratio', 'bytes_per_syn', 'fin_ratio', 'push_ratio', 'mean_window',
]
N_FEATURES = 22

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
    """Raw RobustScaler — no log1p, matches C++ preprocess()."""
    _load()
    x = np.array(raw, dtype=np.float64)
    median   = np.array(_scaler['median'])
    iqr      = np.array(_scaler['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return ((x - median) / iqr_safe).reshape(1, -1)


def score(raw_features: list) -> dict:
    """Score a single bot_client window.

    Args:
        raw_features: 22 raw feature values in FEATURE_NAMES order.

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
                        help='Comma-separated 22 raw feature values: ' + ','.join(FEATURE_NAMES))
    args = parser.parse_args()
    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)
    print(json.dumps(score(raw)))


if __name__ == '__main__':
    main()
