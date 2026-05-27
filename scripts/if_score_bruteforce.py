#!/usr/bin/env python3
"""IsolationForest anomaly scorer for bruteforce_inspector windows.

Preprocessing: log1p(all 10 features) then RobustScaler — matches C++ bruteforce_flow_tracker.h.

Usage (standalone):
    python3 scripts/if_score_bruteforce.py \
        --features 5,1,2,0.5,0.4,0.3,1.5,0.8,0.1,100

Returns JSON: {"if_score": -0.55, "is_anomaly": true, "threshold": -0.5xyz}
"""
import argparse, json, pickle, sys
from pathlib import Path

import numpy as np

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'bruteforce_if_anomaly.pkl'
META_PATH   = BASE / 'models' / 'bruteforce_if_anomaly_meta.json'
SCALER_PATH = BASE / 'models' / 'bruteforce_model_v3_scaler.json'

# Order matches C++ bfc_train_data.txt header:
# lb syn_cnt dst_ips dst_ports port_ratio sps rate iat_cv hshake rst_ah bytes
FEATURE_NAMES = [
    'syn_count', 'dst_ips', 'dst_ports', 'port_ratio',
    'single_port_score', 'rate', 'iat_cv',
    'handshake_ratio', 'rst_after_handshake', 'bytes_per_syn',
]
N_FEATURES = 10

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
    x = np.log1p(np.maximum(x, 0.0))
    median   = np.array(_scaler['median'])
    iqr      = np.array(_scaler['iqr'])
    iqr_safe = np.where(iqr != 0, iqr, 1.0)
    return ((x - median) / iqr_safe).reshape(1, -1)


def score(raw_features: list) -> dict:
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
                        help='Comma-separated 10 raw feature values: ' + ','.join(FEATURE_NAMES))
    args = parser.parse_args()
    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)
    print(json.dumps(score(raw)))


if __name__ == '__main__':
    main()
