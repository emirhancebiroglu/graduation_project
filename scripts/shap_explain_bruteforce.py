#!/usr/bin/env python3
"""SHAP post-hoc explainer for bruteforce_inspector alerts.

Uses bruteforce_model.json (10-feature XGBoost) + bruteforce_model_scaler.json.
Preprocessing: log1p(all 10), then RobustScaler.

Usage:
    python3 scripts/shap_explain_bruteforce.py \
        --features 150,5,3,0.6,0.8,0.5,1.2,0.7,0.1,64.0

Returns JSON list of {feature, raw_value, shap_value, direction} sorted by |shap_value| desc.
"""
import argparse, json, sys
from pathlib import Path

import numpy as np
import xgboost as xgb

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'bruteforce_model.json'
SCALER_PATH = BASE / 'models' / 'bruteforce_model_scaler.json'

FEATURE_NAMES = [
    'syn_count', 'syn_dst_ips', 'syn_dst_ports',
    'port_ratio', 'single_port_score', 'syn_rate',
    'iat_cv', 'hshake_ratio', 'rst_after_hshake', 'bytes_per_syn',
]
N_FEATURES = 10

_model = _explainer = _scaler = None


def _load():
    global _model, _explainer, _scaler
    if _model is None:
        import shap
        _model = xgb.XGBClassifier()
        _model.load_model(str(MODEL_PATH))
        _explainer = shap.TreeExplainer(_model)
        with open(SCALER_PATH) as f:
            _scaler = json.load(f)


def preprocess(raw: list) -> np.ndarray:
    _load()
    x = np.array(raw, dtype=np.float64)
    x = np.log1p(np.maximum(x, 0.0))
    median = np.array(_scaler['median'])
    iqr    = np.array(_scaler['iqr'])
    x = (x - median) / np.where(iqr != 0, iqr, 1.0)
    return x.reshape(1, -1)


def explain(raw_features: list, top_n: int = 5) -> list:
    """Compute SHAP contributions for a single bruteforce window.

    Args:
        raw_features: 10 raw (unscaled) feature values.
        top_n: number of top contributions to return.

    Returns:
        List of dicts sorted by abs(shap_value) descending.
    """
    _load()
    X = preprocess(raw_features)
    sv = _explainer.shap_values(X)[0]  # shape (10,)

    contributions = []
    for fname, raw_val, sv_val in zip(FEATURE_NAMES, raw_features, sv):
        contributions.append({
            'feature':    fname,
            'raw_value':  round(float(raw_val), 6),
            'shap_value': round(float(sv_val), 6),
            'direction':  'attack' if sv_val > 0 else 'benign',
        })
    contributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)
    return contributions[:top_n]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--features', required=True,
                        help='Comma-separated 10 raw feature values: ' + ','.join(FEATURE_NAMES))
    parser.add_argument('--top', type=int, default=5)
    args = parser.parse_args()
    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)
    print(json.dumps(explain(raw, top_n=args.top), indent=2))


if __name__ == '__main__':
    main()
