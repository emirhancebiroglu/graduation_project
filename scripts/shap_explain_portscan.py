#!/usr/bin/env python3
"""SHAP post-hoc explainer for portscan_inspector alerts.

Uses portscan_aggregator_model_v4d.json (7-feature XGBoost).
Preprocessing: log1p(all 7) then RobustScaler (portscan_aggregator_model_v4d_scaler.json).

Usage:
    python3 scripts/shap_explain_portscan.py \
        --features 997,997,1,9.96,200,1.0,16.6

Returns JSON list of {feature, raw_value, shap_value, direction} sorted by |shap_value| desc.
"""
import argparse, json, sys
from pathlib import Path

import numpy as np
import xgboost as xgb

BASE        = Path('/home/emirhan/bitirme')
MODEL_PATH  = BASE / 'models' / 'portscan_aggregator_model_v4d.json'
SCALER_PATH = BASE / 'models' / 'portscan_aggregator_model_v4d_scaler.json'

FEATURE_NAMES = [
    'total_syns', 'unique_dst_ports', 'unique_dst_ips',
    'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate',
]
N_FEATURES = 7

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
    median  = np.array(_scaler['median'])
    iqr     = np.array(_scaler['iqr'])
    x = (x - median) / np.where(iqr != 0, iqr, 1.0)
    return x.reshape(1, -1)


def explain(raw_features: list, top_n: int = 5) -> list:
    """Compute SHAP contributions for a single portscan window.

    Args:
        raw_features: 7 raw (unscaled) feature values.
        top_n: number of top contributions to return.

    Returns:
        List of dicts sorted by abs(shap_value) descending.
    """
    _load()
    X = preprocess(raw_features)
    sv = _explainer.shap_values(X)[0]  # shape (7,)

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
                        help='Comma-separated 7 raw feature values: ' + ','.join(FEATURE_NAMES))
    parser.add_argument('--top', type=int, default=5)
    args = parser.parse_args()
    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != N_FEATURES:
        print(json.dumps({'error': f'Expected {N_FEATURES} features, got {len(raw)}'}))
        sys.exit(1)
    print(json.dumps(explain(raw, top_n=args.top), indent=2))


if __name__ == '__main__':
    main()
