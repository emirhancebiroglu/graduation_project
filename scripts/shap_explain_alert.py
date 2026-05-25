#!/usr/bin/env python3
"""SHAP post-hoc explainer for dos_inspector alerts.

Loads dos_model.json (v1 production) and computes top-5 SHAP feature contributions
for a single alert's feature vector.

Usage (standalone):
    python3 scripts/shap_explain_alert.py \
        --features 0.0,2.0,0.0,116.0,0.0,58.0,0.0,0.0,0.0,0.0479,0.0

Returns JSON list of {feature, value, shap_value, direction} sorted by |shap_value| desc.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import xgboost as xgb

BASE       = Path('/home/emirhan/bitirme')
MODEL_PATH = BASE / 'models' / 'dos_fpr_opt_v3b.json'
SCALER_PATH = BASE / 'models' / 'dos_fpr_opt_v3b_scaler.json'

# v3b feature schema (15 features, swin/dwin removed)
FEATURE_NAMES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'smeansz', 'dmeansz',
    'sintpkt', 'dintpkt',
    'fwd_pkt_mean', 'bwd_pkt_mean',
    'fin_cnt', 'ack_cnt', 'syn_cnt', 'bwd_iat'
]
# Scaler params loaded from JSON at runtime (set in _load)
_SCALER: dict | None = None

_model     = None
_explainer = None


def _load():
    global _model, _explainer, _SCALER
    if _model is None:
        import json
        import shap
        _model = xgb.XGBClassifier()
        _model.load_model(str(MODEL_PATH))
        _explainer = shap.TreeExplainer(_model)
        with open(SCALER_PATH) as f:
            _SCALER = json.load(f)


def preprocess(raw: list[float]) -> np.ndarray:
    _load()
    x = np.array(raw, dtype=np.float64)
    log_idx = set(_SCALER['log1p_indices'])
    for i in range(len(x)):
        if i in log_idx:
            x[i] = np.log1p(max(x[i], 0.0))
    median = np.array(_SCALER['median'])
    iqr    = np.array(_SCALER['iqr'])
    x = (x - median) / np.where(iqr != 0, iqr, 1.0)
    return x.reshape(1, -1)


_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "dur":          "flow duration",
    "spkts":        "source packet count",
    "dpkts":        "destination packet count",
    "sbytes":       "source bytes",
    "dbytes":       "destination bytes",
    "smeansz":      "mean source packet size",
    "dmeansz":      "mean destination packet size",
    "sintpkt":      "mean inter-packet time (src)",
    "dintpkt":      "mean inter-packet time (dst)",
    "fwd_pkt_mean": "forward packet mean size",
    "bwd_pkt_mean": "backward packet mean size",
    "fin_cnt":      "FIN flag count",
    "ack_cnt":      "ACK flag count",
    "syn_cnt":      "SYN flag count",
    "bwd_iat":      "backward inter-arrival time",
}


def explain(raw_features: list[float], top_n: int = 5) -> list[dict]:
    """Compute SHAP contributions for a single flow.

    Args:
        raw_features: 15 raw (unscaled) feature values (v3b schema).
        top_n: number of top contributions to return.

    Returns:
        List of dicts sorted by abs(shap_value) descending.
    """
    _load()
    X = preprocess(raw_features)
    sv = _explainer.shap_values(X)[0]  # shape (15,)

    contributions = []
    for i, (fname, raw_val, sv_val) in enumerate(zip(FEATURE_NAMES, raw_features, sv)):
        contributions.append({
            'feature':     fname,
            'description': _FEATURE_DESCRIPTIONS.get(fname, fname),
            'raw_value':   round(float(raw_val), 6),
            'shap_value':  round(float(sv_val), 6),
            'direction':   'attack' if sv_val > 0 else 'benign',
        })

    contributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)
    return contributions[:top_n]


def shap_to_narrative(contributions: list[dict]) -> str:
    """Convert top SHAP contributions to plain-text 'Why flagged:' string."""
    attack_top = [c for c in contributions if c['direction'] == 'attack'][:3]
    benign_top = [c for c in contributions if c['direction'] == 'benign'][:1]

    parts = []
    for c in attack_top:
        raw = c['raw_value']
        name = c['description']
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        parts.append(f"{name}={fmt}")

    if not parts:
        for c in contributions[:2]:
            raw = c['raw_value']
            name = c['description']
            fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
            parts.append(f"{name}={fmt}")

    suffix = ""
    if benign_top and attack_top:
        b = benign_top[0]
        raw = b['raw_value']
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        suffix = f"; low {b['description']} ({fmt}) reduces confidence"

    return "Why flagged: " + ", ".join(parts) + suffix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--features', required=True,
                        help='Comma-separated 11 raw feature values')
    parser.add_argument('--top', type=int, default=5)
    args = parser.parse_args()

    raw = [float(v) for v in args.features.split(',')]
    if len(raw) != 15:
        print(json.dumps({'error': f'Expected 15 features, got {len(raw)}'}))
        sys.exit(1)

    result = explain(raw, top_n=args.top)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
