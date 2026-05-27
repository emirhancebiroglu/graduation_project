"""SHAP explanation for portscan_inspector (7-feature XGBoost + RobustScaler)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

_BASE = Path(__file__).parent.parent.parent
_MODEL_PATH  = _BASE / "models" / "portscan_aggregator_model_v4e.json"
_SCALER_PATH = _BASE / "models" / "portscan_aggregator_model_v4e_scaler.json"

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "total_syns":        "total SYN packets from source",
    "unique_dst_ports":  "unique destination ports scanned",
    "unique_dst_ips":    "unique destination IPs contacted",
    "dst_port_entropy":  "entropy of destination port distribution",
    "src_port_range":    "source port range spread",
    "unique_port_ratio": "ratio of unique ports to total SYNs",
    "syn_rate":          "SYN packet rate (per second)",
}

FEATURE_NAMES = [
    "total_syns", "unique_dst_ports", "unique_dst_ips",
    "dst_port_entropy", "src_port_range", "unique_port_ratio", "syn_rate",
]

_explainer = None
_scaler = None


def _load():
    global _explainer, _scaler
    if _explainer is not None:
        return
    import xgboost as xgb
    import shap
    model = xgb.Booster()
    model.load_model(str(_MODEL_PATH))
    _explainer = shap.TreeExplainer(model)
    with open(_SCALER_PATH) as f:
        _scaler = json.load(f)


def _scale(raw: list[float]) -> np.ndarray:
    assert _scaler is not None
    x = np.array(raw, dtype=np.float64)
    x = np.log1p(np.maximum(x, 0.0))
    median = np.array(_scaler["median"])
    iqr = np.array(_scaler["iqr"])
    iqr_safe = np.where(iqr == 0, 1.0, iqr)
    return (x - median) / iqr_safe


def explain(raw_features: list[float]) -> list[dict]:
    _load()
    assert _explainer is not None
    import xgboost as xgb
    scaled = _scale(raw_features)
    dmat = xgb.DMatrix(scaled.reshape(1, -1), feature_names=FEATURE_NAMES)
    shap_vals = _explainer.shap_values(dmat)
    contributions = []
    for name, shap_v, raw_v in zip(FEATURE_NAMES, shap_vals[0], raw_features):
        contributions.append({
            "feature": name,
            "description": _FEATURE_DESCRIPTIONS.get(name, name),
            "shap_value": float(shap_v),
            "raw_value": float(raw_v),
            "direction": "attack" if shap_v > 0 else "benign",
        })
    contributions.sort(key=lambda c: abs(c["shap_value"]), reverse=True)
    return contributions[:5]


def shap_to_narrative(contributions: list[dict]) -> str:
    attack_top = [c for c in contributions if c["direction"] == "attack"][:3]
    benign_top = [c for c in contributions if c["direction"] == "benign"][:1]
    parts = []
    for c in attack_top:
        raw = c["raw_value"]
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        parts.append(f"{c['description']}={fmt}")
    if not parts:
        for c in contributions[:2]:
            raw = c["raw_value"]
            fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
            parts.append(f"{c['description']}={fmt}")
    suffix = ""
    if benign_top and attack_top:
        b = benign_top[0]
        raw = b["raw_value"]
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        suffix = f"; low {b['description']} ({fmt}) reduces confidence"
    return "Why flagged: " + ", ".join(parts) + suffix
