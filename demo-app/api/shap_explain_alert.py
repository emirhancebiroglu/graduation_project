"""SHAP explanation for dos_inspector v3b (15-feature RobustScaler + XGBoost)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

_BASE = Path(__file__).parent.parent.parent  # ~/bitirme
_MODEL_PATH = _BASE / "models" / "dos_fpr_opt_v3b.json"
_SCALER_PATH = _BASE / "models" / "dos_fpr_opt_v3b_scaler.json"

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

_explainer = None
_scaler: dict[str, Any] | None = None
_feature_names: list[str] | None = None


def _load() -> None:
    global _explainer, _scaler, _feature_names
    if _explainer is not None:
        return

    import xgboost as xgb
    import shap

    model = xgb.Booster()
    model.load_model(str(_MODEL_PATH))
    _explainer = shap.TreeExplainer(model)

    with open(_SCALER_PATH) as f:
        _scaler = json.load(f)
    _feature_names = _scaler["feature_names"]


def _scale(raw: list[float]) -> np.ndarray:
    assert _scaler is not None
    x = np.array(raw, dtype=np.float64)
    log1p_idx = _scaler["log1p_indices"]
    x[log1p_idx] = np.log1p(x[log1p_idx])
    median = np.array(_scaler["median"])
    iqr = np.array(_scaler["iqr"])
    iqr_safe = np.where(iqr == 0, 1.0, iqr)
    return (x - median) / iqr_safe


def explain(raw_features: list[float]) -> list[dict]:
    """Return top-5 SHAP contributions sorted by |value| descending."""
    _load()
    assert _feature_names is not None and _explainer is not None

    import xgboost as xgb

    scaled = _scale(raw_features)
    dmat = xgb.DMatrix(scaled.reshape(1, -1), feature_names=_feature_names)
    shap_vals = _explainer.shap_values(dmat)

    contributions = []
    for i, (name, shap_v, raw_v) in enumerate(
        zip(_feature_names, shap_vals[0], raw_features)
    ):
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
    """Convert top SHAP contributions to plain-text 'Why flagged:' string."""
    attack_top = [c for c in contributions if c["direction"] == "attack"][:3]
    benign_top = [c for c in contributions if c["direction"] == "benign"][:2]

    parts = []
    for c in attack_top:
        raw = c["raw_value"]
        name = c["description"]
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        parts.append(f"{name}={fmt}")

    if not parts:
        # fallback: top-2 by absolute shap regardless of direction
        for c in contributions[:2]:
            raw = c["raw_value"]
            name = c["description"]
            fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
            parts.append(f"{name}={fmt}")

    suffix = ""
    if benign_top and attack_top:
        b = benign_top[0]
        raw = b["raw_value"]
        fmt = str(int(raw)) if raw == int(raw) and abs(raw) < 1e6 else f"{raw:.3g}"
        suffix = f"; low {b['description']} ({fmt}) reduces confidence"

    return "Why flagged: " + ", ".join(parts) + suffix
