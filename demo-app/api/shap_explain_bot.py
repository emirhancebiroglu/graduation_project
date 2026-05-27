"""SHAP explanation for bot_client_inspector (22-feature XGBoost, raw features — no scaling)."""
from __future__ import annotations

from pathlib import Path

import numpy as np

_BASE = Path(__file__).parent.parent.parent
_MODEL_PATH = _BASE / "models" / "bot_client_v4.json"

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "syn_count":           "total SYN packets sent",
    "dst_ips":             "unique destination IPs",
    "dst_ports":           "unique destination ports",
    "iat_cv":              "inter-arrival time coefficient of variation",
    "port_entropy":        "entropy of destination port distribution",
    "port_ratio":          "unique port to SYN ratio",
    "rate":                "SYN rate (per second)",
    "ip_concentration":    "IP concentration (Herfindahl index)",
    "dst_ip_ratio":        "destination IP diversity ratio",
    "ip_entropy":          "entropy of destination IP distribution",
    "iat_q90_q10_ratio":   "inter-arrival time Q90/Q10 ratio",
    "time_density":        "connection time density",
    "port_to_ip_ratio":    "port to IP ratio",
    "handshake_ratio":     "completed handshake ratio",
    "incoming_ratio":      "incoming to total packet ratio",
    "data_density":        "data packet density",
    "rst_rate":            "RST packet rate",
    "internal_ip_ratio":   "internal destination IP ratio",
    "bytes_per_syn":       "incoming bytes per SYN",
    "fin_ratio":           "FIN packet ratio",
    "push_ratio":          "PUSH flag ratio",
    "mean_window":         "mean TCP window size",
}

FEATURE_NAMES = [
    "syn_count", "dst_ips", "dst_ports", "iat_cv", "port_entropy", "port_ratio", "rate",
    "ip_concentration", "dst_ip_ratio", "ip_entropy",
    "iat_q90_q10_ratio", "time_density", "port_to_ip_ratio",
    "handshake_ratio", "incoming_ratio", "data_density", "rst_rate",
    "internal_ip_ratio", "bytes_per_syn", "fin_ratio", "push_ratio", "mean_window",
]

_explainer = None


def _load():
    global _explainer
    if _explainer is not None:
        return
    import xgboost as xgb
    import shap
    model = xgb.Booster()
    model.load_model(str(_MODEL_PATH))
    _explainer = shap.TreeExplainer(model)


def explain(raw_features: list[float]) -> list[dict]:
    _load()
    assert _explainer is not None
    import xgboost as xgb
    # bot_client_v4 was trained on raw (unscaled) features — feed directly, no scaling
    arr = np.array(raw_features, dtype=np.float32)
    dmat = xgb.DMatrix(arr.reshape(1, -1), feature_names=FEATURE_NAMES)
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
