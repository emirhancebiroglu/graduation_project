#!/usr/bin/env python3
"""
train_dos_specialist.py — XGBoost DoS Specialist Eğitimi

BİTİRME PROJESİ — DoS Pilot (Phase 2)
=====================================
Hedef:
  - 4 max_packets varyantı için ayrı XGBoost modeli eğit
  - Her biri için threshold sweep yap
  - Optuna ile hyperparameter optimization
  - Best modeli kaydet (.json + .ubj for treelite)

Kullanım:
  cd ~/bitirme
  python train/train_dos_specialist.py \\
      --data-dir   data/processed/dos_specialist \\
      --output-dir models/dos_specialist \\
      --variants   mp_2 mp_4 mp_8 full \\
      --n-trials   50

Çıktı:
  models/dos_specialist/
    ├── mp_2_xgb_model.json
    ├── mp_2_xgb_model.ubj          # universal binary, treelite uyumlu
    ├── mp_2_threshold_sweep.csv
    ├── mp_2_metrics.json
    ├── ... (her varyant için)
    └── comparison_report.md
"""

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────────
# Hyperparameter optimization (Optuna ile, opsiyonel)
# ───────────────────────────────────────────────────────────────
def objective_optuna(trial, X_train, y_train, X_val, y_val):
    """Optuna trial — bir hyperparameter seti için val F1 dön."""
    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "tree_method": "hist",
        "max_depth":         trial.suggest_int("max_depth", 4, 10),
        "learning_rate":     trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
        "n_estimators":      trial.suggest_int("n_estimators", 100, 500),
        "subsample":         trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree":  trial.suggest_float("colsample_bytree", 0.6, 1.0),
        "min_child_weight":  trial.suggest_int("min_child_weight", 1, 10),
        "gamma":             trial.suggest_float("gamma", 0.0, 0.5),
        "reg_alpha":         trial.suggest_float("reg_alpha", 0.0, 1.0),
        "reg_lambda":        trial.suggest_float("reg_lambda", 0.5, 2.0),
        # Class imbalance: scale_pos_weight = neg/pos
        "scale_pos_weight":  (y_train == 0).sum() / max((y_train == 1).sum(), 1),
        "random_state":      42,
        "n_jobs":            -1,
    }

    model = xgb.XGBClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    y_val_pred = model.predict(X_val)
    return f1_score(y_val, y_val_pred)


def train_with_optuna(X_train, y_train, X_val, y_val, n_trials=50):
    """Optuna ile en iyi hyperparametreleri bul."""
    try:
        import optuna
    except ImportError:
        log.warning("Optuna kurulu değil, default params kullanılıyor.")
        log.warning("Kurmak için: pip install optuna")
        return None

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    study = optuna.create_study(direction="maximize",
                                study_name="dos_specialist_xgb")
    study.optimize(
        lambda t: objective_optuna(t, X_train, y_train, X_val, y_val),
        n_trials=n_trials,
        show_progress_bar=True,
    )

    log.info("Best F1 (val): %.4f", study.best_value)
    log.info("Best params:")
    for k, v in study.best_params.items():
        log.info("  %s = %s", k, v)
    return study.best_params


# ───────────────────────────────────────────────────────────────
# Default hyperparametreler (Optuna yoksa veya hızlı test için)
# ───────────────────────────────────────────────────────────────
DEFAULT_PARAMS = {
    "objective":        "binary:logistic",
    "eval_metric":      "logloss",
    "tree_method":      "hist",
    "max_depth":        7,
    "learning_rate":    0.05,
    "n_estimators":     300,
    "subsample":        0.85,
    "colsample_bytree": 0.85,
    "min_child_weight": 3,
    "gamma":            0.1,
    "reg_alpha":        0.1,
    "reg_lambda":       1.0,
    "random_state":     42,
    "n_jobs":           -1,
}


# ───────────────────────────────────────────────────────────────
# Threshold sweep
# ───────────────────────────────────────────────────────────────
def threshold_sweep(model, X, y, thresholds=None) -> pd.DataFrame:
    """Belirtilen thresholdlar için confusion matrix + metrikler hesapla."""
    if thresholds is None:
        thresholds = np.arange(0.30, 0.96, 0.05)

    proba = model.predict_proba(X)[:, 1]

    rows = []
    for thr in thresholds:
        pred = (proba >= thr).astype(int)
        cm = confusion_matrix(y, pred, labels=[0, 1])
        tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1  = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        rows.append({
            "threshold": thr,
            "tp": int(tp),
            "fp": int(fp),
            "fn": int(fn),
            "tn": int(tn),
            "precision": prec,
            "recall":    rec,
            "f1":        f1,
            "fpr":       fpr,
        })

    return pd.DataFrame(rows)


# ───────────────────────────────────────────────────────────────
# Tek varyant pipeline
# ───────────────────────────────────────────────────────────────
def train_variant(variant_name: str,
                  data_dir: Path,
                  output_dir: Path,
                  use_optuna: bool,
                  n_trials: int) -> dict:
    """Bir max_packets varyantı için tam eğitim pipeline'ı."""
    log.info("=" * 70)
    log.info("VARYANT: %s", variant_name)
    log.info("=" * 70)

    var_dir = data_dir / variant_name
    if not var_dir.exists():
        log.error("Veri yok: %s", var_dir)
        return {}

    X_train = np.load(var_dir / "X_train.npy")
    y_train = np.load(var_dir / "y_train.npy")
    X_val   = np.load(var_dir / "X_val.npy")
    y_val   = np.load(var_dir / "y_val.npy")
    X_test  = np.load(var_dir / "X_test.npy")
    y_test  = np.load(var_dir / "y_test.npy")

    log.info("Train: %s, Val: %s, Test: %s",
             X_train.shape, X_val.shape, X_test.shape)

    # Hyperparameter
    if use_optuna:
        log.info("Optuna ile hyperparameter search (%d trial)...", n_trials)
        best_params = train_with_optuna(X_train, y_train, X_val, y_val, n_trials)
        if best_params is None:
            params = DEFAULT_PARAMS.copy()
        else:
            params = {**DEFAULT_PARAMS, **best_params}
    else:
        params = DEFAULT_PARAMS.copy()

    # Class imbalance
    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    params["scale_pos_weight"] = n_neg / max(n_pos, 1)
    log.info("scale_pos_weight = %.3f (n_pos=%d, n_neg=%d)",
             params["scale_pos_weight"], n_pos, n_neg)

    # Final eğitim — train + val birleşik (production-style)
    # Önce train ile eğit, val ile early stopping
    log.info("Final model eğitiliyor...")
    model = xgb.XGBClassifier(**params, early_stopping_rounds=20)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    log.info("Best iteration: %d", model.best_iteration)

    # ───── Threshold sweep (val seti üzerinde) ─────
    log.info("Threshold sweep (val seti)...")
    sweep_df = threshold_sweep(model, X_val, y_val)
    log.info("\n%s", sweep_df.to_string(index=False, float_format="%.4f"))

    # En iyi F1 threshold'unu seç
    best_idx = sweep_df["f1"].idxmax()
    best_threshold = float(sweep_df.loc[best_idx, "threshold"])
    log.info("Optimal threshold (val F1 max): %.2f", best_threshold)

    # ───── Test seti final değerlendirmesi ─────
    log.info("Test seti değerlendirmesi (threshold=%.2f)...", best_threshold)
    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred  = (test_proba >= best_threshold).astype(int)

    cm = confusion_matrix(y_test, test_pred, labels=[0, 1])
    tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]

    test_metrics = {
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "accuracy":  float((tp + tn) / (tp + tn + fp + fn)),
        "precision": float(precision_score(y_test, test_pred, zero_division=0)),
        "recall":    float(recall_score(y_test, test_pred, zero_division=0)),
        "f1":        float(f1_score(y_test, test_pred, zero_division=0)),
        "fpr":       float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "auc_roc":   float(roc_auc_score(y_test, test_proba)),
        "threshold": best_threshold,
    }

    log.info("─" * 50)
    log.info("TEST SET METRİKLER (variant=%s)", variant_name)
    log.info("─" * 50)
    for k, v in test_metrics.items():
        if isinstance(v, float):
            log.info("  %-12s %.4f", k, v)
        else:
            log.info("  %-12s %s", k, v)

    # ───── Pilot başarı kontrolü ─────
    success = (
        test_metrics["f1"] >= 0.97
        and test_metrics["fpr"] <= 0.005
        and test_metrics["recall"] >= 0.92
    )
    log.info("PİLOT BAŞARI (offline): %s", "✅ EVET" if success else "❌ HAYIR")

    # ───── Modeli kaydet ─────
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"{variant_name}_xgb_model.json"
    ubj_path  = output_dir / f"{variant_name}_xgb_model.ubj"
    sweep_path = output_dir / f"{variant_name}_threshold_sweep.csv"
    metrics_path = output_dir / f"{variant_name}_metrics.json"

    model.save_model(str(json_path))
    model.save_model(str(ubj_path))   # treelite uyumlu binary
    sweep_df.to_csv(sweep_path, index=False)

    full_metrics = {
        "variant":   variant_name,
        "test":      test_metrics,
        "params":    params,
        "best_iteration": int(model.best_iteration) if model.best_iteration else None,
        "pilot_success_offline": bool(success),
    }
    with open(metrics_path, "w") as f:
        json.dump(full_metrics, f, indent=2, default=str)

    log.info("Kaydedildi: %s", output_dir)
    return full_metrics


# ───────────────────────────────────────────────────────────────
# Karşılaştırma raporu
# ───────────────────────────────────────────────────────────────
def write_comparison_report(all_results: dict, output_dir: Path):
    """Tüm varyantların özet karşılaştırma raporu."""
    lines = [
        "# DoS Specialist — Varyant Karşılaştırma Raporu",
        "",
        "## Test Set Sonuçları (Threshold = optimal F1)",
        "",
        "| Varyant | Threshold | Precision | Recall | F1 | FPR | AUC-ROC | Pilot? |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for variant, result in all_results.items():
        if not result:
            continue
        m = result["test"]
        success = "✅" if result["pilot_success_offline"] else "❌"
        lines.append(
            f"| {variant} | {m['threshold']:.2f} | "
            f"{m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['fpr']:.4f} | {m['auc_roc']:.4f} | {success} |"
        )

    lines += [
        "",
        "## Pilot Başarı Kriteri (Offline)",
        "- F1 ≥ 0.97",
        "- Recall ≥ 0.92",
        "- FPR ≤ 0.005",
        "",
        "## Sonraki Adım",
        "1. En iyi varyantı seç (önerimi: F1 + recall en yüksek olan)",
        "2. Bu varyantı Snort3 plugin'ine entegre et: `plugins/dos_specialist/`",
        "3. PCAP replay → real-time confusion matrix",
    ]

    report_path = output_dir / "comparison_report.md"
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    log.info("Karşılaştırma raporu: %s", report_path)


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DoS Specialist (XGBoost) eğitimi")
    parser.add_argument("--data-dir",   type=Path, required=True,
                        help="data/processed/dos_specialist")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="models/dos_specialist")
    parser.add_argument("--variants", nargs="+",
                        default=["mp_2", "mp_4", "mp_8", "full"],
                        help="Eğitilecek varyantlar")
    parser.add_argument("--no-optuna", action="store_true",
                        help="Hyperparameter search yapma, default params kullan")
    parser.add_argument("--n-trials", type=int, default=50)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    all_results = {}
    for variant in args.variants:
        result = train_variant(
            variant_name=variant,
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            use_optuna=not args.no_optuna,
            n_trials=args.n_trials,
        )
        all_results[variant] = result

    write_comparison_report(all_results, args.output_dir)
    log.info("\n✅ TAMAMLANDI: %s", args.output_dir)


if __name__ == "__main__":
    main()