#!/usr/bin/env python3
"""
train_portscan_aggregator_v4e.py
Fixes cold-start and single-port flood detection.

Changes vs v4d:
  - Remove uports>=100 constraint from synthetic scanners
  - Add "single-port flood scanner" type (uports=1, high syn_cnt, medium spr)
  - Add Pattern C negatives: few uports but very wide spr (SSH/HTTPS multi-connect)
  - Use real CIC Friday windows (1934 samples from Snort dump) as anchor data
  - Output: portscan_aggregator_model_v4e.json
"""
import json, logging, pickle
from math import log2
from pathlib import Path

import numpy as np
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score
import xgboost as xgb

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FEATURE_NAMES = ['total_syns', 'unique_dst_ports', 'unique_dst_ips',
                 'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate']
V4D_DATA  = Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v4d'
OUT_DATA  = Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v4e'
OUT_MODEL = Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model_v4e.json'
CIC_REAL  = Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_cic_friday_real_windows.txt'

N_SYNTH_POS         = 300
N_SYNTH_NEG_A       = 300  # few-ports high-syn (v4d baseline)
N_SYNTH_NEG_C       = 200  # few-ports wide-spr ephemeral (new: SSH/web multi-connect)
N_SYNTH_NEG_D       = 150  # lateral movement: sequential small spr (new)
RANDOM_SEED         = 42


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    pr  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1  = 2 * pr * rec / (pr + rec) if (pr + rec) > 0 else 0.0
    return {'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
            'precision': round(pr, 4), 'recall': round(rec, 4), 'f1': round(f1, 4)}


def generate_synthetic_scanners(n, rng):
    """Multi-type scanners including single-port flood."""
    rows = []
    scan_types = ['slow', 'medium', 'fast', 'flood', 'single_port_flood']
    probs = [0.20, 0.20, 0.20, 0.15, 0.25]  # 25% single-port flood
    for _ in range(n):
        scan_type = rng.choice(scan_types, p=probs)
        if scan_type == 'slow':
            uports = rng.integers(100, 1500)
            syn_cnt = rng.integers(uports, max(uports + 1, int(uports * 1.5)))
        elif scan_type == 'medium':
            uports = rng.integers(200, 3000)
            syn_cnt = rng.integers(uports, max(uports + 1, uports * 5))
        elif scan_type == 'fast':
            uports = rng.integers(500, 10000)
            syn_cnt = rng.integers(uports, max(uports + 1, uports * 10))
        elif scan_type == 'flood':
            # High-volume flood with many ports (Cupid-like)
            uports = rng.integers(100, 5000)
            syn_cnt = rng.integers(uports * 10, max(uports * 11, uports * 200))
        else:
            # Single-port SYN flood (CIC DoS final phase):
            # high syn_cnt (hundreds to thousands), uports=1, wide ephemeral spr
            uports = 1
            syn_cnt = int(rng.integers(500, 8000))   # high volume
            sp_range = float(rng.integers(20000, 62000))  # wide ephemeral
            pratio = 1.0 / syn_cnt
            srate = syn_cnt / 60.0
            uips = 1
            entropy = 0.0
            rows.append([float(syn_cnt), float(uports), float(uips),
                         entropy, sp_range, pratio, srate])
            continue

        uips = rng.integers(1, 4)
        max_entropy = log2(uports) if uports > 1 else 1.0
        entropy = rng.uniform(max(5.0, max_entropy * 0.6), min(max_entropy, 16.0))
        sp_range = float(rng.integers(200, 30000))
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     float(entropy), sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def generate_pattern_a_negatives(n, rng):
    """Pattern A: high syn_cnt, few dst ports (v4d baseline)."""
    rows = []
    for _ in range(n):
        syn_cnt = rng.integers(5, 1500)
        uports = rng.integers(1, min(25, max(2, int(syn_cnt * 0.15) + 1)))
        uips = rng.integers(1, 15)
        entropy = rng.uniform(0.0, min(3.0, log2(uports) + 0.3) if uports > 1 else 0.1)
        if rng.random() < 0.5:
            sp_range = float(rng.integers(max(1, syn_cnt - 100), syn_cnt + 200))
        else:
            sp_range = float(rng.integers(10000, 60000))
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     entropy, sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def generate_pattern_c_negatives(n, rng):
    """Pattern C: few dst ports, wide spr, LOW syn_cnt (ephemeral port clients).
    E.g., SSH/HTTPS client connecting to same server with random ephemeral src ports.
    Key distinguisher from scanner SYN flood: syn_cnt << 200 (not high-volume).
    """
    rows = []
    for _ in range(n):
        uports = rng.integers(1, 15)
        syn_cnt = rng.integers(5, 80)   # low volume — not a flood
        uips = rng.integers(1, 5)
        entropy = rng.uniform(0.0, min(3.0, log2(uports) + 0.3) if uports > 1 else 0.1)
        sp_range = float(rng.integers(8000, 63000))  # wide ephemeral
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     entropy, sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def generate_pattern_d_negatives(n, rng):
    """Pattern D: lateral movement — sequential small spr.
    Few ports, few unique IPs, small src_port_range (NOT ephemeral randomization).
    E.g., admin script connecting to multiple hosts on port 445.
    """
    rows = []
    for _ in range(n):
        uports = rng.integers(1, 15)
        syn_cnt = rng.integers(5, 300)
        uips = rng.integers(2, 20)  # multiple dest IPs (lateral)
        entropy = rng.uniform(0.0, min(3.0, log2(uports) + 0.3) if uports > 1 else 0.1)
        sp_range = float(rng.integers(1, min(500, syn_cnt + 50)))  # small range
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     entropy, sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def load_real_cic_windows(path):
    """Load real CIC Friday windows from Snort dump."""
    rows_pos, rows_neg = [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            label = int(parts[0])
            features = list(map(float, parts[1:8]))
            if label == 1:
                rows_pos.append(features)
            else:
                rows_neg.append(features)
    X_pos = np.array(rows_pos, dtype=np.float64) if rows_pos else np.empty((0, 7))
    X_neg = np.array(rows_neg, dtype=np.float64) if rows_neg else np.empty((0, 7))
    return X_pos, X_neg


def main():
    OUT_DATA.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(RANDOM_SEED)

    # 1. Load v4d base data (inverse-transform back to log1p space)
    logging.info("Loading v4d data...")
    with open(V4D_DATA / 'scaler.pkl', 'rb') as f:
        sc_v4d = pickle.load(f)
    Xtr = np.load(V4D_DATA / 'X_train.npy')
    ytr = np.load(V4D_DATA / 'y_train.npy')
    Xva = np.load(V4D_DATA / 'X_val.npy')
    yva = np.load(V4D_DATA / 'y_val.npy')
    Xte = np.load(V4D_DATA / 'X_test.npy')
    yte = np.load(V4D_DATA / 'y_test.npy')
    X_all_v4d = np.vstack([Xtr, Xva, Xte])
    y_all_v4d = np.concatenate([ytr, yva, yte])
    X_log1p_v3 = sc_v4d.inverse_transform(X_all_v4d)  # back to log1p space
    y_all_v3 = y_all_v4d
    logging.info(f"v4d: {len(y_all_v3)} windows, pos={y_all_v3.sum()}")

    # 2. Load real CIC windows
    logging.info("Loading real CIC Friday windows...")
    if CIC_REAL.exists():
        X_cic_pos, X_cic_neg = load_real_cic_windows(CIC_REAL)
        logging.info(f"CIC real: pos={len(X_cic_pos)}, neg_sample={min(len(X_cic_neg), 200)}")
        # Use all real positives, sample 200 real negatives
        X_cic_neg_sample = X_cic_neg[rng.choice(len(X_cic_neg), min(200, len(X_cic_neg)), replace=False)]
        y_cic_pos = np.ones(len(X_cic_pos), dtype=np.int64)
        y_cic_neg = np.zeros(len(X_cic_neg_sample), dtype=np.int64)
        X_cic_pos_log1p   = np.log1p(X_cic_pos)
        X_cic_neg_log1p   = np.log1p(X_cic_neg_sample)
    else:
        logging.warning(f"CIC real windows not found: {CIC_REAL}")
        X_cic_pos_log1p = np.empty((0, 7))
        X_cic_neg_log1p = np.empty((0, 7))
        y_cic_pos = np.empty(0, dtype=np.int64)
        y_cic_neg = np.empty(0, dtype=np.int64)

    # 3. Synthetic data
    X_synth_pos = generate_synthetic_scanners(N_SYNTH_POS, rng)
    y_synth_pos = np.ones(N_SYNTH_POS, dtype=np.int64)
    logging.info(f"Synth scanners: {N_SYNTH_POS}")
    sp_flood = X_synth_pos[X_synth_pos[:, 1] == 1]
    logging.info(f"  Single-port flood: {len(sp_flood)}, syn_cnt range: {sp_flood[:, 0].min():.0f}-{sp_flood[:, 0].max():.0f}")

    X_synth_neg_a = generate_pattern_a_negatives(N_SYNTH_NEG_A, rng)
    y_synth_neg_a = np.zeros(N_SYNTH_NEG_A, dtype=np.int64)

    X_synth_neg_c = generate_pattern_c_negatives(N_SYNTH_NEG_C, rng)
    y_synth_neg_c = np.zeros(N_SYNTH_NEG_C, dtype=np.int64)
    logging.info(f"Synth Pattern-C (ephemeral wide spr): {N_SYNTH_NEG_C}")

    X_synth_neg_d = generate_pattern_d_negatives(N_SYNTH_NEG_D, rng)
    y_synth_neg_d = np.zeros(N_SYNTH_NEG_D, dtype=np.int64)
    logging.info(f"Synth Pattern-D (lateral movement): {N_SYNTH_NEG_D}")

    X_synth_pos_log1p   = np.log1p(X_synth_pos)
    X_synth_neg_a_log1p = np.log1p(X_synth_neg_a)
    X_synth_neg_c_log1p = np.log1p(X_synth_neg_c)
    X_synth_neg_d_log1p = np.log1p(X_synth_neg_d)

    # 4. Merge all
    X_parts = [X_log1p_v3, X_synth_pos_log1p,
               X_synth_neg_a_log1p, X_synth_neg_c_log1p, X_synth_neg_d_log1p]
    y_parts = [y_all_v3, y_synth_pos,
               y_synth_neg_a, y_synth_neg_c, y_synth_neg_d]
    if len(X_cic_pos_log1p) > 0:
        X_parts += [X_cic_pos_log1p, X_cic_neg_log1p]
        y_parts += [y_cic_pos, y_cic_neg]

    X_combined = np.vstack(X_parts)
    y_combined = np.concatenate(y_parts)
    logging.info(f"Combined: {len(y_combined)}, pos={y_combined.sum()}, neg={len(y_combined)-y_combined.sum()}")

    # 5. Fit scaler
    sc_new = RobustScaler()
    sc_new.fit(X_combined)
    X_scaled = sc_new.transform(X_combined)

    # 6. Split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X_scaled, y_combined, test_size=0.15, random_state=42, stratify=y_combined)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.1765, random_state=42, stratify=y_temp)
    logging.info(f"Train: {X_train.shape}, pos={y_train.sum()}")
    logging.info(f"Val:   {X_val.shape}, pos={y_val.sum()}")
    logging.info(f"Test:  {X_test.shape}, pos={y_test.sum()}")

    # 7. Train
    pos_count = int(y_train.sum())
    neg_count = len(y_train) - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1.0
    logging.info(f"scale_pos_weight={spw:.2f}")

    model = xgb.XGBClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.05,
        scale_pos_weight=spw, subsample=0.8, colsample_bytree=0.8,
        gamma=0.1, reg_lambda=1.0, reg_alpha=0.1,
        objective='binary:logistic', tree_method='hist',
        eval_metric='aucpr', early_stopping_rounds=30,
        random_state=42, n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
    logging.info(f"Best iteration: {model.best_iteration}")

    # 8. Feature importances
    logging.info("Feature importances:")
    for name, imp in zip(FEATURE_NAMES, model.feature_importances_):
        logging.info(f"  {name}: {imp:.4f}")

    # 9. Threshold sweep on val
    val_proba = model.predict_proba(X_val)[:, 1]
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.40, 0.96, 0.05):
        m = compute_metrics(y_val, (val_proba >= t).astype(int))
        logging.info(f"Val t={t:.2f}: Rec={m['recall']:.3f} Prec={m['precision']:.3f} "
                     f"F1={m['f1']:.3f} FP={m['fp']} FN={m['fn']}")
        if m['f1'] > best_f1:
            best_f1, best_t = m['f1'], round(float(t), 2)
    logging.info(f"Best val t={best_t:.2f} F1={best_f1:.4f}")

    # 10. Test
    test_proba = model.predict_proba(X_test)[:, 1]
    logging.info("--- Test ---")
    for t in [0.50, 0.80, 0.90, 0.93, 0.95, best_t]:
        m = compute_metrics(y_test, (test_proba >= t).astype(int))
        logging.info(f"Test t={t:.2f}: Rec={m['recall']:.3f} Prec={m['precision']:.3f} "
                     f"F1={m['f1']:.3f} FP={m['fp']} FN={m['fn']}")
    auc = roc_auc_score(y_test, test_proba)
    logging.info(f"AUC={auc:.4f}")

    # 11. Probe key vectors
    logging.info("--- Key probe scores (raw → log1p → scaled) ---")
    probes = {
        'CIC single-port flood (35/1/1, spr=896)':  [35.0, 1.0, 1.0, 0.0, 896.0, 0.0286, 0.583],
        'CIC single-port flood (36/1/1, spr=920)':  [36.0, 1.0, 1.0, 0.0, 920.0, 0.0278, 0.600],
        'CIC broad scan (997/997/1, spr=28000)':     [997.0, 997.0, 1.0, 9.96, 28000.0, 1.0, 16.6],
        'Pattern A benign (386/5/1, spr=387)':       [386.0, 5.0, 1.0, 1.065, 387.0, 0.013, 6.43],
        'Pattern C benign SSH (10/1/1, spr=35000)':  [10.0, 1.0, 1.0, 0.0, 35000.0, 0.1, 0.167],
        'Pattern D lateral (50/5/10, spr=50)':       [50.0, 5.0, 10.0, 1.92, 50.0, 0.1, 0.833],
        'Cupid flood (68661/1000/1)':                [68661.0, 1000.0, 1.0, 9.935, 297.0, 0.0146, 1144.35],
        'Medium scan (5000/800/1)':                  [5000.0, 800.0, 1.0, 9.0, 15000.0, 0.16, 83.3],
    }
    for label, raw in probes.items():
        r = np.array([raw])
        r_log1p = np.log1p(r)
        r_scaled = sc_new.transform(r_log1p)
        score = model.predict_proba(r_scaled)[0, 1]
        logging.info(f"  {label}: score={score:.4f}")

    # 12. Save
    model.save_model(str(OUT_MODEL))
    np.save(OUT_DATA / 'X_train.npy', X_train)
    np.save(OUT_DATA / 'y_train.npy', y_train)
    np.save(OUT_DATA / 'X_val.npy', X_val)
    np.save(OUT_DATA / 'y_val.npy', y_val)
    np.save(OUT_DATA / 'X_test.npy', X_test)
    np.save(OUT_DATA / 'y_test.npy', y_test)
    with open(OUT_DATA / 'scaler.pkl', 'wb') as f:
        pickle.dump(sc_new, f)

    scaler_path = Path(str(OUT_MODEL).replace('.json', '_scaler.json'))
    sidecar = {
        'feature_names': FEATURE_NAMES,
        'median': sc_new.center_.tolist(),
        'iqr': sc_new.scale_.tolist(),
        'log1p_all': True,
    }
    with open(scaler_path, 'w') as f:
        json.dump(sidecar, f, indent=2)
    logging.info(f"Saved: {OUT_MODEL}")
    logging.info(f"C++ median: {sc_new.center_.tolist()}")
    logging.info(f"C++ iqr:    {sc_new.scale_.tolist()}")


if __name__ == '__main__':
    main()
