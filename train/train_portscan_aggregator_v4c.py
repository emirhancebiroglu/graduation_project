#!/usr/bin/env python3
"""
train_portscan_aggregator_v4c.py
Fix for v4b over-generalization.

Changes vs v4b:
  - Synthetic positives: ALL must have uports >= 100 (ensures port diversity)
  - Add explicit "high-traffic-to-few-ports" benign negatives (Pattern A)
  - No "flood to few ports" scanner type (removed)
  - Entropy constraint for scanners: entropy > 5.0 (uniform port distribution)
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

FEATURE_NAMES = ['total_syns','unique_dst_ports','unique_dst_ips',
                 'dst_port_entropy','src_port_range','unique_port_ratio','syn_rate']
V3_DATA = Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v3'
OUT_DATA = Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_v4d'
OUT_MODEL = Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model_v4d.json'
N_SYNTH_POS = 300
N_SYNTH_NEG_PATTERNN_A = 300  # high syn_cnt, few dst ports (explicitly benign, inc. wide spr)
RANDOM_SEED = 42


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0,1])
    tn, fp, fn, tp = cm.ravel()
    pr = tp/(tp+fp) if (tp+fp)>0 else 0.0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0.0
    f1 = 2*pr*rec/(pr+rec) if (pr+rec)>0 else 0.0
    return {'tp':int(tp),'fp':int(fp),'tn':int(tn),'fn':int(fn),
            'precision':round(pr,4),'recall':round(rec,4),'f1':round(f1,4)}


def generate_synthetic_scanners(n, rng):
    """All scanners MUST have uports >= 100 and entropy > 5."""
    rows = []
    for _ in range(n):
        scan_type = rng.choice(['slow','medium','fast','flood'], p=[0.30,0.25,0.25,0.20])
        if scan_type == 'slow':
            # CIC-like: 200-1500 SYNs, 1 SYN/port mostly
            uports = rng.integers(100, 1500)
            syn_cnt = rng.integers(uports, max(uports+1, int(uports * 1.5)))
        elif scan_type == 'medium':
            uports = rng.integers(200, 3000)
            syn_cnt = rng.integers(uports, max(uports+1, uports * 5))
        elif scan_type == 'fast':
            uports = rng.integers(500, 10000)
            syn_cnt = rng.integers(uports, max(uports+1, uports * 10))
        else:
            # Flood/Cupid-like: many SYNs per port, but still many ports
            uports = rng.integers(100, 5000)
            syn_cnt = rng.integers(uports * 10, max(uports*11, uports * 200))
        
        uips = rng.integers(1, 4)
        # High entropy (uniform) for diverse port scans
        max_entropy = log2(uports) if uports > 1 else 1.0
        entropy = rng.uniform(max(5.0, max_entropy * 0.6), min(max_entropy, 16.0))
        
        sp_range = float(rng.integers(200, 30000))
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     float(entropy), sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def generate_pattern_a_negatives(n, rng):
    """Pattern A: high syn_cnt but very few dst ports — explicitly benign.
    Two sub-types:
      A1: src_prange ~ syn_cnt (sequential ephemeral, one port per conn)
      A2: src_prange >> syn_cnt (OS picks from full ephemeral range 1024-65535)
    """
    rows = []
    for _ in range(n):
        syn_cnt = rng.integers(5, 1500)
        uports = rng.integers(1, min(25, max(2, int(syn_cnt * 0.15) + 1)))
        uips = rng.integers(1, 15)
        # Low entropy (connecting to few specific ports)
        entropy = rng.uniform(0.0, min(3.0, log2(uports)+0.3) if uports>1 else 0.1)
        # Mix of src_prange patterns
        if rng.random() < 0.5:
            # A1: sequential ephemeral
            sp_range = float(rng.integers(max(1, syn_cnt-100), syn_cnt+200))
        else:
            # A2: wide ephemeral range (modern OS behavior)
            sp_range = float(rng.integers(10000, 60000))
        pratio = uports / syn_cnt
        srate = syn_cnt / 60.0
        rows.append([float(syn_cnt), float(uports), float(uips),
                     entropy, sp_range, pratio, srate])
    return np.array(rows, dtype=np.float64)


def main():
    OUT_DATA.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(RANDOM_SEED)

    # 1. Load v3 (inverse-transform to log1p)
    logging.info("Loading v3 data...")
    with open(V3_DATA / 'scaler.pkl','rb') as f:
        sc_v3 = pickle.load(f)
    Xtr = np.load(V3_DATA / 'X_train.npy')
    ytr = np.load(V3_DATA / 'y_train.npy')
    Xva = np.load(V3_DATA / 'X_val.npy')
    yva = np.load(V3_DATA / 'y_val.npy')
    Xte = np.load(V3_DATA / 'X_test.npy')
    yte = np.load(V3_DATA / 'y_test.npy')
    X_all_v3 = np.vstack([Xtr, Xva, Xte])
    y_all_v3 = np.concatenate([ytr, yva, yte])
    X_log1p_v3 = sc_v3.inverse_transform(X_all_v3)
    logging.info(f"v3: {len(y_all_v3)} windows, pos={y_all_v3.sum()}")

    # 2. Synthetic data
    X_synth_pos = generate_synthetic_scanners(N_SYNTH_POS, rng)
    y_synth_pos = np.ones(N_SYNTH_POS, dtype=np.int64)
    logging.info(f"Synth scanners: {N_SYNTH_POS}, uports range: {X_synth_pos[:,1].min():.0f}-{X_synth_pos[:,1].max():.0f}")

    X_synth_neg_a = generate_pattern_a_negatives(N_SYNTH_NEG_PATTERNN_A, rng)
    y_synth_neg_a = np.zeros(N_SYNTH_NEG_PATTERNN_A, dtype=np.int64)
    logging.info(f"Synth Pattern-A negatives: {N_SYNTH_NEG_PATTERNN_A}, uports: {X_synth_neg_a[:,1].min():.0f}-{X_synth_neg_a[:,1].max():.0f}")

    X_synth_pos_log1p = np.log1p(X_synth_pos)
    X_synth_neg_a_log1p = np.log1p(X_synth_neg_a)

    # 3. Merge
    X_combined = np.vstack([X_log1p_v3, X_synth_pos_log1p, X_synth_neg_a_log1p])
    y_combined = np.concatenate([y_all_v3, y_synth_pos, y_synth_neg_a])
    logging.info(f"Combined: {len(y_combined)}, pos={y_combined.sum()}")

    # 4. Fit scaler
    sc_new = RobustScaler()
    sc_new.fit(X_combined)
    X_scaled = sc_new.transform(X_combined)

    # 5. Split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X_scaled, y_combined, test_size=0.15, random_state=42, stratify=y_combined)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.1765, random_state=42, stratify=y_temp)
    logging.info(f"Train: {X_train.shape}, pos={y_train.sum()}")
    logging.info(f"Val:   {X_val.shape}, pos={y_val.sum()}")
    logging.info(f"Test:  {X_test.shape}, pos={y_test.sum()}")

    # 6. Train
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

    # 7. Feature importances
    names = FEATURE_NAMES
    logging.info("Feature importances:")
    for n, imp in zip(names, model.feature_importances_):
        logging.info(f"  {n}: {imp:.4f}")

    # 8. Val threshold sweep
    val_proba = model.predict_proba(X_val)[:,1]
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.40, 0.96, 0.05):
        m = compute_metrics(y_val, (val_proba >= t).astype(int))
        logging.info(f"Val t={t:.2f}: Rec={m['recall']:.3f} Prec={m['precision']:.3f} F1={m['f1']:.3f} FP={m['fp']} FN={m['fn']}")
        if m['f1'] > best_f1:
            best_f1, best_t = m['f1'], round(float(t), 2)

    logging.info(f"Best val t={best_t:.2f} F1={best_f1:.4f}")

    # 9. Test
    test_proba = model.predict_proba(X_test)[:,1]
    logging.info("--- Test ---")
    for t in [0.50, 0.65, 0.80, 0.85, 0.90, best_t]:
        m = compute_metrics(y_test, (test_proba >= t).astype(int))
        logging.info(f"Test t={t:.2f}: Rec={m['recall']:.3f} Prec={m['precision']:.3f} F1={m['f1']:.3f} FP={m['fp']} FN={m['fn']}")
    auc = roc_auc_score(y_test, test_proba)
    logging.info(f"AUC={auc:.4f}")

    # 10. Save
    model.save_model(str(OUT_MODEL))
    np.save(OUT_DATA / 'X_train.npy', X_train); np.save(OUT_DATA / 'y_train.npy', y_train)
    np.save(OUT_DATA / 'X_val.npy', X_val);   np.save(OUT_DATA / 'y_val.npy', y_val)
    np.save(OUT_DATA / 'X_test.npy', X_test); np.save(OUT_DATA / 'y_test.npy', y_test)
    with open(OUT_DATA / 'scaler.pkl','wb') as f:
        pickle.dump(sc_new, f)

    scaler_path = Path(str(OUT_MODEL).replace('.json','_scaler.json'))
    sidecar = {'feature_names': FEATURE_NAMES, 'median': sc_new.center_.tolist(), 'iqr': sc_new.scale_.tolist(), 'log1p_all': True}
    with open(scaler_path, 'w') as f:
        json.dump(sidecar, f, indent=2)
    logging.info(f"Saved: {OUT_MODEL}")
    logging.info(f"C++ median: {sc_new.center_.tolist()}")
    logging.info(f"C++ iqr:    {sc_new.scale_.tolist()}")

    # Probe specific vectors
    logging.info("--- Key probe scores ---")
    probes = {
        'Cupid flood (68661/1000/1)': [68661.0, 1000.0, 1.0, 9.935019, 297.0, 0.014564, 1144.35],
        'CIC slow (997/997/1)':        [997.0, 997.0, 1.0, 9.96, 28000.0, 1.0, 16.6],
        'Pattern_A benign (386/5/1)':  [386.0, 5.0, 1.0, 1.065, 387.0, 0.013, 6.43],
        'Pattern_A benign (489/3/1)':  [489.0, 3.0, 1.0, 0.786, 488.0, 0.006, 8.15],
        'Medium scan (5000/800/1)':    [5000.0, 800.0, 1.0, 9.0, 15000.0, 0.16, 83.3],
    }
    for label, raw in probes.items():
        r = np.array([raw])
        r_log1p = np.log1p(r)
        r_scaled = sc_new.transform(r_log1p)
        score = model.predict_proba(r_scaled)[0,1]
        logging.info(f"  {label}: score={score:.4f}")


if __name__ == '__main__':
    main()
