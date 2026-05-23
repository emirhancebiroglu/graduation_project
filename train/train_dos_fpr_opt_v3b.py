#!/usr/bin/env python3
"""
train_dos_fpr_opt_v3b.py — DoS FPR Optimization v3b

Same as v3 but removes swin/dwin (CIC-native TCP window values ~29000 vs UNSW ~255).
Uses mixed training: CIC labeled dumps + UNSW-NB15 attack/benign.

Feature schema (15):
  dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz,
  sintpkt, dintpkt, fwd_pkt_mean, bwd_pkt_mean,
  fin_cnt, ack_cnt, syn_cnt, bwd_iat

UNSW feature derivation:
  fwd_pkt_mean = sbytes/max(spkts,1), bwd_pkt_mean = dbytes/max(dpkts,1)
  fin_cnt=0, ack_cnt=0, syn_cnt=0  (not in UNSW)
  bwd_iat ≈ dintpkt

Saves:
  models/dos_fpr_opt_v3b.json
  models/dos_fpr_opt_v3b_scaler.json
"""

import json
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

BASE_DIR    = Path('/home/emirhan/bitirme')
LABELED_DIR = BASE_DIR / 'data/snort_dump/labeled'
UNSW_DIR    = BASE_DIR / 'data/unsw'
MODEL_OUT   = BASE_DIR / 'models/dos_fpr_opt_v3b.json'
SCALER_OUT  = BASE_DIR / 'models/dos_fpr_opt_v3b_scaler.json'
RESULTS_DIR = BASE_DIR / 'results/fpr-opt-dos/v3b'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

N_FEATURES = 15
FEATURE_COLS = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'smeansz', 'dmeansz',
    'sintpkt', 'dintpkt', 'fwd_pkt_mean', 'bwd_pkt_mean',
    'fin_cnt', 'ack_cnt', 'syn_cnt', 'bwd_iat'
]
# Indices to apply log1p (all except fin_cnt=11)
LOG1P_IDX = {0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14}

UNSW_COLS = [
    'srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes',
    'sttl','dttl','sloss','dloss','service','sload','dload','spkts','dpkts',
    'swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'sjit','djit','stime','ltime','sintpkt','dintpkt','tcprtt','synack','ackdat',
    'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
    'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label'
]
UNSW_BASE = ['dur','spkts','dpkts','sbytes','dbytes','smeansz','dmeansz','sintpkt','dintpkt']


def apply_log1p_scale(X: np.ndarray, median: np.ndarray, iqr: np.ndarray) -> np.ndarray:
    X = X.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))
    for i in range(N_FEATURES):
        X[:, i] = (X[:, i] - median[i]) / iqr[i] if iqr[i] > 0 else 0.0
    return X.astype(np.float32)


def load_cic_labeled(day: str):
    path = LABELED_DIR / f'{day}_labeled.csv'
    if not path.exists():
        log.warning(f'Not found: {path}')
        return None, None
    df = pd.read_csv(path, low_memory=False)
    # Drop swin/dwin, use only 15 features
    cic_cols = [c for c in FEATURE_COLS if c in df.columns]
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        log.warning(f'  Missing cols in {day}: {missing} — filling 0')
        for c in missing:
            df[c] = 0.0
    for c in FEATURE_COLS:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df['label'].values.astype(np.float32)
    log.info(f'  [CIC {day}] {len(df):,} rows  attack={y.sum():.0f}  benign={(1-y).sum():.0f}')
    return X, y


def load_unsw():
    """Load UNSW-NB15 (all 4 files), derive 15 features."""
    log.info('Loading UNSW-NB15...')
    dfs = []
    for i in [1, 2, 3, 4]:
        path = UNSW_DIR / f'UNSW-NB15_{i}.csv'
        df = pd.read_csv(path, header=None, names=UNSW_COLS, low_memory=False)
        if str(df.iloc[0, 0]).strip().lower() == 'srcip':
            df = df.iloc[1:]
        dfs.append(df)
    full = pd.concat(dfs, ignore_index=True)
    full['label'] = pd.to_numeric(full['label'], errors='coerce').fillna(0).astype(int)
    full[UNSW_BASE] = full[UNSW_BASE].apply(pd.to_numeric, errors='coerce')
    full.dropna(subset=UNSW_BASE + ['label'], inplace=True)

    x = full[UNSW_BASE].values.astype(np.float64)
    # UNSW_BASE order: dur(0), spkts(1), dpkts(2), sbytes(3), dbytes(4), smeansz(5), dmeansz(6), sintpkt(7), dintpkt(8)
    spkts   = x[:, 1]; dpkts = x[:, 2]
    sbytes  = x[:, 3]; dbytes = x[:, 4]
    dintpkt = x[:, 8]

    fwd_pkt_mean = sbytes / np.maximum(spkts, 1)   # col 9
    bwd_pkt_mean = dbytes / np.maximum(dpkts, 1)   # col 10
    fin_cnt      = np.zeros(len(x))                 # col 11
    ack_cnt      = np.zeros(len(x))                 # col 12
    syn_cnt      = np.zeros(len(x))                 # col 13
    bwd_iat      = dintpkt.copy()                   # col 14

    X = np.column_stack([x, fwd_pkt_mean, bwd_pkt_mean,
                          fin_cnt, ack_cnt, syn_cnt, bwd_iat]).astype(np.float32)
    y = full['label'].values.astype(np.float32)
    cats = full['attack_cat'].astype(str).str.strip().values

    log.info(f'  [UNSW] {len(y):,} rows  attack={y.sum():.0f}  benign={(1-y).sum():.0f}')
    return X, y, cats


def main():
    log.info('=' * 60)
    log.info('DoS FPR-Opt v3b — 15-feature, CIC+UNSW mixed training')
    log.info('=' * 60)

    # ── 1. Load CIC ─────────────────────────────────────────────
    log.info('[1/7] Loading CIC labeled dumps...')
    X_mon, y_mon = load_cic_labeled('Monday')
    X_tue, y_tue = load_cic_labeled('Tuesday')
    X_wed, y_wed = load_cic_labeled('Wednesday')

    X_wed_tr, X_wed_te, y_wed_tr, y_wed_te = train_test_split(
        X_wed, y_wed, test_size=0.30, random_state=42, stratify=y_wed)
    log.info(f'  Wednesday: train={len(y_wed_tr):,} (att={y_wed_tr.sum():.0f}) '
             f'test={len(y_wed_te):,} (att={y_wed_te.sum():.0f})')

    X_tue_ben = X_tue[y_tue == 0]
    y_tue_ben = y_tue[y_tue == 0]

    # ── 2. Load UNSW ─────────────────────────────────────────────
    log.info('[2/7] Loading UNSW-NB15...')
    X_unsw, y_unsw, cats_unsw = load_unsw()

    # UNSW 80/20 split (same seed as eval script)
    idx_u = np.arange(len(y_unsw))
    idx_u_tr, idx_u_te = train_test_split(idx_u, test_size=0.2, random_state=42, stratify=y_unsw)
    X_unsw_tr, y_unsw_tr = X_unsw[idx_u_tr], y_unsw[idx_u_tr]
    X_unsw_te, y_unsw_te = X_unsw[idx_u_te], y_unsw[idx_u_te]
    cats_unsw_te = cats_unsw[idx_u_te]
    log.info(f'  UNSW train: {len(y_unsw_tr):,}  UNSW test: {len(y_unsw_te):,}')

    # ── 3. Build combined train set ───────────────────────────────
    # CIC: full (Wed 70% + Mon + Tue benign)
    # UNSW: undersample to balance (avoid UNSW dominating)
    # UNSW has 2.5M rows vs CIC ~450K → cap UNSW at 400K randomly
    UNSW_CAP = 400_000
    if len(y_unsw_tr) > UNSW_CAP:
        rng = np.random.default_rng(42)
        cap_idx = rng.choice(len(y_unsw_tr), UNSW_CAP, replace=False)
        X_unsw_tr_cap = X_unsw_tr[cap_idx]
        y_unsw_tr_cap = y_unsw_tr[cap_idx]
    else:
        X_unsw_tr_cap = X_unsw_tr
        y_unsw_tr_cap = y_unsw_tr

    X_train = np.concatenate([X_wed_tr, X_mon, X_tue_ben, X_unsw_tr_cap], axis=0)
    y_train = np.concatenate([y_wed_tr, y_mon, y_tue_ben, y_unsw_tr_cap], axis=0)
    log.info(f'  Total train: {len(y_train):,}  attack={y_train.sum():.0f}  benign={(1-y_train).sum():.0f}')

    # Sample weights: CIC attack rows get 3x weight to preserve CIC recall ≥ 0.99
    CIC_ATTACK_WEIGHT = 3.0
    n_cic = len(y_wed_tr) + len(y_mon) + len(y_tue_ben)
    n_unsw = len(y_unsw_tr_cap)
    w_cic  = np.where(y_train[:n_cic] == 1, CIC_ATTACK_WEIGHT, 1.0)
    w_unsw = np.ones(n_unsw)
    sample_weight = np.concatenate([w_cic, w_unsw]).astype(np.float32)
    log.info(f'  CIC attack weight={CIC_ATTACK_WEIGHT}x  (CIC rows={n_cic:,}, UNSW rows={n_unsw:,})')

    # ── 4. Fit scaler on combined benign ─────────────────────────
    log.info('[4/7] Fitting RobustScaler on combined benign flows...')
    X_benign = X_train[y_train == 0]
    X_ben_log = X_benign.copy().astype(np.float64)
    for i in LOG1P_IDX:
        X_ben_log[:, i] = np.log1p(np.maximum(X_ben_log[:, i], 0.0))
    scaler = RobustScaler()
    scaler.fit(X_ben_log)
    median = scaler.center_
    iqr    = scaler.scale_
    log.info(f'  Scaler fit on {len(X_benign):,} benign rows')

    # ── 5. Scale ─────────────────────────────────────────────────
    log.info('[5/7] Scaling...')
    X_train_s  = apply_log1p_scale(X_train, median, iqr)
    X_wed_te_s = apply_log1p_scale(X_wed_te, median, iqr)
    X_unsw_te_s = apply_log1p_scale(X_unsw_te, median, iqr)

    # ── 6. Train ─────────────────────────────────────────────────
    log.info('[6/7] Training XGBoost...')
    spw = float((y_train == 0).sum()) / float((y_train == 1).sum())
    log.info(f'  scale_pos_weight = {spw:.2f}')
    model = xgb.XGBClassifier(
        n_estimators=650,
        max_depth=5,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.5,
        reg_alpha=0.2,
        gamma=0.5,
        min_child_weight=5,
        scale_pos_weight=spw,
        use_label_encoder=False,
        eval_metric='logloss',
        tree_method='hist',
        nthread=4,
        random_state=42,
    )
    model.fit(X_train_s, y_train,
              sample_weight=sample_weight,
              eval_set=[(X_train_s, y_train), (X_wed_te_s, y_wed_te)],
              verbose=100)

    # ── 7. Save ──────────────────────────────────────────────────
    log.info('[7/7] Saving...')
    model.save_model(str(MODEL_OUT))
    scaler_data = {
        'n_features': N_FEATURES,
        'log1p_indices': sorted(LOG1P_IDX),
        'median': median.tolist(),
        'iqr': iqr.tolist(),
        'feature_names': FEATURE_COLS
    }
    with open(SCALER_OUT, 'w') as f:
        json.dump(scaler_data, f, indent=2)
    log.info(f'  Model: {MODEL_OUT}')
    log.info(f'  Scaler: {SCALER_OUT}')

    # ── Evaluate ─────────────────────────────────────────────────
    log.info('\n=== CIC Wednesday 30% eval ===')
    _eval_and_print(model, X_wed_te_s, y_wed_te, 'CIC Wednesday', RESULTS_DIR / 'cic_wed_eval.json')

    log.info('\n=== UNSW 20% eval (per-category) ===')
    _eval_unsw(model, X_unsw_te_s, y_unsw_te, cats_unsw_te, RESULTS_DIR / 'unsw_eval.json')

    # Print C++ scaler params
    log.info('\nC++ scaler params → dos_inspector.cc:')
    log.info('// median[15]')
    log.info('{ ' + ', '.join(f'{v:.6f}' for v in median) + ' },')
    log.info('// iqr[15]')
    log.info('{ ' + ', '.join(f'{v:.6f}' for v in iqr) + ' }')


def _eval_and_print(model, X_te_s, y_te, label, out_path):
    y_prob = model.predict_proba(X_te_s)[:, 1]
    thresholds = [0.50, 0.70, 0.80, 0.85, 0.90, 0.92, 0.95]
    log.info(f"{'t':>6} {'TP':>8} {'FP':>8} {'FN':>7} {'TN':>8} "
             f"{'Rec':>7} {'Prec':>7} {'F1':>7} {'FPR':>8}")
    log.info('-' * 72)
    results = []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        cm = confusion_matrix(y_te, y_pred)
        tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0
        rec  = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
        fpr  = fp/(fp+tn) if (fp+tn) > 0 else 0
        log.info(f"{t:>6.2f} {tp:>8} {fp:>8} {fn:>7} {tn:>8} "
                 f"{rec:>7.4f} {prec:>7.4f} {f1:>7.4f} {fpr:>8.4f}")
        results.append({'t': t, 'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'tn': int(tn),
                         'rec': rec, 'prec': prec, 'f1': f1, 'fpr': fpr})
    with open(out_path, 'w') as f:
        json.dump({'label': label, 'results': results}, f, indent=2)
    log.info(f'  Saved: {out_path}')
    return results


def _eval_unsw(model, X_te_s, y_te, cats_te, out_path):
    from sklearn.metrics import confusion_matrix as cm_fn
    y_prob = model.predict_proba(X_te_s)[:, 1]
    THRESHOLD = 0.90
    yp = (y_prob >= THRESHOLD).astype(int)

    tp = int(((y_te==1)&(yp==1)).sum())
    fp = int(((y_te==0)&(yp==1)).sum())
    fn = int(((y_te==1)&(yp==0)).sum())
    tn = int(((y_te==0)&(yp==0)).sum())
    rec  = tp/(tp+fn) if (tp+fn)>0 else 0
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    fpr  = fp/(fp+tn) if (fp+tn)>0 else 0

    log.info(f'  Overall @t={THRESHOLD}: TP={tp:,} FP={fp:,} FN={fn:,} '
             f'Rec={rec:.4f} Prec={prec:.4f} F1={f1:.4f} FPR={fpr:.6f}')
    status = "PASS" if rec >= 0.81 else "FAIL"
    log.info(f'  Accept (Recall>=0.81): {status}')

    per_cat = {}
    log.info(f'\n  {"Category":<18} {"Total":>8} {"Attacks":>8} {"TP":>7} {"Recall":>8}')
    log.info('  ' + '-' * 56)
    for cat in sorted(set(cats_te), key=str):
        mask = cats_te == cat
        yt_c = y_te[mask]; yp_c = yp[mask]
        tp_c = int(((yt_c==1)&(yp_c==1)).sum())
        fn_c = int(((yt_c==1)&(yp_c==0)).sum())
        fp_c = int(((yt_c==0)&(yp_c==1)).sum())
        tn_c = int(((yt_c==0)&(yp_c==0)).sum())
        rec_c = tp_c/(tp_c+fn_c) if (tp_c+fn_c)>0 else 0
        prec_c = tp_c/(tp_c+fp_c) if (tp_c+fp_c)>0 else 0
        f1_c = 2*prec_c*rec_c/(prec_c+rec_c) if (prec_c+rec_c)>0 else 0
        fpr_c = fp_c/(fp_c+tn_c) if (fp_c+tn_c)>0 else 0
        per_cat[str(cat)] = {'tp':tp_c,'fp':fp_c,'fn':fn_c,'tn':tn_c,
                              'recall':round(rec_c,4),'precision':round(prec_c,4),
                              'f1':round(f1_c,4),'fpr':round(fpr_c,6),
                              'total':int(mask.sum()),'n_attacks':int(yt_c.sum())}
        flag = ' ✅' if yt_c.sum()==0 or rec_c>=0.81 else ' ❌'
        log.info(f'  {str(cat):<18} {mask.sum():>8,} {yt_c.sum():>8,} {tp_c:>7,} {rec_c:>8.4f}{flag}')

    result = {
        'model': 'dos_fpr_opt_v3b.json', 'threshold': THRESHOLD,
        'overall': {'tp':tp,'fp':fp,'fn':fn,'tn':tn,
                    'recall':round(rec,4),'precision':round(prec,4),
                    'f1':round(f1,4),'fpr':round(fpr,6)},
        'accept_status': status,
        'per_category': per_cat,
    }
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    log.info(f'  Saved: {out_path}')


if __name__ == '__main__':
    main()
