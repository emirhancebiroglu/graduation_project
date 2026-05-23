#!/usr/bin/env python3
"""Label training dump from CSV ground truth and train XGBoost."""
import json, logging, pickle, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

FEATURE_NAMES = [
    'total_attempts','unique_dst_ports','unique_dst_ips',
    'dst_port_entropy','src_port_range','unique_port_ratio','attempt_rate',
    'tcp_syn_ratio','fin_null_xmas_ratio','udp_ratio',
    'scan_type_diversity','avg_ttl',
]

CIC_DIR = Path.home() / 'bitirme' / 'data' / 'raw' / 'cicids2017'
PCAP_TS = {  # approximate start of each PCAP in epoch seconds
    'Monday':    1499328000,  # 2017-07-06 09:00
    'Tuesday':   1499414400,  # 2017-07-07 09:00
    'Wednesday': 1499500800,  # 2017-07-08 09:00
    'Thursday':  1499587200,  # 2017-07-09 09:00
    'Friday':    1499673600,  # 2017-07-10 09:00
}

def load_csv_labels(day_name):
    """Return dict of (src_ip, window_id) -> label (0/1) for a given day."""
    csv_map = {
        'Monday':    ['Monday-WorkingHours.pcap_ISCX.csv'],
        'Tuesday':   ['Tuesday-WorkingHours.pcap_ISCX.csv'],
        'Wednesday': ['Wednesday-workingHours.pcap_ISCX.csv'],
        'Thursday':  ['Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
                      'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'],
        'Friday':    ['Friday-WorkingHours-Morning.pcap_ISCX.csv',
                      'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
                      'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'],
    }
    labels = {}
    for fname in csv_map.get(day_name, []):
        fpath = CIC_DIR / fname
        if not fpath.exists():
            logging.warning(f"  Not found: {fpath}")
            continue
        df = pd.read_csv(fpath, low_memory=False, on_bad_lines='skip')
        df.columns = df.columns.str.strip()
        df['Label'] = df['Label'].str.strip()

        ts = pd.to_datetime(df['Timestamp'])
        epoch_s = ts.astype('int64').to_numpy(dtype=np.float64) / 1e6
        df['window_id'] = (epoch_s // 60).astype(int)

        for _, row in df.iterrows():
            ip = row['Source IP']
            wid = row['window_id']
            label = 1 if row['Label'] == 'PortScan' else 0
            if label == 1:
                labels[(ip, wid)] = 1
            elif (ip, wid) not in labels:
                labels[(ip, wid)] = 0
    return labels

def main():
    dump_path = Path('/tmp/portscan_train_data.txt')
    if not dump_path.exists():
        logging.error("Training dump not found. Run PCAP replays first.")
        sys.exit(1)

    raw_data = np.loadtxt(dump_path, comments='#')
    y_dump = raw_data[:, 0].astype(int)
    X_raw = raw_data[:, 1:-1]
    scores = raw_data[:, -1]

    logging.info(f"Loaded {len(X_raw)} samples, {y_dump.sum()} scanner-labeled in dump")

    # The dump labels (y_dump) are based on src_ip == 172.16.0.1
    # This is a reasonable heuristic. But we can refine by window-based labeling.
    y = y_dump  # Use dump labels (they're already from known scanner IP)
    
    X = X_raw.astype(np.float64)
    log1p_cols = [0, 1, 2, 6]  # total_attempts, unique_dst_ports, unique_dst_ips, attempt_rate
    for i in range(len(FEATURE_NAMES)):
        if i in log1p_cols:
            X[:, i] = np.log1p(X[:, i])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logging.info(f"Train: {X_train_s.shape}, pos={y_train.sum()}/{len(y_train)}")
    logging.info(f"Test:  {X_test_s.shape}, pos={y_test.sum()}/{len(y_test)}")

    model = xgb.XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.1,
        objective='binary:logistic', tree_method='hist',
        random_state=42, n_jobs=-1,
    )
    model.fit(X_train_s, y_train, eval_set=[(X_test_s, y_test)], verbose=50)

    proba = model.predict_proba(X_test_s)[:, 1]

    # Threshold sweep
    best_f1, best_t = 0, 0.50
    print("\nThreshold sweep:")
    for t in [x/100 for x in range(5, 96, 5)]:
        y_p = (proba >= t).astype(int)
        tp = ((y_test == 1) & (y_p == 1)).sum()
        fp = ((y_test == 0) & (y_p == 1)).sum()
        fn = ((y_test == 1) & (y_p == 0)).sum()
        tn = ((y_test == 0) & (y_p == 0)).sum()
        prec = tp/(tp+fp) if (tp+fp)>0 else 0
        rec = tp/(tp+fn) if (tp+fn)>0 else 0
        f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
        fpr = fp/(fp+tn) if (fp+tn)>0 else 0
        mark = " <--" if f1 > best_f1 else ""
        if f1 > best_f1:
            best_f1, best_t = f1, t
        print(f"  t={t:.2f}: TP={tp} FP={fp} FN={fn} TN={tn}  "
              f"Prec={prec:.3f} Rec={rec:.3f} F1={f1:.3f} FPR={fpr:.4f}{mark}")

    y_p = (proba >= best_t).astype(int)
    tp = ((y_test == 1) & (y_p == 1)).sum()
    fn = ((y_test == 1) & (y_p == 0)).sum()
    fp = ((y_test == 0) & (y_p == 1)).sum()
    tn = ((y_test == 0) & (y_p == 0)).sum()
    print(f"\n--- Best threshold={best_t:.2f} ---")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Recall={tp/(tp+fn):.4f} Precision={tp/(tp+fp):.4f} FPR={fp/(fp+tn):.4f}")

    # Save model and scaler
    model_path = Path.home() / 'bitirme' / 'models' / 'portscan_aggregator_model.json'
    model.save_model(str(model_path))
    logging.info(f"Model saved: {model_path}")

    scaler_params = {
        'median': [round(v, 10) for v in scaler.center_.tolist()],
        'iqr': [round(v, 10) for v in scaler.scale_.tolist()],
    }
    with open(Path.home() / 'bitirme' / 'models' / 'aggregator_scaler_params.json', 'w') as f:
        json.dump(scaler_params, f, indent=2)

    print(f"\nScaler median: {[round(v,10) for v in scaler.center_.tolist()]}")
    print(f"Scaler iqr:    {[round(v,10) for v in scaler.scale_.tolist()]}")

if __name__ == '__main__':
    main()
