#!/usr/bin/env python3
"""
prepare_aggregated_portscan.py — Cross-flow aggregated PortScan dataset

Instead of per-flow rows, groups flows by source IP into time windows
and computes cross-flow features that capture port scan behavior.

Output: data/processed/portscan_aggregated/
  X_train.npy  (N_windows × AGG_FEATURE_COUNT)
  y_train.npy  (N_windows,)
  X_val.npy, y_val.npy
  X_test.npy, y_test.npy
  scaler.pkl
  metadata.json
"""

import argparse
import json
import logging
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AGG_FEATURE_COUNT = 4
WINDOW_SECONDS = 60

FEATURE_NAMES = [
    'unique_dst_ports',
    'unique_dst_ips',
    'total_flows',
    'flow_rate',
]

FRIDAY_CSV_FILES = [
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

WEDNESDAY_CSV = 'Wednesday-workingHours.pcap_ISCX.csv'


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False, on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    df['Label'] = df['Label'].str.strip()
    return df


def build_windows(df: pd.DataFrame, window_sec: int) -> pd.DataFrame:
    """Group CSV flows by source IP into time windows, compute cross-flow features."""
    df = df.sort_values('Timestamp').reset_index(drop=True)

    # Pre-compute label
    df['_is_portscan'] = (df['Label'] == 'PortScan').astype(int)

    # Use minute-granularity timestamps directly (no spreading).
    # pandas stores datetime64[us], so astype('int64') gives MICROseconds.
    # Dividing by 1e6 converts to seconds since epoch.
    orig_ts = pd.to_datetime(df['Timestamp'])
    epoch_s = orig_ts.astype('int64').to_numpy(dtype=np.float64) / 1e6
    df['window_id'] = (epoch_s // window_sec).astype(int)

    grouped = df.groupby(['Source IP', 'window_id'])

    logging.info("Computing aggregated features...")
    result = grouped.agg(
        unique_dst_ports=('Destination Port', 'nunique'),
        unique_dst_ips=('Destination IP', 'nunique'),
        total_flows=('Flow Duration', 'size'),
        label=('_is_portscan', 'max'),
    ).reset_index()

    result['flow_rate'] = result['total_flows'] / window_sec

    logging.info(f"Windows: {len(result)} ({result['label'].sum()} scan, {(result['label']==0).sum()} benign)")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'raw' / 'cicids2017'))
    parser.add_argument('--output-dir', type=str,
                        default=str(Path.home() / 'bitirme' / 'data' / 'processed' / 'portscan_aggregated'))
    parser.add_argument('--window', type=int, default=WINDOW_SECONDS)
    parser.add_argument('--add-wednesday', action='store_true',
                        help='Add Wednesday flows as extra negatives')
    args = parser.parse_args()

    csv_dir = Path(args.csv_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logging.info(f"Loading Friday CSVs from {csv_dir}")
    all_dfs = []
    for fname in FRIDAY_CSV_FILES:
        fpath = csv_dir / fname
        if not fpath.exists():
            logging.warning(f"Not found: {fpath}")
            continue
        logging.info(f"Loading {fname}...")
        df = load_csv(fpath)
        all_dfs.append(df)

    if args.add_wednesday:
        wed_path = csv_dir / WEDNESDAY_CSV
        if wed_path.exists():
            logging.info(f"Loading Wednesday (extra negatives)...")
            wed_df = load_csv(wed_path)
            all_dfs.append(wed_df)
        else:
            logging.warning(f"Wednesday CSV not found: {wed_path}")

    combined = pd.concat(all_dfs, ignore_index=True)
    logging.info(f"Combined: {combined.shape}, labels: {combined['Label'].value_counts().to_dict()}")

    logging.info(f"Building {args.window}s windows per source IP...")
    windows = build_windows(combined, args.window)

    logging.info(f"Label distribution: {windows['label'].value_counts().to_dict()}")

    X = windows[FEATURE_NAMES].values.astype(np.float64)
    y = windows['label'].values.astype(np.int64)

    # log1p transform on count features
    log1p_cols = ['unique_dst_ports', 'unique_dst_ips', 'total_flows', 'flow_rate']
    # Remove zero_resp and syn_only from columns not present
    feature_names = [f for f in FEATURE_NAMES]
    for i, name in enumerate(FEATURE_NAMES):
        if name in log1p_cols:
            X[:, i] = np.log1p(X[:, i])

    # Train/val/test split (70/15/15, stratified)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.15 / 0.85, random_state=42, stratify=y_temp
    )

    logging.info(f"Train: {X_train.shape}, pos={y_train.sum()}/{len(y_train)}")
    logging.info(f"Val:   {X_val.shape}, pos={y_val.sum()}/{len(y_val)}")
    logging.info(f"Test:  {X_test.shape}, pos={y_test.sum()}/{len(y_test)}")

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    np.save(out_dir / 'X_train.npy', X_train_scaled)
    np.save(out_dir / 'y_train.npy', y_train)
    np.save(out_dir / 'X_val.npy', X_val_scaled)
    np.save(out_dir / 'y_val.npy', y_val)
    np.save(out_dir / 'X_test.npy', X_test_scaled)
    np.save(out_dir / 'y_test.npy', y_test)

    with open(out_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    median_vals = scaler.center_.tolist()
    iqr_vals = scaler.scale_.tolist()

    metadata = {
        'source': 'Friday CSVs + Wednesday (optional)',
        'window_seconds': args.window,
        'feature_count': AGG_FEATURE_COUNT,
        'feature_names': FEATURE_NAMES,
        'log1p_features': log1p_cols,
        'train_samples': len(X_train),
        'val_samples': len(X_val),
        'test_samples': len(X_test),
        'attack_rate_train': float(y_train.sum() / len(y_train)),
        'attack_rate_test': float(y_test.sum() / len(y_test)),
        'scaler_median': median_vals,
        'scaler_iqr': iqr_vals,
    }
    with open(out_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logging.info(f"Saved to {out_dir}")
    logging.info(f"Scaler median: {[round(v, 6) for v in median_vals]}")
    logging.info(f"Scaler iqr:    {[round(v, 6) for v in iqr_vals]}")


if __name__ == '__main__':
    main()
