#!/usr/bin/env python3
"""Measure train/serve skew in dos_aggregator due to log1p mismatch.

Python train: log1p only on cols [0,1,2,6]
C++ runtime:  log1p on ALL 7 cols

This script loads the actual dump files, computes both versions,
scales both with the saved scaler, and measures the difference.
"""
import numpy as np
import json
import glob
import os
from pathlib import Path

BASE    = Path('/home/emirhan/bitirme')
DUMP_DIR = BASE / 'results' / 'dos_aggregator'
SCALER_PATH = BASE / 'models' / 'dos_aggregator_model_scaler.json'

def load_scaler(path):
    with open(path) as f:
        s = json.load(f)
    return np.array(s['median']), np.array(s['iqr'])

def robust_scale(X, median, iqr):
    return (X - median) / iqr

def main():
    # Load dump files
    files = sorted(glob.glob(str(DUMP_DIR / 'dos_train_data_*.txt')))
    if not files:
        print(f'ERROR: No dump files found in {DUMP_DIR}')
        print('Run Snort replay first to generate dumps.')
        return

    all_data = []
    for f in files:
        day = os.path.basename(f).replace('dos_train_data_','').replace('.txt','')
        data = np.loadtxt(f, comments='#')
        if data.ndim == 1:
            data = data.reshape(1,-1)
        print(f'  {day}: {len(data)} windows')
        all_data.append(data)

    data = np.vstack(all_data)
    X_raw = data[:, 1:8].astype(np.float64)
    print(f'\nTotal windows: {len(X_raw)}')

    # Python train version: log1p only on [0,1,2,6]
    X_python = X_raw.copy()
    for i in [0,1,2,6]:
        X_python[:,i] = np.log1p(X_python[:,i])

    # C++ runtime version: log1p on ALL 7
    X_cpp = np.log1p(X_raw)

    # Load scaler (trained on Python version)
    median, iqr = load_scaler(SCALER_PATH)
    print(f'Scaler median: {median.round(4)}')
    print(f'Scaler IQR:    {iqr.round(4)}')

    X_python_s = robust_scale(X_python, median, iqr)
    X_cpp_s    = robust_scale(X_cpp,    median, iqr)

    diff = np.abs(X_cpp_s - X_python_s)
    print()
    print('=== Train/Serve Skew Analysis ===')
    print(f'{"Col":>4}  {"Mean Diff":>10}  {"Max Diff":>10}  {"Relative %":>12}')
    print('-' * 42)
    for i in range(7):
        col_diff = diff[:,i]
        col_scale = np.abs(X_python_s[:,i]).mean() + 1e-9
        rel_pct = 100 * col_diff.mean() / col_scale
        print(f'  {i:>2}  {col_diff.mean():>10.4f}  {col_diff.max():>10.4f}  {rel_pct:>11.1f}%')

    overall_mean = diff.mean()
    overall_max  = diff.max()
    print()
    print(f'Overall mean scaled diff: {overall_mean:.4f}')
    print(f'Overall max  scaled diff: {overall_max:.4f}')

    # Which columns are affected?
    affected = [i for i in range(7) if i not in [0,1,2,6]]
    print(f'\nCols affected (C++ applies log1p, Python does not): {affected}')
    print(f'These are cols 3,4,5 — check what they represent in dos_aggregator')

    if overall_mean > 0.05:
        print('\n⚠  SIGNIFICANT SKEW (>5% mean diff) — C++ fix recommended')
        verdict = 'FIX_REQUIRED'
    elif overall_mean > 0.01:
        print('\n⚠  MODERATE SKEW (1-5%) — monitor, fix in next retrain')
        verdict = 'FIX_RECOMMENDED'
    else:
        print('\n✓  NEGLIGIBLE SKEW (<1%) — acceptable')
        verdict = 'ACCEPTABLE'

    result = {
        'verdict': verdict,
        'overall_mean_diff': round(float(overall_mean), 6),
        'overall_max_diff':  round(float(overall_max),  6),
        'per_col': {str(i): {'mean': round(float(diff[:,i].mean()),6),
                              'max':  round(float(diff[:,i].max()), 6)}
                    for i in range(7)},
        'affected_cols': affected,
        'note': 'Scaler was fit on Python-version (log1p only [0,1,2,6]). '
                'C++ applies log1p to all 7 cols before scaling. '
                'Cols 3,4,5 are scaled with wrong scaler params.'
    }

    out = BASE / 'results' / 'generalization' / 'phase1' / 'dos_aggregator' / 'log1p_consistency.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
