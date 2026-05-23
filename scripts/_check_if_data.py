#!/usr/bin/env python3
import numpy as np, json
from pathlib import Path

BASE = Path('/home/emirhan/bitirme')

# portscan training data
Xp = np.load(BASE/'data/processed/portscan_v4d/X_train.npy')
yp = np.load(BASE/'data/processed/portscan_v4d/y_train.npy')
print(f"portscan X_train: {Xp.shape}, benign={( yp==0).sum()}, attack={(yp==1).sum()}")

Xpv = np.load(BASE/'data/processed/portscan_v4d/X_val.npy')
ypv = np.load(BASE/'data/processed/portscan_v4d/y_val.npy')
print(f"portscan X_val:   {Xpv.shape}, benign={(ypv==0).sum()}, attack={(ypv==1).sum()}")

# check bot_client model scaler
sc = json.load(open(BASE/'models/bot_client_model_scaler.json'))
print(f"bot_client scaler keys: {list(sc.keys())}")
print(f"bot_client n_features: {len(sc.get('median',[]))}")
print(f"bot_client log1p: {sc.get('log1p_indices','NONE')}")

# check dos_aggregator scaler
sc2 = json.load(open(BASE/'models/dos_aggregator_model_scaler.json'))
print(f"dos_agg scaler keys: {list(sc2.keys())}")
print(f"dos_agg log1p: {sc2.get('log1p_indices','NONE')}")
