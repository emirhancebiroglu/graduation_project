# PortScan Classifier Optimizer — Project Context

## Goal
Train a PortScan specialist XGBoost model that achieves ALL targets in ONLINE Snort evaluation:
- Recall >= 0.99, Precision >= 0.98, F1-Score >= 0.98, FPR <= 0.01

## Critical: Online vs Offline
**Offline** = sklearn on CSV features. **Online** = Snort plugin on PCAP replay.
We target ONLINE. Offline is only a training direction guide.

## The 11 Plugin Features (UNSW-style)
dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz, swin, dwin, sintpkt, dintpkt

## CICIDS → UNSW Mapping + Unit Conversions
Flow Duration          → dur       (/1e6: µs→s)
Total Fwd Packets      → spkts
Total Backward Packets → dpkts
Total Length Fwd Pkts  → sbytes
Total Length Bwd Pkts  → dbytes
Fwd Packet Length Mean → smeansz
Bwd Packet Length Mean → dmeansz
Init_Win_bytes_forward → swin
Init_Win_bytes_backward→ dwin
Fwd IAT Mean           → sintpkt   (/1e3: µs→ms)
Bwd IAT Mean           → dintpkt   (/1e3: µs→ms)

## Preprocessing Pipeline (must match C++ plugin exactly)
1. Map 11 features + unit conversions
2. log1p on: dur, spkts, dpkts, sbytes, dbytes, sintpkt, dintpkt
3. RobustScaler → median/IQR hardcoded in portscan_inspector.cc

## Scaler Patching (every iteration)
Train → results/portscan/scaler_params.json → patch_and_build.sh patches .cc → recompile

## Dataset Labels
Friday Morning: Benign + Bot | Friday Aft-DDoS: DDoS | Friday Aft-PortScan: PortScan
Wednesday: DoS (extra negatives when needed)
Positive class: PortScan=1, everything else=0

## Reference: DoS model
~/bitirme/models/fine_tuned_xgb_model.json — threshold=0.90, max_packets=2
Use as fine-tune base: --finetune-from ~/bitirme/models/fine_tuned_xgb_model.json

## Locked Test Split
test_size=0.2, random_state=42, stratify=y — NEVER CHANGE