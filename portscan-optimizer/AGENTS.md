# PortScan Classifier Optimizer — Project Context

## Project Goal
Train a PortScan attack detector using CICIDS 2017 Friday data that achieves:
- Recall >= 0.99
- Precision >= 0.98
- F1-Score >= 0.98
- FPR <= 0.01

## Dataset Files
- `data/friday_portscan.csv` — CICIDS 2017 Friday (Morning=Benign, Afternoon-DDoS, Afternoon-PortScan)
- `data/wednesday.csv` — CICIDS 2017 Wednesday (DoS/DDoS traffic, use as extra negative samples)

## Feature Columns (84 total)
Flow ID, Source IP, Source Port, Destination IP, Timestamp → DROP THESE
All other columns → features
Label column → target (PortScan=1, all others=0)

## Critical Data Facts
- Friday CSV has DDoS mixed in — this causes high FPR if model not trained on DDoS
- Label values need .str.strip() — there are leading/trailing spaces in raw CSV
- Some features have inf values — replace with NaN then fillna(0)
- Class imbalance: PortScan is minority class

## Reference Model (DoS Specialist)
- Architecture: XGBoost pretrained on UNSW dataset, fine-tuned on 10% CICIDS
- Location: models/dos_specialist/
- Achieved all 4 targets on Wednesday data

## Locked Test Split
test_size=0.2, random_state=42, stratify=y
THIS NEVER CHANGES. All tuning on train split only.

## Directory Structure
- src/          → Python training scripts (one per iteration: train_iter_0.py, etc.)
- models/       → Saved model files (model_iter_0.pkl, etc.)
- results/      → metrics.json (current best), history.jsonl (all iterations)
- data/         → CSV files

## Iteration History
See results/history.jsonl for all previous attempts.
See results/metrics.json for the latest result.