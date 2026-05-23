#!/bin/bash
# Update all script/config/doc references from xgb_inspector to dos_inspector
cd /home/emirhan/bitirme

echo "=== Updating scripts ==="
# run_xgb_replay.sh → run_dos_replay.sh
sed -i 's|xgb_replay|dos_replay|g' scripts/run_xgb_replay.sh
sed -i 's|XGBoost Replay|DoS Replay|g' scripts/run_xgb_replay.sh
sed -i 's|xgb_flowid_confusion_wednesday|dos_flowid_confusion_wednesday|g' scripts/run_xgb_replay.sh
sed -i 's|xgb_flowid_confusion_friday|dos_flowid_confusion_friday|g' scripts/run_xgb_replay.sh

# Update confusion scripts
sed -i 's|xgb_flowid_confusion|dos_flowid_confusion|g' scripts/dos_flowid_confusion_wednesday.py 2>/dev/null || true
sed -i 's|xgb_flowid_confusion|dos_flowid_confusion|g' scripts/dos_flowid_confusion_friday.py 2>/dev/null || true

echo "=== Updating docs ==="
sed -i 's|fine_tuned_xgb_model.json|dos_model.json|g' docs/PIPELINE.md 2>/dev/null || true
sed -i 's|snort_xgb.lua|snort_dos.lua|g' docs/commands.md 2>/dev/null || true
sed -i 's|results/xgboost|results/dos_inspector|g' docs/commands.md 2>/dev/null || true
sed -i 's|xgb_inspector\.cc|dos_inspector\.cc|g' docs/system-overview.md 2>/dev/null || true
sed -i 's|plugins/xgb_inspector|plugins/dos_inspector|g' docs/system-overview.md 2>/dev/null || true

echo "Done"
