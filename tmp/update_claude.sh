#!/bin/bash
sed -i 's|fine_tuned_xgb_model.json|dos_model.json|g' /home/emirhan/bitirme/CLAUDE.md
sed -i 's|snort_xgb.lua|snort_dos.lua|g' /home/emirhan/bitirme/CLAUDE.md
sed -i 's|xgb_inspector/|dos_inspector/|g' /home/emirhan/bitirme/CLAUDE.md
sed -i 's|XGBoost anomaly|DoS per-flow|g' /home/emirhan/bitirme/CLAUDE.md
sed -i 's|xgb_flowid_confusion|dos_flowid_confusion|g' /home/emirhan/bitirme/CLAUDE.md
sed -i 's|results/xgboost/|results/dos_inspector/|g' /home/emirhan/bitirme/CLAUDE.md
echo "CLAUDE.md updated"
