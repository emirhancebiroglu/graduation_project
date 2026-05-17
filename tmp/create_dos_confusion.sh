#!/bin/bash
cd /home/emirhan/bitirme/scripts
for f in xgb_flowid_confusion.py xgb_flowid_confusion_wednesday.py xgb_flowid_confusion_friday.py; do
    newf="${f/xgb/dos}"
    cp "$f" "$newf"
    sed -i 's|xgb_inspector|dos_inspector|g' "$newf"
    sed -i 's|results/xgboost|results/dos_inspector|g' "$newf"
    sed -i 's|XGBoost|DoS|g' "$newf"
    echo "Created: $newf"
    rm "$f"
done
echo "Old xgb scripts removed"
ls -la dos_flowid_*
