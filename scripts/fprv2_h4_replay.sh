#!/bin/bash
# H4 replay for one variant.
# Usage: bash scripts/fprv2_h4_replay.sh <spw> <mcw>
# Example: bash scripts/fprv2_h4_replay.sh 0.5 5
set -e

SPW=$1
MCW=$2
if [ -z "$SPW" ] || [ -z "$MCW" ]; then
    echo "Usage: $0 <scale_pos_weight> <min_child_weight>"
    exit 1
fi

TAG="spw${SPW/./}_mcw${MCW}"
MODEL_FILE="$HOME/bitirme/models/fine_tuned_xgb_v2_h4_${TAG}.json"
RUN_DIR="$HOME/bitirme/results/xgboost/fpr-v2/H4/${TAG}"
ALERT_DIR="${RUN_DIR}/Wednesday-workingHours"
XGBOOST_LIB="$HOME/snort_src/xgboost/lib"

export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

if [ ! -f "$MODEL_FILE" ]; then
    echo "ERROR: model not found: $MODEL_FILE"
    exit 1
fi

mkdir -p "$ALERT_DIR"

# Swap model path in config, run replay, restore
CFG="$HOME/bitirme/configs/snort_xgb.lua"
ORIG_LINE='model_path  = "/home/emirhan/bitirme/models/fine_tuned_xgb_model.json"'
NEW_LINE="model_path  = \"${MODEL_FILE}\""

sed -i "s|${ORIG_LINE}|${NEW_LINE}|" "$CFG"

echo "======================================="
echo " H4 Replay: spw=${SPW} mcw=${MCW}"
echo " Model: $(basename $MODEL_FILE)"
echo "======================================="

START=$(date +%s)
cd /usr/local/etc/snort && snort \
    -c "$CFG" \
    --plugin-path "$HOME/bitirme/plugins/xgb_inspector/build" \
    -r "$HOME/bitirme/pcaps/Wednesday-workingHours.pcap" \
    -A alert_csv \
    -l "$ALERT_DIR" \
    --warn-all -q \
    2>"${RUN_DIR}/snort_stderr.log"
END=$(date +%s)

# Restore config immediately
sed -i "s|${NEW_LINE}|${ORIG_LINE}|" "$CFG"

ALERTS=$(wc -l < "${ALERT_DIR}/alert_csv.txt" 2>/dev/null || echo 0)
echo "Done: ${ALERTS} alerts in $((END-START))s"

# Score
cd "$HOME/bitirme" && source venv/bin/activate
python scripts/xgb_flowid_confusion_wednesday.py \
    --alert-dir "$RUN_DIR" \
    --csv-dir   "$HOME/bitirme/data/raw/cicids2017" \
    --output    "${RUN_DIR}/confusion_matrix.txt" \
    2>/dev/null

echo ""
cat "${RUN_DIR}/confusion_matrix.txt"
