#!/bin/bash
# sweep_maxpkts.sh — 1D max_packets sweep at the best threshold from task 02.
#
# BEST_T = 0.90 (task 02 result: lowest FPR=0.0193 with Recall=0.9998)
# max_packets=2 is already known (from sweep_threshold t090_mp2) → injected as baseline row.
#
# Usage: cd ~/bitirme && bash scripts/sweep_maxpkts.sh

set -e

SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
TEMPLATE_CONFIG="$HOME/bitirme/configs/snort_xgb.lua"
PCAP_PATH="$HOME/bitirme/pcaps/Wednesday-workingHours.pcap"
PLUGIN_PATH="$HOME/bitirme/plugins/xgb_inspector/build"
OUTPUT_BASE="$HOME/bitirme/results/xgboost/sweep_maxpkts"
CSV_DIR="$HOME/bitirme/data/raw/cicids2017"
SCRIPT_DIR="$HOME/bitirme/scripts"

XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

mkdir -p "$OUTPUT_BASE"
SUMMARY="$OUTPUT_BASE/summary.csv"
echo "threshold,max_packets,tp,tn,fp,fn,accuracy,precision,recall,f1,fpr" > "$SUMMARY"

# Inject mp=2 baseline row from task 02 sweep (t=0.90, mp=2) — no re-run needed.
echo "0.90,2,252610,431531,8500,62,0.9876,0.9674,0.9998,0.9833,0.0193" >> "$SUMMARY"

BEST_T="0.90"
MAX_PKTS=(3 4 5 6 8 10)

# Sanity checks
if [ ! -f "$PLUGIN_PATH/xgb_inspector.so" ]; then
    echo "ERROR: xgb_inspector.so not found at $PLUGIN_PATH"
    echo "Build first: cd ~/bitirme/plugins/xgb_inspector && ./build.sh"
    exit 1
fi
if [ ! -f "$XGBOOST_LIB/libxgboost.so" ]; then
    echo "ERROR: libxgboost.so not found at $XGBOOST_LIB"
    echo "Set XGBOOST_ROOT to the xgboost source directory."
    exit 1
fi
if [ ! -f "$PCAP_PATH" ]; then
    echo "ERROR: PCAP not found: $PCAP_PATH"
    exit 1
fi

echo "============================================="
echo " max_packets sweep  threshold=${BEST_T}"
echo " max_packets: ${MAX_PKTS[*]}"
echo " Output: $OUTPUT_BASE"
echo "============================================="

for mp in "${MAX_PKTS[@]}"; do
    T_TAG="${BEST_T//./}"
    RUN_NAME="t${T_TAG}_mp${mp}"
    RUN_DIR="$OUTPUT_BASE/$RUN_NAME"
    ALERT_DIR="$RUN_DIR/Wednesday-workingHours"
    mkdir -p "$ALERT_DIR"

    RUN_CONFIG="$RUN_DIR/snort_xgb.lua"
    sed \
        -e "s/threshold\s*=\s*[0-9.]*/threshold   = ${BEST_T}/" \
        -e "s/max_packets\s*=\s*[0-9]*/max_packets = ${mp}/" \
        "$TEMPLATE_CONFIG" > "$RUN_CONFIG"

    SNORT_LOG="$RUN_DIR/snort_stderr.log"

    echo ""
    echo "─────────────────────────────────────────────"
    echo " threshold=${BEST_T}  max_packets=${mp}  run=${RUN_NAME}"
    echo "─────────────────────────────────────────────"
    START_TIME=$(date +%s)

    cd "$SNORT_ETC" && $SNORT_BIN \
        -c "$RUN_CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP_PATH" \
        -A alert_csv \
        -l "$ALERT_DIR" \
        --warn-all \
        -q \
        2>"$SNORT_LOG"

    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    ALERT_COUNT=$(wc -l < "$ALERT_DIR/alert_csv.txt" 2>/dev/null || echo 0)
    echo " Done: ${ALERT_COUNT} alerts in ${ELAPSED}s"

    # Extract per-flow scores from stderr log if present
    grep '\[xgb_inspector\]' "$SNORT_LOG" 2>/dev/null \
        | grep 'score=' \
        | awk -F'score=' '{print $2}' \
        | awk '{print $1}' \
        > "$RUN_DIR/score_distribution.txt" || true
    SCORE_COUNT=$(wc -l < "$RUN_DIR/score_distribution.txt" 2>/dev/null || echo 0)
    echo " Score lines extracted: ${SCORE_COUNT}"

    cd "$SCRIPT_DIR"
    python3 xgb_flowid_confusion_wednesday.py \
        --alert-dir "$RUN_DIR" \
        --csv-dir "$CSV_DIR" \
        --output "$RUN_DIR/confusion_matrix.txt" \
        2>/dev/null

    python3 - "$RUN_DIR/confusion_matrix.txt" "$BEST_T" "$mp" >> "$SUMMARY" <<'PYEOF'
import re, sys

matrix_file, threshold, max_pkt = sys.argv[1], sys.argv[2], sys.argv[3]
with open(matrix_file, encoding='utf-8') as f:
    txt = f.read()

def grab_metric(label):
    m = re.search(rf"{label}:\s+([0-9.]+)", txt)
    return m.group(1) if m else "NA"

def grab_count(label):
    m = re.search(rf"{label}\s*=\s*([0-9]+)", txt)
    return m.group(1) if m else "NA"

row = ",".join([
    threshold, max_pkt,
    grab_count("TP"), grab_count("TN"), grab_count("FP"), grab_count("FN"),
    grab_metric("Accuracy"), grab_metric("Precision"),
    grab_metric("Recall \\(TPR\\)"), grab_metric("F1-Score"), grab_metric("FPR"),
])
print(row)
PYEOF

    echo " Row appended to summary.csv"
done

echo ""
echo "============================================="
echo " Sweep complete."
echo " Summary: $SUMMARY"
echo "============================================="
echo ""
cat "$SUMMARY"
