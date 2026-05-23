#!/bin/bash
# run_dos_feature_dump.sh — Snort feature dump for CIC days
# threshold=0.0 → ALL flows dumped with v2 model (17 features)
# Output: data/snort_dump/<day>_features.csv

set -e
BASE_DIR="$HOME/bitirme"
DUMP_DIR="$BASE_DIR/data/snort_dump"
PLUGIN_PATH="$BASE_DIR/plugins/dos_inspector/build"
CFG_TEMPLATE="$BASE_DIR/configs/snort_dos_dump.lua"
PCAP_DIR="$BASE_DIR/pcaps"
LD_SETUP="LD_LIBRARY_PATH=/home/emirhan/snort_src/xgboost/lib:/usr/local/lib"

mkdir -p "$DUMP_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${YELLOW}....${NC} $1"; }
pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; }

# day_key → pcap filename (must match ~/bitirme/pcaps/)
declare -A PCAP_MAP=(
    ["Monday"]="Monday-WorkingHours.pcap"
    ["Tuesday"]="Tuesday-WorkingHours.pcap"
    ["Wednesday"]="Wednesday-workingHours.pcap"
    ["Thursday-Morning"]="Thursday-WorkingHours-Morning-Web-Attacks.pcap"
    ["Thursday-Afternoon"]="Thursday-WorkingHours-Afternoon-Infilteration.pcap"
    ["Friday-Morning"]="Friday-WorkingHours-Morning.pcap"
    ["Friday-DDos"]="Friday-WorkingHours-Afternoon-DDos.pcap"
    ["Friday-PortScan"]="Friday-WorkingHours-Afternoon-PortScan.pcap"
)

echo "============================================================"
echo "  DoS Feature Dump — CIC Days (v2 model, 17 features)"
echo "  threshold=0.0 → ALL flows written to CSV"
echo "============================================================"

TOTAL_PASS=0; TOTAL_FAIL=0

for DAY_KEY in Monday Wednesday Tuesday Thursday-Morning Thursday-Afternoon Friday-Morning Friday-DDos Friday-PortScan; do
    PCAP_FILE="${PCAP_MAP[$DAY_KEY]}"
    PCAP_PATH="$PCAP_DIR/$PCAP_FILE"
    DUMP_OUT="$DUMP_DIR/${DAY_KEY}_features.csv"
    ALERT_TMP="/tmp/snort_dump_alert_${DAY_KEY}"

    if [ ! -f "$PCAP_PATH" ]; then
        info "PCAP not found: $PCAP_FILE — skipping"
        continue
    fi

    info "[$DAY_KEY] Replaying $PCAP_FILE..."
    mkdir -p "$ALERT_TMP"

    TMP_CFG="/tmp/snort_dos_dump_${DAY_KEY}.lua"
    sed "s|dump_placeholder.csv|${DAY_KEY}_features.csv|g" "$CFG_TEMPLATE" \
        | sed "s|/home/emirhan/bitirme/data/snort_dump/|${DUMP_DIR}/|g" \
        > "$TMP_CFG"

    cd /usr/local/etc/snort
    eval "$LD_SETUP snort \
        -c '$TMP_CFG' \
        --plugin-path '$PLUGIN_PATH' \
        -r '$PCAP_PATH' \
        -l '$ALERT_TMP' -q" 2>/dev/null

    if [ -f "$DUMP_OUT" ]; then
        LINES=$(( $(wc -l < "$DUMP_OUT") - 1 ))  # exclude header
        pass "[$DAY_KEY] $LINES flows → $DUMP_OUT"
        TOTAL_PASS=$((TOTAL_PASS+1))
    else
        fail "[$DAY_KEY] dump not created"
        TOTAL_FAIL=$((TOTAL_FAIL+1))
    fi
done

echo ""
echo "============================================================"
echo "  PASS: $TOTAL_PASS   FAIL: $TOTAL_FAIL"
echo "  Next: python3 scripts/label_dos_dump.py"
echo "============================================================"
