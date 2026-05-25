#!/bin/bash
# eval_bruteforce_generalization.sh — Phase 2 generalization test
# Tests: CIC Tuesday (attack), CIC Monday (benign), synthetic PCAPs

set -e

SNORT_ETC="/usr/local/etc/snort"
PLUGIN_PATH="$HOME/bitirme/plugins/bruteforce_inspector/build"
CFG="$HOME/bitirme/configs/snort_bruteforce.lua"
PCAP_DIR="$HOME/bitirme/pcaps"
SYNTH_DIR="$HOME/bitirme/pcaps/synthetic_bruteforce"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

PASS=0
FAIL=0

echo "========================================="
echo " BruteForce Generalization Test (Phase 2)"
echo " Config: snort_bruteforce.lua (v2 model)"
echo "========================================="
echo ""

run_test() {
    local label="$1"
    local pcap="$2"
    local expected="$3"  # "pos" or "neg" or number
    local outdir="/tmp/bf_gen_$(echo "$label" | tr ' /' '__')"
    mkdir -p "$outdir"
    rm -f "$outdir/alert_csv.txt"

    cd "$SNORT_ETC" && snort -c "$CFG" --plugin-path "$PLUGIN_PATH" \
        -r "$pcap" -A alert_csv -l "$outdir" -q 2>&1 | grep '\[bruteforce\] ALERT' | head -3

    ALERTS=$(wc -l < "$outdir/alert_csv.txt" 2>/dev/null || echo 0)
    ALERTS=$(echo "$ALERTS" | tr -d ' ')

    if [ "$expected" = "neg" ]; then
        if [ "$ALERTS" -eq 0 ]; then
            STATUS="PASS (0 FP)"
            PASS=$((PASS + 1))
        else
            STATUS="FAIL ($ALERTS FP)"
            FAIL=$((FAIL + 1))
        fi
    elif [ "$expected" = "benign_ok" ]; then
        if [ "$ALERTS" -le 1 ]; then
            STATUS="PASS ($ALERTS FP)"
            PASS=$((PASS + 1))
        else
            STATUS="FAIL ($ALERTS FP)"
            FAIL=$((FAIL + 1))
        fi
    else
        # expect at least 1 alert
        if [ "$ALERTS" -ge 1 ]; then
            STATUS="PASS ($ALERTS alerts)"
            PASS=$((PASS + 1))
        else
            STATUS="FAIL (0 alerts)"
            FAIL=$((FAIL + 1))
        fi
    fi
    echo "  $label: $STATUS"
}

# CIC Tuesday — SSH+FTP Patator
if [ -f "$PCAP_DIR/Tuesday-WorkingHours.pcap" ]; then
    echo "--- CIC Days ---"
    run_test "Tuesday (attack)" "$PCAP_DIR/Tuesday-WorkingHours.pcap" "pos"
    run_test "Monday (benign)" "$PCAP_DIR/Monday-WorkingHours.pcap" "neg"
    run_test "Wednesday (benign)" "$PCAP_DIR/Wednesday-workingHours.pcap" "benign_ok"
fi

# Synthetic PCAPs
if [ -d "$SYNTH_DIR" ]; then
    echo ""
    echo "--- Synthetic PCAPs ---"
    for pcap in hydra_fast.pcap medusa_slow.pcap distributed_brute.pcap very_slow.pcap patator_fast.pcap ncrack_burst.pcap; do
        if [ -f "$SYNTH_DIR/$pcap" ]; then
            run_test "$pcap" "$SYNTH_DIR/$pcap" "pos"
        else
            echo "  $pcap: SKIP (not found)"
        fi
    done
fi

echo ""
echo "========================================="
echo " Results: $PASS PASS, $FAIL FAIL"
echo "========================================="
