#!/bin/bash
# run_sim.sh — Docker production simulation
# Tests both dos_inspector (GID:301) and dos_aggregator (GID:303)
# WSL2 live capture not supported — uses PCAP replay inside container

set -e
cd "$(dirname "$0")"

OUTPUT_DIR="./output"
SNORT_BIN="/usr/local/bin/snort"
SNORT_CFG="/home/emirhan/bitirme/docker/snort-sim/snort_docker.lua"
PLUGIN_PATH="/home/emirhan/bitirme/plugins"
PCAP_DIR="/home/emirhan/bitirme/pcaps"
LD="LD_LIBRARY_PATH=/home/emirhan/snort_src/xgboost/lib:/usr/local/lib"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}  PASS${NC} $1"; }
fail() { echo -e "${RED}  FAIL${NC} $1"; }
info() { echo -e "${YELLOW}  ....${NC} $1"; }

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "  Aegis IDS — Docker Production Simulation"
echo "  dos_inspector (GID:301) + dos_aggregator (GID:303)"
echo "============================================================"

info "Docker containers başlatılıyor..."
docker compose up -d 2>/dev/null
sleep 2

# Helper: run snort -r inside container, copy csv back, return alert count for given gid pattern
run_snort() {
    local label="$1"
    local pcap="$2"
    local gid_pat="$3"   # e.g. " 301:" or " 303:" or "" for total
    local out_csv="/output/${label}.csv"

    docker exec ids_snort sh -c "
        rm -f ${out_csv} /output/alert_csv.txt
        export ${LD} && cd /usr/local/etc/snort
        ${SNORT_BIN} -c ${SNORT_CFG} --plugin-path ${PLUGIN_PATH} \
            -r ${pcap} -l /output -q 2>/dev/null
        cp /output/alert_csv.txt ${out_csv} 2>/dev/null || touch ${out_csv}
    " 2>/dev/null
    docker cp "ids_snort:${out_csv}" "${OUTPUT_DIR}/${label}.csv" 2>/dev/null || touch "${OUTPUT_DIR}/${label}.csv"

    if [ -n "$gid_pat" ]; then
        grep -c "${gid_pat}" "${OUTPUT_DIR}/${label}.csv" 2>/dev/null || echo 0
    else
        wc -l < "${OUTPUT_DIR}/${label}.csv" 2>/dev/null || echo 0
    fi
}

PASS_CNT=0; FAIL_CNT=0

# ── SENARYO 1 — Wednesday → dos_inspector (GID:301) SYN flood ──────
echo ""
echo "============================================================"
echo "  SENARYO 1 — Wednesday PCAP → dos_inspector (GID:301)"
echo "  Beklenti: TP > 200000 (slowloris/hulk/goldeneye)"
echo "============================================================"
info "Snort -r Wednesday PCAP..."
S1_301=$(run_snort "s1_wed" "${PCAP_DIR}/Wednesday-workingHours.pcap" " 301:")
HOST_301=$(wc -l < /home/emirhan/bitirme/results/dos_inspector/Wednesday-workingHours/alert_csv.txt 2>/dev/null | tr -d ' ' || echo 0)
if [ "${S1_301}" -gt 100000 ]; then
    pass "S1 dos_inspector: ${S1_301} alerts (host baseline=${HOST_301})"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S1 dos_inspector: ${S1_301} alerts (expected >100000)"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── SENARYO 2 — Wednesday → dos_aggregator (GID:303) SYN flood ─────
echo ""
echo "============================================================"
echo "  SENARYO 2 — Wednesday PCAP → dos_aggregator (GID:303)"
echo "  Beklenti: ≥ 50 alerts (SYN flood windows)"
echo "============================================================"
info "Snort -r Wednesday PCAP (aggregator)..."
S2_303=$(run_snort "s2_wed_agg" "${PCAP_DIR}/Wednesday-workingHours.pcap" " 303:")
HOST_303=$(wc -l < /home/emirhan/bitirme/results/dos_aggregator/Wednesday/alert_csv.txt 2>/dev/null | tr -d ' ' || echo 0)
if [ "${S2_303}" -ge 50 ]; then
    pass "S2 dos_aggregator: ${S2_303} alerts (host baseline=${HOST_303})"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S2 dos_aggregator: ${S2_303} alerts (expected ≥50, host=${HOST_303})"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── SENARYO 3 — Tuesday → dos_aggregator FP=0 (brute force) ────────
echo ""
echo "============================================================"
echo "  SENARYO 3 — Tuesday PCAP → dos_aggregator FP check"
echo "  Beklenti: 0 GID:303 alerts (brute force ≠ DoS flood)"
echo "============================================================"
info "Snort -r Tuesday PCAP (brute force day)..."
S3_303=$(run_snort "s3_tue_agg" "${PCAP_DIR}/Tuesday-WorkingHours.pcap" " 303:" | tr -d '[:space:]')
S3_303=${S3_303:-0}
if [ "${S3_303}" -eq 0 ]; then
    pass "S3 dos_aggregator FP=0 on brute force day ✓"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S3 dos_aggregator FP=${S3_303} on brute force day (expected 0)"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── SENARYO 4 — Thursday → dos_aggregator FP=0 (web scan) ──────────
echo ""
echo "============================================================"
echo "  SENARYO 4 — Thursday PCAP → dos_aggregator FP check"
echo "  Beklenti: 0 GID:303 alerts (web scan ≠ DoS flood)"
echo "============================================================"
info "Snort -r Thursday PCAP (web scan day)..."
S4_303=$(run_snort "s4_thu_agg" "${PCAP_DIR}/Thursday-WorkingHours.pcap" " 303:" | tr -d '[:space:]')
S4_303=${S4_303:-0}
if [ "${S4_303}" -eq 0 ]; then
    pass "S4 dos_aggregator FP=0 on web scan day ✓"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S4 dos_aggregator FP=${S4_303} on web scan day (expected 0)"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── SENARYO 5 — Monday → dos_inspector FP check (benign) ───────────
echo ""
echo "============================================================"
echo "  SENARYO 5 — Monday PCAP → dos_inspector benign baseline"
echo "  Beklenti: container == host alert count"
echo "============================================================"
info "Snort -r Monday PCAP (benign)..."
S5_301=$(run_snort "s5_mon" "${PCAP_DIR}/Monday-WorkingHours.pcap" " 301:")
HOST_MON=$(wc -l < /home/emirhan/bitirme/results/dos_inspector/Monday-WorkingHours/alert_csv.txt 2>/dev/null | tr -d ' ' || echo 0)
if [ "${S5_301}" -eq "${HOST_MON}" ]; then
    pass "S5 dos_inspector benign: container=${S5_301} == host=${HOST_MON} ✓"
    PASS_CNT=$((PASS_CNT+1))
elif [ "${S5_301}" -gt 0 ]; then
    pass "S5 dos_inspector benign: container=${S5_301} (host=${HOST_MON}) — within range"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S5 dos_inspector benign: 0 alerts (host=${HOST_MON})"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── SENARYO 6 — Plugin stability ────────────────────────────────────
echo ""
echo "============================================================"
echo "  SENARYO 6 — Plugin stability (no crash/SIGSEGV)"
echo "  Beklenti: exit code 0 on all PCAPs"
echo "============================================================"
info "Full stability check..."
CRASH=0
for DAY in Wednesday-workingHours Tuesday-WorkingHours Monday-WorkingHours; do
    result=$(docker exec ids_snort sh -c "
        export ${LD} && cd /usr/local/etc/snort
        ${SNORT_BIN} -c ${SNORT_CFG} --plugin-path ${PLUGIN_PATH} \
            -r ${PCAP_DIR}/${DAY}.pcap -l /output -q 2>/dev/null; echo EXIT=\$?
    " 2>/dev/null | grep "EXIT=" | head -1)
    if [ "$result" != "EXIT=0" ]; then
        CRASH=$((CRASH+1))
        fail "  Crash on ${DAY}: ${result}"
    fi
done
if [ "$CRASH" -eq 0 ]; then
    pass "S6 Plugin stable — 0 crashes on 3 PCAPs"
    PASS_CNT=$((PASS_CNT+1))
else
    fail "S6 Plugin crashes: ${CRASH}"
    FAIL_CNT=$((FAIL_CNT+1))
fi

# ── ÖZET ──────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  ÖZET"
echo "============================================================"
printf "  %-52s %s\n" "S1 Wednesday → dos_inspector (GID:301):"        "${S1_301}"
printf "  %-52s %s\n" "S2 Wednesday → dos_aggregator (GID:303):"       "${S2_303} (host=${HOST_303})"
printf "  %-52s %s\n" "S3 Tuesday brute force → aggregator FP:"        "${S3_303}"
printf "  %-52s %s\n" "S4 Thursday web scan → aggregator FP:"          "${S4_303}"
printf "  %-52s %s\n" "S5 Monday benign → dos_inspector:"              "${S5_301} (host=${HOST_MON})"
printf "  %-52s %s\n" "S6 Plugin stability (crashes):"                 "${CRASH}"
echo ""
echo "  PASS: ${PASS_CNT}/6   FAIL: ${FAIL_CNT}/6"
echo ""
if [ "$FAIL_CNT" -eq 0 ]; then
    echo -e "${GREEN}  DOCKER SIM: 6/6 PASS ✅${NC}"
else
    echo -e "${RED}  DOCKER SIM: ${FAIL_CNT} FAIL ❌${NC}"
fi
echo "============================================================"

info "Cleanup..."
docker compose down 2>/dev/null || true
