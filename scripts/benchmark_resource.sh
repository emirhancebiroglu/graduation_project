#!/bin/bash
# scripts/benchmark_resource.sh — Snort3 ML Plugin Resource Benchmark
# Measures CPU%, RSS, and alert throughput across scenarios.
# Usage: bash scripts/benchmark_resource.sh
set -euo pipefail

# ─── Configuration ───
BASE_DIR="$HOME/bitirme"
CONFIG_DIR="$BASE_DIR/configs"
PLUGIN_DIR="$BASE_DIR/plugins"
PCAP="$BASE_DIR/pcaps/Wednesday-workingHours.pcap"
RESULTS_DIR="$BASE_DIR/results/benchmark"
SNORT_ETC="/usr/local/etc/snort"
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"

# ─── Tool Check ───
for cmd in snort bc python3 ps; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FATAL: $cmd not found. Install it first."
        case "$cmd" in
            bc) echo "  apt install bc" ;;
            python3) echo "  apt install python3" ;;
        esac
        exit 1
    fi
done

if [ ! -f "$PCAP" ]; then
    echo "FATAL: PCAP not found: $PCAP"
    exit 1
fi

export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH:-}"
mkdir -p "$RESULTS_DIR"

# ─── Cleanup Handler ───
SNORT_PID=""
MONITOR_PID=""

cleanup() {
    kill "$MONITOR_PID" 2>/dev/null || true
    kill "$SNORT_PID" 2>/dev/null || true
    pkill -x snort 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ─── Run Single Scenario (offline -r mode) ───
run_scenario() {
    local name=$1 config=$2 plugin_path=$3
    local workdir="/tmp/snort_bench_${name}"

    echo ""
    echo "=============================================="
    echo " Scenario $name"
    echo "=============================================="
    echo " Config:  $config"
    echo " Plugins: $plugin_path"
    echo ""

    [ -f "$config" ] || { echo "SKIP: config not found"; return 1; }

    rm -rf "$workdir"
    mkdir -p "$workdir"

    # Kill leftover snort
    pkill -x snort 2>/dev/null || true
    sleep 1

    # ── Start snort (offline mode) ──
    echo " [*] Starting snort (offline -r)..."
    cd "$SNORT_ETC"
    SNORT_START_TS=$(date +%s)
    snort -c "$config" \
        -r "$PCAP" \
        -A alert_csv \
        -l "$workdir" \
        --plugin-path "$plugin_path" \
        -q \
        2>/dev/null &
    SNORT_PID=$!

    # Verify snort started
    sleep 3
    if ! kill -0 "$SNORT_PID" 2>/dev/null; then
        echo " FAIL: snort died on startup"
        return 1
    fi

    # ── Monitor via /proc (no root needed, captures all threads) ──
    local res_file="/tmp/bench_res_${name}.txt"
    echo " [*] Monitoring PID $SNORT_PID (via /proc)..."
    > "$res_file"
    (
        while kill -0 "$SNORT_PID" 2>/dev/null; do
            ts=$(date +%s)
            cpu=$(ps -p "$SNORT_PID" -o %cpu= --no-headers 2>/dev/null || echo "0")
            rss_kb=$(grep VmRSS "/proc/$SNORT_PID/status" 2>/dev/null | awk '{print $2}' || echo "0")
            echo "$ts $cpu $rss_kb" >> "$res_file"
            sleep 1
        done
    ) &
    MONITOR_PID=$!

    # ── Wait for snort to finish ──
    echo " [*] Waiting for snort to process PCAP..."
    wait "$SNORT_PID" 2>/dev/null || true
    SNORT_END_TS=$(date +%s)

    echo " [*] Snort finished. Stopping monitor..."
    kill "$MONITOR_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    SNORT_PID=""

    # ── Actual duration ──
    local actual_duration=$(( SNORT_END_TS - SNORT_START_TS ))
    [ "$actual_duration" -lt 1 ] && actual_duration=1

    # ── Parse monitoring data via awk ──
    local cpu_avg=0 cpu_peak=0 rss_avg=0 rss_peak=0
    if [ -s "$res_file" ]; then
        read cpu_avg cpu_peak rss_avg rss_peak samples <<< $(
            awk '
            { cpu_sum+=$2; rss_sum+=$3; if($2>cpu_p) cpu_p=$2; if($3>rss_p) rss_p=$3; n++ }
            END {
                if(n>0) printf "%.1f %.1f %d %d %d", cpu_sum/n, cpu_p, rss_sum/n/1024, rss_p/1024, n
                else print "0 0 0 0 0"
            }
            ' "$res_file"
        )
        echo "   Samples: $samples"
    fi

    # ── Count alerts ──
    local alert_csv="$workdir/alert_csv.txt"
    local alert_count=0
    [ -f "$alert_csv" ] && alert_count=$(wc -l < "$alert_csv")

    local alerts_per_sec
    alerts_per_sec=$(echo "scale=2; $alert_count / $actual_duration" | bc)

    # ── Save JSON ──
    python3 -c "
import json, sys
n, du, ca, cp, ra, rp, ac, aps, out = sys.argv[1:];
json.dump({
    'scenario': n, 'duration_s': int(du),
    'cpu_avg': float(ca), 'cpu_peak': float(cp),
    'rss_avg_mb': float(ra), 'rss_peak_mb': float(rp),
    'alert_count': int(ac), 'alerts_per_sec': float(aps)
}, open(out, 'w'), indent=2)
" "$name" "$actual_duration" "$cpu_avg" "$cpu_peak" "$rss_avg" "$rss_peak" "$alert_count" "$alerts_per_sec" "$RESULTS_DIR/scenario_${name}.json"

    echo ""
    echo " Results (duration=${actual_duration}s):"
    echo "   CPU avg=${cpu_avg}%  peak=${cpu_peak}%"
    echo "   RSS  avg=${rss_avg}MB peak=${rss_peak}MB"
    echo "   Alerts: $alert_count (${alerts_per_sec}/s)"
}

# ═══════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════

echo "╔══════════════════════════════════════════════╗"
echo "║   Snort3 ML Plugin Resource Benchmark        ║"
echo "║   PCAP: $PCAP"
echo "║   Mode: offline (-r) per scenario            ║"
echo "╚══════════════════════════════════════════════╝"

# ── Scenario A: dos_inspector only ──
run_scenario "A" \
    "$CONFIG_DIR/snort_dos.lua" \
    "$PLUGIN_DIR/dos_inspector/build"

# ── Scenario B: Combined ML-only (SKIP) ──
echo ""
echo "=============================================="
echo " Scenario B — SKIPPED"
echo "=============================================="
echo " No combined-ML-only config exists."
echo " snort_combined.lua hardcodes community rules"
echo " via combined_rules.rules include."
echo ""
python3 -c "
import json
json.dump({'scenario':'B','skipped':True,'note':'No combined-ML-only config exists - snort_combined.lua hardcodes community_rules include'}, open('$RESULTS_DIR/scenario_B.json','w'), indent=2)
"

# ── Scenario C: Full combined (5 ML + community) ──
C_PLUGINS="$PLUGIN_DIR/dos_inspector/build"
C_PLUGINS="${C_PLUGINS}:$PLUGIN_DIR/portscan_inspector/build"
C_PLUGINS="${C_PLUGINS}:$PLUGIN_DIR/dos_aggregator/build"
C_PLUGINS="${C_PLUGINS}:$PLUGIN_DIR/bot_client_inspector/build"
C_PLUGINS="${C_PLUGINS}:$PLUGIN_DIR/bruteforce_inspector/build"

run_scenario "C" \
    "$CONFIG_DIR/snort_combined.lua" \
    "$C_PLUGINS"

# ═══════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║               SUMMARY                        ║"
echo "╚══════════════════════════════════════════════╝"

generate_summary() {
    local json_a="$RESULTS_DIR/scenario_A.json"
    local json_b="$RESULTS_DIR/scenario_B.json"
    local json_c="$RESULTS_DIR/scenario_C.json"

    if [ -f "$json_a" ] && [ -f "$json_c" ]; then
        python3 -c "
import json, os
scenarios = {}
for s in ['A','B','C']:
    fp = '$RESULTS_DIR/scenario_' + s + '.json'
    if os.path.exists(fp):
        with open(fp) as f:
            scenarios[s] = json.load(f)
    else:
        scenarios[s] = {'scenario': s, 'error': 'file not found'}
out = {
    'summary': 'Snort3 ML Plugin Resource Benchmark',
    'date': __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'pcap': '$PCAP',
    'duration_s': 'per-scenario',
    'scenarios': scenarios
}
with open('$RESULTS_DIR/summary.json','w') as f:
    json.dump(out, f, indent=2)
"
    fi

    echo ""
    printf "%-12s %10s %10s %10s %10s %12s %12s\n" \
        "Scenario" "CPU avg%" "CPU peak%" "RSS avg(MB)" "RSS peak(MB)" "Alerts" "Alerts/sec"
    echo "──────────────────────────────────────────────────────────────────────────────────────"

    local label_a="A (dos_only)"
    local label_b="B (ML-only)"
    local label_c="C (combined)"

    if [ -f "$json_a" ]; then
        python3 -c "
import json
with open('$json_a') as f:
    d = json.load(f)
print(f\"{d['cpu_avg']} {d['cpu_peak']} {d['rss_avg_mb']} {d['rss_peak_mb']} {d['alert_count']} {d['alerts_per_sec']}\")
" | while read -r ca cp ra rp ac aps; do
            printf "%-12s %10.1f %10.1f %10.0f %10.0f %12d %12.1f\n" \
                "$label_a" "$ca" "$cp" "$ra" "$rp" "$ac" "$aps"
        done
    fi

    echo "  (skipped)  —   —   —   —   —   —"

    if [ -f "$json_c" ]; then
        python3 -c "
import json
with open('$json_c') as f:
    d = json.load(f)
print(f\"{d['cpu_avg']} {d['cpu_peak']} {d['rss_avg_mb']} {d['rss_peak_mb']} {d['alert_count']} {d['alerts_per_sec']}\")
" | while read -r ca cp ra rp ac aps; do
            printf "%-12s %10.1f %10.1f %10.0f %10.0f %12d %12.1f\n" \
                "$label_c" "$ca" "$cp" "$ra" "$rp" "$ac" "$aps"
        done
    fi

    echo ""
    echo "Results saved to: $RESULTS_DIR/"
}

generate_summary

echo ""
echo "Done."
