#!/bin/bash
# portscan_gate_sweep.sh
# Gate sweep: min_dst_ports × threshold → Friday window recall + benign FP check
# Usage: bash scripts/portscan_gate_sweep.sh

set -e
cd /usr/local/etc/snort

export XGBOOST_LIB=$HOME/snort_src/xgboost/lib
export LD_LIBRARY_PATH=${XGBOOST_LIB}:${LD_LIBRARY_PATH}

PLUGIN_PATH="$HOME/bitirme/plugins/portscan_inspector/build"
MODEL_PATH="$HOME/bitirme/models/portscan_aggregator_model_v4d.json"
PCAP_FRIDAY="$HOME/bitirme/pcaps/Friday-WorkingHours.pcap"
PCAP_MONDAY="$HOME/bitirme/pcaps/Monday-WorkingHours.pcap"
PCAP_THURSDAY="$HOME/bitirme/pcaps/Thursday-WorkingHours.pcap"
RESULTS_DIR="$HOME/bitirme/results/portscan/gate_sweep"

mkdir -p "$RESULTS_DIR"

# Sweep parameters
MIN_PORTS_LIST=(10 15 20 25 30)
THRESHOLD_LIST=(0.90 0.93 0.95)

SUMMARY="$RESULTS_DIR/summary.csv"
echo "min_dst_ports,threshold,friday_scanner_alerts,friday_scanner_windows,friday_recall,friday_fp,monday_fp,thursday_fp" > "$SUMMARY"

write_config() {
    local cfg_path=$1
    local thr=$2
    local mdp=$3
    cat > "$cfg_path" << LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
include 'snort_defaults.lua'
stream = {}
stream_ip = {}
stream_icmp = {}
stream_tcp = {}
stream_udp = {}
stream_user = {}
stream_file = {}
arp_spoof = {}
back_orifice = {}
dns = {}
imap = {}
netflow = {}
normalizer = {}
pop = {}
rpc_decode = {}
sip = {}
socks = {}
ssh = {}
ssl = {}
telnet = {}
cip = {}
dnp3 = {}
iec104 = {}
mms = {}
modbus = {}
opcua = {}
s7commplus = {}
dce_smb = {}
dce_tcp = {}
dce_udp = {}
dce_http_proxy = {}
dce_http_server = {}
gtp_inspect = default_gtp
port_scan = default_med_port_scan
smtp = default_smtp
ftp_server = default_ftp_server
ftp_client = {}
ftp_data = {}
http_inspect = {}
http2_inspect = {}
file_inspect = { rules_file = 'file_magic.rules' }
file_policy = {}
js_norm = default_js_norm
appid = {}
wizard = default_wizard
binder = {
    { when = { proto = 'udp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111', role='server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502', role='server' }, use = { type = 'modbus' } },
    { when = { service = 'http' },  use = { type = 'http_inspect' } },
    { when = { service = 'http2' }, use = { type = 'http2_inspect' } },
    { when = { service = 'ssh' },   use = { type = 'ssh' } },
    { when = { service = 'ssl' },   use = { type = 'ssl' } },
    { when = { service = 'smtp' },  use = { type = 'smtp' } },
    { when = { service = 'dns' },   use = { type = 'dns' } },
    { use = { type = 'wizard' } }
}
references = default_references
classifications = default_classifications
ips = {
    include = '/home/emirhan/bitirme/configs/portscan_rules.rules',
    variables = default_variables
}
alert_csv = { file = true, }
portscan_inspector = {
    threshold     = $thr,
    model_path    = "$MODEL_PATH",
    window_sec    = 60,
    min_packets   = 5,
    min_dst_ports = $mdp,
}
LUAEOF
}

run_snort() {
    local pcap=$1
    local out_dir=$2
    local thr=$3
    local mdp=$4

    mkdir -p "$out_dir"
    rm -f "$out_dir"/alert_csv.txt "$out_dir"/snort_output.log

    local tmp_cfg="$out_dir/snort_cfg.lua"
    write_config "$tmp_cfg" "$thr" "$mdp"

    snort -c "$tmp_cfg" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$pcap" \
        -A alert_csv -l "$out_dir" \
        --warn-all > "$out_dir/snort_output.log" 2>&1 || true
}

count_ip_alerts() {
    local alert_csv=$1
    local target_ip=$2
    local match_mode=$3  # "eq" or "neq"
    if [ ! -f "$alert_csv" ]; then echo "0"; return; fi
    python3 - "$alert_csv" "$target_ip" "$match_mode" << 'PYEOF'
import sys
alert_csv, target_ip, match_mode = sys.argv[1], sys.argv[2], sys.argv[3]
count = 0
with open(alert_csv) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) > 3:
            src = parts[3].strip()
            if match_mode == "eq" and src == target_ip:
                count += 1
            elif match_mode == "neq" and src != target_ip:
                count += 1
print(count)
PYEOF
}

echo "=== PortScan Gate Sweep ==="
echo "Model: portscan_aggregator_model_v4d.json"
echo "Params: min_dst_ports in {${MIN_PORTS_LIST[*]}}, threshold in {${THRESHOLD_LIST[*]}}"
echo "3 PCAPs per combo: Friday (attack), Monday (benign), Thursday (web attacks)"
echo ""

FRIDAY_SCANNER_WINDOWS=37

for mdp in "${MIN_PORTS_LIST[@]}"; do
    for thr in "${THRESHOLD_LIST[@]}"; do
        TAG="mdp${mdp}_t${thr//.}"
        echo "--- min_dst_ports=$mdp threshold=$thr ---"

        FRI_DIR="$RESULTS_DIR/friday_${TAG}"
        run_snort "$PCAP_FRIDAY" "$FRI_DIR" "$thr" "$mdp"
        FRI_SCANNER=$(count_ip_alerts "$FRI_DIR/alert_csv.txt" "172.16.0.1" "eq")
        FRI_FP=$(count_ip_alerts "$FRI_DIR/alert_csv.txt" "172.16.0.1" "neq")
        FRI_RECALL=$(python3 -c "print(f'{int('$FRI_SCANNER')/int('$FRIDAY_SCANNER_WINDOWS'):.4f}')" 2>/dev/null || echo "N/A")

        MON_DIR="$RESULTS_DIR/monday_${TAG}"
        run_snort "$PCAP_MONDAY" "$MON_DIR" "$thr" "$mdp"
        MON_ALL=$(count_ip_alerts "$MON_DIR/alert_csv.txt" "" "neq")  # all alerts = FP on Monday
        MON_ALL=$(python3 -c "
import sys
count = 0
try:
    with open('$MON_DIR/alert_csv.txt') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                count += 1
except: pass
print(count)
" 2>/dev/null || echo "0")

        THU_DIR="$RESULTS_DIR/thursday_${TAG}"
        run_snort "$PCAP_THURSDAY" "$THU_DIR" "$thr" "$mdp"
        THU_FP=$(count_ip_alerts "$THU_DIR/alert_csv.txt" "172.16.0.1" "neq")

        echo "  Friday:   scanner=$FRI_SCANNER/$FRIDAY_SCANNER_WINDOWS (recall=$FRI_RECALL), fp=$FRI_FP"
        echo "  Monday:   total_alerts=$MON_ALL (all=FP, no scanner)"
        echo "  Thursday: fp=$THU_FP"

        PASS="FAIL"
        if python3 -c "
recall = $FRI_SCANNER / $FRIDAY_SCANNER_WINDOWS
fp_ok = ($FRI_FP == 0) and ($MON_ALL == 0)
print('PASS' if recall >= 0.85 and fp_ok else 'FAIL')
" 2>/dev/null | grep -q PASS; then
            PASS="PASS (recall>= 0.85, FP=0)"
        fi
        echo "  STATUS: $PASS"

        echo "$mdp,$thr,$FRI_SCANNER,$FRIDAY_SCANNER_WINDOWS,$FRI_RECALL,$FRI_FP,$MON_ALL,$THU_FP" >> "$SUMMARY"
        echo ""
    done
done

echo "============================================"
echo "FINAL SUMMARY"
echo "============================================"
cat "$SUMMARY"
echo ""
echo "Results: $RESULTS_DIR"
echo "Summary: $SUMMARY"
