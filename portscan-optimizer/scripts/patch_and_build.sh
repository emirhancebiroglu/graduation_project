#!/bin/bash
# patch_and_build.sh — Patch scaler params into portscan_inspector.cc and recompile
#
# Usage: bash scripts/patch_and_build.sh --threshold 0.50 --iteration 0
#
# Reads: results/portscan/scaler_params.json
# Patches: plugins/portscan_inspector/portscan_inspector.cc (SCALER_PARAMS_BEGIN/END block)
# Updates: configs/snort_portscan.lua (threshold, model_path)
# Rebuilds: plugins/portscan_inspector/build.sh

set -e

BITIRME="$HOME/bitirme"
SCALER_JSON="$BITIRME/results/portscan/scaler_params.json"
CC_FILE="$BITIRME/plugins/portscan_inspector/portscan_inspector.cc"
LUA_FILE="$BITIRME/configs/snort_portscan.lua"
BUILD_SH="$BITIRME/plugins/portscan_inspector/build.sh"

THRESHOLD=0.50
ITERATION=0
MODEL_PATH="$BITIRME/models/portscan_model.json"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --threshold)  THRESHOLD="$2";  shift 2 ;;
        --iteration)  ITERATION="$2";  shift 2 ;;
        --model-path) MODEL_PATH="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "=== Patch & Build — Iteration $ITERATION ==="
echo "Threshold:  $THRESHOLD"
echo "Model:      $MODEL_PATH"
echo "Scaler:     $SCALER_JSON"
echo ""

# Check files exist
if [ ! -f "$SCALER_JSON" ]; then
    echo "ERROR: scaler_params.json not found: $SCALER_JSON"
    echo "Run train_portscan_iter.py first."
    exit 1
fi

if [ ! -f "$CC_FILE" ]; then
    echo "ERROR: portscan_inspector.cc not found: $CC_FILE"
    exit 1
fi

# ── Step 1: Generate new scaler block via Python ──────────────────────────
echo "[1/3] Generating new scaler block..."

NEW_BLOCK=$(python3 - <<EOF
import json

with open("$SCALER_JSON") as f:
    p = json.load(f)

median = p['median']
iqr    = p['iqr']

def fmt(vals):
    return ', '.join(f'{v:.10f}' for v in vals)

print("// SCALER_PARAMS_BEGIN")
print("static PsiScalerParams g_scaler_params = {")
print(f"    // median[11] — iteration $ITERATION")
print(f"    {{ {fmt(median)} }},")
print(f"    // iqr[11] — iteration $ITERATION")
print(f"    {{ {fmt(iqr)} }}")
print("};")
print("// SCALER_PARAMS_END")
EOF
)

echo "New scaler block:"
echo "$NEW_BLOCK"
echo ""

# ── Step 2: Patch portscan_inspector.cc ──────────────────────────────────
echo "[2/3] Patching portscan_inspector.cc..."

python3 - <<EOF
import re

with open("$CC_FILE", 'r') as f:
    content = f.read()

new_block = """$NEW_BLOCK"""

# Replace between markers
pattern = r'// SCALER_PARAMS_BEGIN.*?// SCALER_PARAMS_END'
replacement = new_block
new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

if new_content == content:
    print("WARNING: Pattern not found — markers missing from .cc file!")
    exit(1)

with open("$CC_FILE", 'w') as f:
    f.write(new_content)

print("portscan_inspector.cc patched successfully.")
EOF

# ── Step 3: Update snort_portscan.lua ────────────────────────────────────
echo "[3/3] Updating snort_portscan.lua..."

python3 - <<EOF
import re

with open("$LUA_FILE", 'r') as f:
    content = f.read()

# Update threshold
content = re.sub(
    r'(portscan_inspector\s*=\s*\{[^}]*threshold\s*=\s*)[0-9.]+',
    r'\g<1>$THRESHOLD',
    content
)

# Update model_path
content = re.sub(
    r'(portscan_inspector\s*=\s*\{[^}]*model_path\s*=\s*")[^"]*"',
    r'\g<1>$MODEL_PATH"',
    content
)

with open("$LUA_FILE", 'w') as f:
    f.write(content)

print(f"snort_portscan.lua updated: threshold=$THRESHOLD, model=$MODEL_PATH")
EOF

# ── Step 4: Recompile ─────────────────────────────────────────────────────
echo ""
echo "[4/4] Recompiling portscan_inspector..."
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

cd "$BITIRME/plugins/portscan_inspector"
bash build.sh

echo ""
echo "=== Patch & Build Complete ==="
echo "Plugin: $BITIRME/plugins/portscan_inspector/build/portscan_inspector.so"
echo "Config: $LUA_FILE"
echo "Ready to run Snort replay."