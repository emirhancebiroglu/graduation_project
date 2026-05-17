#!/bin/bash
# Apply JSON scaler loading to all 6 inspectors
cd /home/emirhan/bitirme/plugins

apply_cmake() {
    local dir=$1
    local file="${dir}/CMakeLists.txt"
    if grep -q 'scaler_loader\|plugins/include' "$file" 2>/dev/null; then
        echo "  [SKIP] $dir already has scaler pathes"
        return
    fi
    # Add ../include after the last existing include
    sed -i 's|${CMAKE_CURRENT_SOURCE_DIR}|${CMAKE_CURRENT_SOURCE_DIR}\n    ${CMAKE_CURRENT_SOURCE_DIR}/../include|' "$file"
    echo "  [CMAKE] $dir: added plugins/include"
}

apply_cc() {
    local dir=$1
    local tracker="${dir}/src/${dir}_inspector.cc"
    if [ ! -f "$tracker" ]; then
        # Try alternate naming (dos vs botnet_c2 etc)
        tracker=$(ls ${dir}/src/*inspector.cc 2>/dev/null | head -1)
    fi
    if [ -z "$tracker" ] || [ ! -f "$tracker" ]; then
        echo "  [SKIP] $dir: no CC file found"
        return
    fi
    local basename=$(basename "$tracker" .cc)

    # Already applied?
    if grep -q 'scaler_loader.h' "$tracker"; then
        echo "  [SKIP] $dir already has scaler"
        return
    fi

    # Add include
    sed -i '1s/^/#include "scaler_loader.h"\n/' "$tracker"

    # Remove static from g_scaler (first occurrence in AGG_SCALER_PARAMS block)
    sed -i 's/static \(.*ScalerParams g_scaler =\)/\1/' "$tracker"

    # Add loading to configure()
    sed -i 's|\(if (!xgb.load(mp)\)|\0 \&\& load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))|' "$tracker"
    sed -i 's|\(if (!xgb.load(mp)\)|\0 \&\& load_scaler_json(mp, g_scaler, XGB_FI_COUNT))|' "$tracker"

    echo "  [CC] $dir: updated $basename"
}

for d in dos_inspector portscan_inspector dos_aggregator ddos_aggregator botnet_c2_inspector; do
    echo "--- $d ---"
    apply_cmake "$d"
    apply_cc "$d"
done

echo "=== Done ==="
