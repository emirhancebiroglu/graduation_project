#!/usr/bin/env python3
"""Apply JSON scaler loading to all inspector plugins."""

import os, re

PLUGINS_DIR = "/home/emirhan/bitirme/plugins"
INSPECTORS = [
    ("portscan_inspector", "PsiAggScalerParams", "g_scaler", "AGG_FEATURE_COUNT", "portscan"),
    ("dos_aggregator", "DasAggScalerParams", "g_scaler", "AGG_FEATURE_COUNT", "dos_agg"),
    ("ddos_aggregator", "DdsAggScalerParams", "g_scaler", "AGG_FEATURE_COUNT", "ddos_agg"),
    ("botnet_c2_inspector", "BotC2ScalerParams", "g_scaler", "AGG_FEATURE_COUNT", "botc2"),
]

for name, scaler_type, scaler_var, feat_count, tag in INSPECTORS:
    cc_file = os.path.join(PLUGINS_DIR, name, "src", f"{name}.cc")
    cmake_file = os.path.join(PLUGINS_DIR, name, "CMakeLists.txt")
    
    if not os.path.exists(cc_file):
        alt = os.path.join(PLUGINS_DIR, name, "src")
        files = [f for f in os.listdir(alt) if f.endswith('.cc')] if os.path.exists(alt) else []
        if files:
            cc_file = os.path.join(alt, files[0])
        else:
            print(f"[SKIP] {name}: no CC file")
            continue
    
    print(f"=== {name} ===")
    
    # 1. Update CMakeLists.txt
    if os.path.exists(cmake_file):
        with open(cmake_file) as f:
            cmake = f.read()
        if "../include" not in cmake:
            cmake = cmake.replace(
                "${CMAKE_CURRENT_SOURCE_DIR}",
                "${CMAKE_CURRENT_SOURCE_DIR}\n    ${CMAKE_CURRENT_SOURCE_DIR}/../include"
            )
            with open(cmake_file, 'w') as f:
                f.write(cmake)
            print("  CMakeLists.txt: updated")
        else:
            print("  CMakeLists.txt: already updated")
    
    # 2. Update CC file
    with open(cc_file) as f:
        content = f.read()
    
    changes = 0
    
    # Add scaler_loader.h include
    if 'scaler_loader.h' not in content:
        content = re.sub(
            r'(#include ".*_flow_tracker\.h")',
            r'\1\n#include "scaler_loader.h"',
            content
        )
        changes += 1
    
    # Remove static from g_scaler (the non-const version)
    pattern = rf'static\s+{re.escape(scaler_type)}\s+{re.escape(scaler_var)}\s*='
    if re.search(pattern, content):
        content = re.sub(pattern, f'{scaler_type} {scaler_var} =', content)
        changes += 1
        print(f"  Removed static from {scaler_var}")
    
    # Add load_scaler_json to configure()
    # Find configure()
    cfg_match = re.search(
        r'(bool configure\(snort::SnortConfig\*\).*?\{.*?'
        r'(?:xgb\.load|engine\.load|model\.load)\([^)]+\)[^;]*;)',
        content, re.DOTALL
    )
    if cfg_match and 'load_scaler_json' not in cfg_match.group():
        # Find the closing of configure
        cfg_block = cfg_match.group(1)
        # Add after model load
        new_cfg = cfg_block + f"""
        if (load_scaler_json(model_path, {scaler_var}, {feat_count}))
            snort::LogMessage("[{tag}] Loaded scaler from JSON\\n");
        else
            snort::LogMessage("[{tag}] Using hardcoded scaler params\\n");"""
        content = content.replace(cfg_block, new_cfg)
        changes += 1
        print(f"  Added scaler loading to configure()")
    
    if changes > 0:
        with open(cc_file, 'w') as f:
            f.write(content)
        print(f"  Applied {changes} changes")
    else:
        print("  No changes needed (already applied)")

print("\n=== Done ===")
