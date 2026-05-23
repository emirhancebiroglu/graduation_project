#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
echo "=== Brute Force Inspector Plugin Derleniyor ==="
XGBOOST_ROOT="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}"
if [ ! -f "${XGBOOST_ROOT}/include/xgboost/c_api.h" ]; then
    echo "HATA: XGBoost C API header bulunamadi: ${XGBOOST_ROOT}/include/xgboost/c_api.h"
    exit 1
fi
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
echo "[1/2] CMake..."
cmake "$SCRIPT_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DXGBOOST_ROOT="${XGBOOST_ROOT}"
echo "[2/2] Derleme..."
make -j$(nproc)
echo ""
echo "=== Derleme Basarili ==="
echo "Plugin: ${BUILD_DIR}/bruteforce_inspector.so"
