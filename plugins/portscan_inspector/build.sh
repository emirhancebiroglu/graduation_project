#!/bin/bash
# build.sh — PortScan Inspector plugin derleme scripti
# Kullanım: cd ~/bitirme/plugins/portscan_inspector && ./build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "=== PortScan Inspector Plugin Derleniyor ==="

XGBOOST_ROOT="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}"
if [ ! -f "${XGBOOST_ROOT}/include/xgboost/c_api.h" ]; then
    echo "HATA: XGBoost C API header bulunamadı: ${XGBOOST_ROOT}/include/xgboost/c_api.h"
    exit 1
fi

if [ ! -f "${XGBOOST_ROOT}/lib/libxgboost.so" ]; then
    echo "HATA: libxgboost.so bulunamadı: ${XGBOOST_ROOT}/lib/libxgboost.so"
    exit 1
fi

echo "XGBoost: ${XGBOOST_ROOT}"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[1/2] CMake konfigürasyonu..."
cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DXGBOOST_ROOT="${XGBOOST_ROOT}"

echo "[2/2] Derleme..."
make -j$(nproc)

echo ""
echo "=== Derleme Başarılı ==="
echo "Plugin: ${BUILD_DIR}/portscan_inspector.so"