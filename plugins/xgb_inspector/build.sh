#!/bin/bash
# build.sh — XGBoost Inspector plugin derleme scripti
# Kullanım: cd ~/bitirme/plugins/xgb_inspector && ./build.sh
#
# Ön koşullar:
#   - Snort3 /usr/local altına kurulmuş olmalı
#   - pkg-config snort3'ü bulabilmeli
#   - XGBoost kaynak kodu ~/snort_src/xgboost altında derlenmiş olmalı
#   - cmake >= 3.16

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "=== XGBoost Inspector Plugin Derleniyor ==="

# XGBoost kontrolü
XGBOOST_ROOT="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}"
if [ ! -f "${XGBOOST_ROOT}/include/xgboost/c_api.h" ]; then
    echo ""
    echo "HATA: XGBoost C API header bulunamadı!"
    echo "Beklenen: ${XGBOOST_ROOT}/include/xgboost/c_api.h"
    echo ""
    echo "XGBoost'u derlemek için:"
    echo "  cd ~/snort_src"
    echo "  git clone --recursive https://github.com/dmlc/xgboost.git"
    echo "  cd xgboost"
    echo "  mkdir build && cd build"
    echo "  cmake .. -DCMAKE_INSTALL_PREFIX=\$(dirname \$(pwd))"
    echo "  make -j\$(nproc)"
    echo "  make install"
    echo ""
    echo "Veya farklı dizin kullanıyorsanız:"
    echo "  XGBOOST_ROOT=/path/to/xgboost ./build.sh"
    exit 1
fi

if [ ! -f "${XGBOOST_ROOT}/lib/libxgboost.so" ]; then
    echo ""
    echo "HATA: libxgboost.so bulunamadı!"
    echo "Beklenen: ${XGBOOST_ROOT}/lib/libxgboost.so"
    echo "XGBoost'u derleyip 'make install' çalıştırdığınızdan emin olun."
    exit 1
fi

echo "XGBoost: ${XGBOOST_ROOT}"

# Build dizinini oluştur
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake konfigürasyonu
echo "[1/2] CMake konfigürasyonu..."
cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DXGBOOST_ROOT="${XGBOOST_ROOT}"

# Derleme
echo "[2/2] Derleme..."
make -j$(nproc)

echo ""
echo "=== Derleme Başarılı ==="
echo "Plugin: ${BUILD_DIR}/xgb_inspector.so"
echo ""
echo "Test etmek için:"
echo "  snort -c ~/bitirme/configs/snort_xgb.lua \\"
echo "        --plugin-path ${BUILD_DIR} \\"
echo "        -r test.pcap -A alert_csv"
