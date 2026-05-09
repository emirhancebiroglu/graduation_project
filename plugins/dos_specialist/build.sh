#!/usr/bin/env bash
# build.sh — DoS Specialist plugin derleme scripti
# Kullanım: cd plugins/dos_specialist && bash build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "[dos_specialist] Build başlıyor..."

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DSNORT3_INCLUDE_DIR=/usr/local/include/snort \
    -DXGBOOST_INCLUDE_DIR=/usr/local/include \
    -DXGBOOST_LIB_DIR=/usr/local/lib

make -j"$(nproc)"

echo ""
echo "[dos_specialist] Build tamamlandı:"
ls -lh "${BUILD_DIR}/dos_specialist.so" 2>/dev/null || \
    echo "HATA: dos_specialist.so bulunamadı — derleme başarısız."

# Smoke test: plugin yüklenip yüklenemediğini kontrol et
echo ""
echo "[dos_specialist] Smoke test (ldd):"
ldd "${BUILD_DIR}/dos_specialist.so" 2>&1 | grep -E "xgboost|not found" || true