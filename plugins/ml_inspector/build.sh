#!/bin/bash
# build.sh — ML Inspector plugin derleme scripti
# Kullanım: cd ml_inspector && ./build.sh
#
# Ön koşullar:
#   - Snort3 /usr/local altına kurulmuş olmalı
#   - pkg-config snort3'ü bulabilmeli
#   - cmake >= 3.16

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "=== ML Inspector Plugin Derleniyor ==="

# Build dizinini oluştur
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake konfigürasyonu
echo "[1/2] CMake konfigürasyonu..."
cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local

# Derleme
echo "[2/2] Derleme..."
make -j$(nproc)

echo ""
echo "=== Derleme Başarılı ==="
echo "Plugin: ${BUILD_DIR}/ml_inspector.so"
echo ""
echo "Test etmek için:"
echo "  snort3 -c ~/bitirme/configs/snort_test.lua \\"
echo "         --plugin-path ${BUILD_DIR} \\"
echo "         -r test.pcap -A alert_csv"
