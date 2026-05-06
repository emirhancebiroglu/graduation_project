#!/bin/bash
# setup_xgboost.sh — XGBoost C API kurulum ve doğrulama scripti
# Kullanım: bash setup_xgboost.sh
#
# Bu script:
#   1. XGBoost'un zaten kurulu olup olmadığını kontrol eder
#   2. Kurulu değilse kaynak koddan derler
#   3. C API header ve library'yi doğrular

set -e

INSTALL_DIR="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}"

echo "============================================="
echo " XGBoost C API Kurulum Scripti"
echo "============================================="
echo "Hedef dizin: $INSTALL_DIR"
echo ""

# ─── Adım 1: Mevcut kurulumu kontrol et ───
echo "[1/4] Mevcut kurulum kontrol ediliyor..."

if [ -f "$INSTALL_DIR/include/xgboost/c_api.h" ] && \
   [ -f "$INSTALL_DIR/lib/libxgboost.so" ]; then
    echo "  ✅ XGBoost C API zaten kurulu!"
    echo "  Header:  $INSTALL_DIR/include/xgboost/c_api.h"
    echo "  Library: $INSTALL_DIR/lib/libxgboost.so"
    echo ""
    echo "Derlemeye geçebilirsiniz:"
    echo "  cd ~/bitirme/plugins/xgb_inspector && ./build.sh"
    exit 0
fi

# pip ile kurulu libxgboost.so'yu kontrol et
PIP_XGB=$(python3 -c "import xgboost; import os; print(os.path.dirname(xgboost.__file__))" 2>/dev/null || true)
if [ -n "$PIP_XGB" ] && [ -f "$PIP_XGB/lib/libxgboost.so" ]; then
    echo "  ℹ️  pip xgboost bulundu: $PIP_XGB"
    echo "  Ancak C API header'ları pip ile gelmez."
    echo "  Kaynak koddan derleme gerekli."
fi

echo "  XGBoost C API bulunamadı, kaynak koddan derlenecek."
echo ""

# ─── Adım 2: Gerekli paketler ───
echo "[2/4] Gerekli paketler kontrol ediliyor..."
for pkg in cmake g++ git; do
    if command -v $pkg &>/dev/null; then
        echo "  ✅ $pkg"
    else
        echo "  ❌ $pkg bulunamadı! Kurulum: sudo apt install $pkg"
        exit 1
    fi
done
echo ""

# ─── Adım 3: XGBoost kaynak kodunu indir ve derle ───
echo "[3/4] XGBoost kaynak kodu indiriliyor ve derleniyor..."
echo "  Bu işlem 5-15 dakika sürebilir."
echo ""

SRC_DIR="$HOME/snort_src"
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

if [ ! -d "xgboost/.git" ]; then
    echo "  git clone yapılıyor..."
    git clone --recursive https://github.com/dmlc/xgboost.git
else
    echo "  Mevcut kaynak kodu kullanılıyor..."
    cd xgboost
    git submodule update --init --recursive
    cd ..
fi

cd xgboost
mkdir -p build
cd build

echo "  CMake konfigürasyonu..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DBUILD_STATIC_LIB=OFF

echo "  Derleniyor ($(nproc) thread)..."
make -j$(nproc)

echo "  Kuruluyor..."
make install

echo ""

# ─── Adım 4: Doğrulama ───
echo "[4/4] Doğrulama..."

if [ -f "$INSTALL_DIR/include/xgboost/c_api.h" ]; then
    echo "  ✅ C API header: $INSTALL_DIR/include/xgboost/c_api.h"
else
    echo "  ❌ C API header bulunamadı!"
    exit 1
fi

if [ -f "$INSTALL_DIR/lib/libxgboost.so" ]; then
    echo "  ✅ Library: $INSTALL_DIR/lib/libxgboost.so"
else
    echo "  ❌ Library bulunamadı!"
    exit 1
fi

echo ""
echo "============================================="
echo " XGBoost C API Kurulumu Başarılı!"
echo "============================================="
echo ""
echo "Sonraki adımlar:"
echo "  1. Plugin derle:"
echo "     cd ~/bitirme/plugins/xgb_inspector && ./build.sh"
echo ""
echo "  2. PCAP replay çalıştır:"
echo "     cd ~/bitirme && bash scripts/run_xgb_replay.sh"
echo ""
echo "  3. Confusion matrix hesapla:"
echo "     python scripts/xgb_flowid_confusion.py \\"
echo "         --alert-dir ~/bitirme/results/xgboost \\"
echo "         --csv-dir ~/bitirme/data/raw/cicids2017 \\"
echo "         --output ~/bitirme/results/xgboost/confusion_matrix.txt"
