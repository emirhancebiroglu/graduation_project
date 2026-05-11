#!/bin/bash
# run_xgb_replay.sh — CIC-IDS2017 PCAP'larını XGBoost Inspector ile çalıştır
# Kullanım: cd ~/bitirme && bash scripts/run_xgb_replay.sh

set -e

# ─── Konfigürasyon ───
SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
CONFIG="$HOME/bitirme/configs/snort_xgb.lua"
PLUGIN_PATH="$HOME/bitirme/plugins/xgb_inspector/build"
PCAP_DIR="$HOME/bitirme/pcaps"
OUTPUT_DIR="$HOME/bitirme/results/xgboost"

# XGBoost runtime library path (libxgboost.so)
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

# ─── PCAP dosyaları ───
PCAP_FILES=(
    "Wednesday-workingHours.pcap"
)

echo "============================================="
echo " XGBoost Inspector — CIC-IDS2017 PCAP Replay"
echo "============================================="
echo "Config:      $CONFIG"
echo "Plugin:      $PLUGIN_PATH"
echo "XGBoost lib: $XGBOOST_LIB"
echo "PCAP dizini: $PCAP_DIR"
echo "Çıktı:       $OUTPUT_DIR"
echo ""

# Plugin kontrolü
if [ ! -f "$PLUGIN_PATH/xgb_inspector.so" ]; then
    echo "HATA: xgb_inspector.so bulunamadı!"
    echo "Önce derleme yapın: cd ~/bitirme/plugins/xgb_inspector && ./build.sh"
    exit 1
fi

# libxgboost kontrolü
if [ ! -f "$XGBOOST_LIB/libxgboost.so" ]; then
    echo "HATA: libxgboost.so bulunamadı: $XGBOOST_LIB"
    echo "XGBOOST_ROOT değişkenini kontrol edin."
    exit 1
fi

TOTAL=${#PCAP_FILES[@]}
CURRENT=0

for pcap in "${PCAP_FILES[@]}"; do
    CURRENT=$((CURRENT + 1))
    PCAP_PATH="$PCAP_DIR/$pcap"
    BASE_NAME="${pcap%.pcap}"
    ALERT_DIR="$OUTPUT_DIR/$BASE_NAME"

    echo "─────────────────────────────────────────────"
    echo "[$CURRENT/$TOTAL] $pcap"
    echo "─────────────────────────────────────────────"

    if [ ! -f "$PCAP_PATH" ]; then
        echo "  UYARI: $PCAP_PATH bulunamadı, atlaniyor!"
        continue
    fi

    mkdir -p "$ALERT_DIR"

    echo "  Başlatılıyor..."
    START_TIME=$(date +%s)

    cd "$SNORT_ETC" && $SNORT_BIN \
        -c "$CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP_PATH" \
        -A alert_csv \
        -l "$ALERT_DIR" \
        --warn-all \
        -q \
        2>/dev/null

    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))

    ALERT_FILE="$ALERT_DIR/alert_csv.txt"
    if [ -f "$ALERT_FILE" ]; then
        ALERT_COUNT=$(wc -l < "$ALERT_FILE")
        echo "  Tamamlandı: $ALERT_COUNT alert, süre: ${ELAPSED}s"
    else
        echo "  Tamamlandı: 0 alert, süre: ${ELAPSED}s"
    fi
    echo ""
done

echo "============================================="
echo " Tüm PCAP'lar işlendi!"
echo "============================================="
echo ""
echo "ÖZET:"
echo "─────────────────────────────────────────────"
printf "%-45s %s\n" "PCAP Dosyası" "Alert Sayısı"
echo "─────────────────────────────────────────────"

TOTAL_ALERTS=0
for pcap in "${PCAP_FILES[@]}"; do
    BASE_NAME="${pcap%.pcap}"
    ALERT_FILE="$OUTPUT_DIR/$BASE_NAME/alert_csv.txt"
    if [ -f "$ALERT_FILE" ]; then
        COUNT=$(wc -l < "$ALERT_FILE")
    else
        COUNT=0
    fi
    TOTAL_ALERTS=$((TOTAL_ALERTS + COUNT))
    printf "%-45s %d\n" "$pcap" "$COUNT"
done
echo "─────────────────────────────────────────────"
printf "%-45s %d\n" "TOPLAM" "$TOTAL_ALERTS"
echo "─────────────────────────────────────────────"
echo ""
echo "Confusion matrix hesaplamak için:"
echo "  python scripts/xgb_flowid_confusion.py \\"
echo "      --alert-dir ~/bitirme/results/xgboost \\"
echo "      --csv-dir ~/bitirme/data/raw/cicids2017 \\"
echo "      --output ~/bitirme/results/xgboost/confusion_matrix.txt"
