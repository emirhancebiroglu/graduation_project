#!/bin/bash
# run_combined_replay.sh — CIC-IDS2017 PCAP'larını Combined Mode ile çalıştır
# LSTM Inspector + XGBoost Inspector + Community Rules — tek Snort process
#
# Kullanım: cd ~/bitirme && bash scripts/run_combined_replay.sh

set -e

# ─── Konfigürasyon ───
SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
CONFIG="$HOME/bitirme/configs/snort_combined.lua"

# Her iki plugin dizini --plugin-path ile eklenir
LSTM_PLUGIN_PATH="$HOME/bitirme/plugins/ml_inspector/build"
XGB_PLUGIN_PATH="$HOME/bitirme/plugins/xgb_inspector/build"

PCAP_DIR="$HOME/bitirme/pcaps"
OUTPUT_DIR="$HOME/bitirme/results/combined"

# XGBoost runtime
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH}"

# ─── PCAP dosyaları ───
PCAP_FILES=(
    "Monday-WorkingHours.pcap"
    "Tuesday-WorkingHours.pcap"
    "Wednesday-workingHours.pcap"
    "Thursday-WorkingHours.pcap"
    "Friday-WorkingHours.pcap"
)

echo "============================================="
echo " Combined Run — LSTM + XGBoost + Community"
echo "============================================="
echo "Config:      $CONFIG"
echo "LSTM Plugin: $LSTM_PLUGIN_PATH"
echo "XGB Plugin:  $XGB_PLUGIN_PATH"
echo "PCAP dizini: $PCAP_DIR"
echo "Çıktı:       $OUTPUT_DIR"
echo ""

# ─── Kontroller ───
if [ ! -f "$LSTM_PLUGIN_PATH/ml_inspector.so" ]; then
    echo "HATA: ml_inspector.so bulunamadı: $LSTM_PLUGIN_PATH"
    exit 1
fi

if [ ! -f "$XGB_PLUGIN_PATH/xgb_inspector.so" ]; then
    echo "HATA: xgb_inspector.so bulunamadı: $XGB_PLUGIN_PATH"
    exit 1
fi

if [ ! -f "$XGBOOST_LIB/libxgboost.so" ]; then
    echo "HATA: libxgboost.so bulunamadı: $XGBOOST_LIB"
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
        echo "  UYARI: $PCAP_PATH bulunamadı, atlanıyor!"
        continue
    fi

    mkdir -p "$ALERT_DIR"

    echo "  Başlatılıyor..."
    START_TIME=$(date +%s)

    # İki plugin dizini ayrı --plugin-path ile verilir
    cd "$SNORT_ETC" && $SNORT_BIN \
        -c "$CONFIG" \
        --plugin-path "$LSTM_PLUGIN_PATH" \
        --plugin-path "$XGB_PLUGIN_PATH" \
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
        TOTAL_ALERTS=$(wc -l < "$ALERT_FILE")
        # GID'e göre say: GID alanı sütun 3 (0-indexed: col index değişebilir)
        # alert_csv formatı: timestamp,pkt_num,proto,..gid:sid..
        # GID'i msg alanındaki prefix'ten ayırt ediyoruz
        LSTM_ALERTS=$(grep -c " 300:" "$ALERT_FILE" 2>/dev/null || true); LSTM_ALERTS=${LSTM_ALERTS:-0}
        XGB_ALERTS=$(grep -c " 301:" "$ALERT_FILE" 2>/dev/null || true); XGB_ALERTS=${XGB_ALERTS:-0}
        COMM_ALERTS=$((TOTAL_ALERTS - LSTM_ALERTS - XGB_ALERTS))
        echo "  Tamamlandı (${ELAPSED}s): toplam=$TOTAL_ALERTS | lstm=$LSTM_ALERTS xgb=$XGB_ALERTS community=$COMM_ALERTS"
    else
        echo "  Tamamlandı (${ELAPSED}s): 0 alert"
    fi
    echo ""
done

echo "============================================="
echo " Tüm PCAP'lar işlendi!"
echo "============================================="
echo ""
echo "ÖZET:"
echo "─────────────────────────────────────────────"
printf "%-45s %8s %8s %8s %8s\n" "PCAP Dosyası" "Toplam" "LSTM" "XGBoost" "Community"
echo "─────────────────────────────────────────────"

GRAND_TOTAL=0; GRAND_LSTM=0; GRAND_XGB=0; GRAND_COMM=0

for pcap in "${PCAP_FILES[@]}"; do
    BASE_NAME="${pcap%.pcap}"
    ALERT_FILE="$OUTPUT_DIR/$BASE_NAME/alert_csv.txt"
    if [ -f "$ALERT_FILE" ]; then
        T=$(wc -l < "$ALERT_FILE")
        L=$(grep -c " 300:" "$ALERT_FILE" 2>/dev/null || true); L=${L:-0}
        X=$(grep -c " 301:" "$ALERT_FILE" 2>/dev/null || true); X=${X:-0}
        C=$((T - L - X))
    else
        T=0; L=0; X=0; C=0
    fi
    GRAND_TOTAL=$((GRAND_TOTAL + T))
    GRAND_LSTM=$((GRAND_LSTM + L))
    GRAND_XGB=$((GRAND_XGB + X))
    GRAND_COMM=$((GRAND_COMM + C))
    printf "%-45s %8d %8d %8d %8d\n" "$pcap" "$T" "$L" "$X" "$C"
done

echo "─────────────────────────────────────────────"
printf "%-45s %8d %8d %8d %8d\n" "TOPLAM" "$GRAND_TOTAL" "$GRAND_LSTM" "$GRAND_XGB" "$GRAND_COMM"
echo "─────────────────────────────────────────────"
echo ""
echo "Confusion matrix için:"
echo "  python scripts/combined_confusion.py \\"
echo "      --alert-dir ~/bitirme/results/combined \\"
echo "      --csv-dir   ~/bitirme/data/raw/cicids2017 \\"
echo "      --output    ~/bitirme/results/combined/confusion_matrix.txt"