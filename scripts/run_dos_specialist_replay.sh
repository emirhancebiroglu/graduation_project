#!/usr/bin/env bash
# run_dos_specialist_replay.sh — DoS Specialist Inspector PCAP Replay
# Bitirme Projesi — DoS Pilot Faz 5
#
# Kullanım:
#   cd ~/bitirme && bash scripts/run_dos_specialist_replay.sh
#
# Önce derle:
#   cd plugins/dos_specialist && bash build.sh
#
# Önemli: Wednesday-WorkingHours.pcap DoS Hulk+GoldenEye içerdiği için
# öncelikli test PCAP'ıdır. Tüm günler de çalıştırılır.

set -euo pipefail

# ─── Konfigürasyon ─────────────────────────────────────────────
SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
CONFIG="$HOME/bitirme/configs/snort_dos_specialist.lua"
PLUGIN_PATH="$HOME/bitirme/plugins/dos_specialist/build"
PCAP_DIR="$HOME/bitirme/pcaps"
OUTPUT_DIR="$HOME/bitirme/results/dos_specialist"

# XGBoost runtime library
XGBOOST_LIB="${XGBOOST_ROOT:-$HOME/snort_src/xgboost}/lib"
export LD_LIBRARY_PATH="${XGBOOST_LIB}:${LD_LIBRARY_PATH:-}"

# ─── PCAP listesi (Wednesday önce — DoS odaklı) ────────────────
PCAP_FILES=(
    "Wednesday-workingHours.pcap"
)

echo "=============================================="
echo " DoS Specialist — CIC-IDS2017 PCAP Replay"
echo " GID=302 | mp_2 | threshold=0.50"
echo "=============================================="
echo "Config:      $CONFIG"
echo "Plugin:      $PLUGIN_PATH"
echo "XGBoost lib: $XGBOOST_LIB"
echo "PCAP dizini: $PCAP_DIR"
echo "Çıktı:       $OUTPUT_DIR"
echo ""

# ─── Ön kontroller ─────────────────────────────────────────────
if [ ! -f "$PLUGIN_PATH/dos_specialist.so" ]; then
    echo "HATA: dos_specialist.so bulunamadı!"
    echo "Derle: cd ~/bitirme/plugins/dos_specialist && bash build.sh"
    exit 1
fi

if [ ! -f "$XGBOOST_LIB/libxgboost.so" ]; then
    echo "HATA: libxgboost.so bulunamadı: $XGBOOST_LIB"
    echo "XGBOOST_ROOT değişkenini kontrol edin."
    exit 1
fi

MODEL_PATH="$HOME/bitirme/models/dos_specialist/mp_2_xgb_model.json"
if [ ! -f "$MODEL_PATH" ]; then
    echo "UYARI: Model dosyası bulunamadı: $MODEL_PATH"
    echo "train_dos_specialist.py çıktısını kontrol edin."
fi

# ─── Replay döngüsü ────────────────────────────────────────────
TOTAL=${#PCAP_FILES[@]}
CURRENT=0

for pcap in "${PCAP_FILES[@]}"; do
    CURRENT=$((CURRENT + 1))
    PCAP_PATH="$PCAP_DIR/$pcap"
    BASE_NAME="${pcap%.pcap}"
    ALERT_DIR="$OUTPUT_DIR/$BASE_NAME"

    echo "──────────────────────────────────────────────"
    echo "[$CURRENT/$TOTAL] $pcap"
    echo "──────────────────────────────────────────────"

    if [ ! -f "$PCAP_PATH" ]; then
        echo "  UYARI: $PCAP_PATH bulunamadı, atlıyor."
        continue
    fi

    mkdir -p "$ALERT_DIR"

    echo "  Başlatılıyor..."
    START_TIME=$(date +%s)

    # Snort3 çalıştır — alert_csv formatı confusion matrix için gerekli
    cd "$SNORT_ETC" && $SNORT_BIN \
        -c "$CONFIG" \
        --plugin-path "$PLUGIN_PATH" \
        -r "$PCAP_PATH" \
        -A alert_csv \
        -l "$ALERT_DIR" \
        --warn-all \
        -q \
        2>/dev/null || true   # exit ≠ 0 → loglama hatası, devam et

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

# ─── Özet tablo ────────────────────────────────────────────────
echo "=============================================="
echo " Tüm PCAP'lar işlendi!"
echo "=============================================="
echo ""
echo "ÖZET:"
echo "──────────────────────────────────────────────"
printf "%-45s %s\n" "PCAP Dosyası" "Alert Sayısı"
echo "──────────────────────────────────────────────"

TOTAL_ALERTS=0
for pcap in "${PCAP_FILES[@]}"; do
    BASE_NAME="${pcap%.pcap}"
    ALERT_FILE="$OUTPUT_DIR/$BASE_NAME/alert_csv.txt"
    COUNT=0
    [ -f "$ALERT_FILE" ] && COUNT=$(wc -l < "$ALERT_FILE")
    TOTAL_ALERTS=$((TOTAL_ALERTS + COUNT))
    printf "%-45s %d\n" "$pcap" "$COUNT"
done
echo "──────────────────────────────────────────────"
printf "%-45s %d\n" "TOPLAM" "$TOTAL_ALERTS"
echo "──────────────────────────────────────────────"
echo ""
echo "Confusion matrix için:"
echo "  python scripts/dos_specialist_flowid_confusion.py \\"
echo "      --alert-dir $OUTPUT_DIR \\"
echo "      --csv-dir   ~/bitirme/data/raw/cicids2017 \\"
echo "      --output    $OUTPUT_DIR/confusion_matrix.txt"