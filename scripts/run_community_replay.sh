#!/bin/bash
# run_community_replay.sh — CIC-IDS2017 PCAP'larını Community Rules ile çalıştır
# Kullanım: cd ~/bitirme && bash scripts/run_community_replay.sh
set -e

# ─── Konfigürasyon ───
SNORT_BIN="snort"
SNORT_ETC="/usr/local/etc/snort"
CONFIG="$HOME/bitirme/configs/snort_community.lua"
PCAP_DIR="$HOME/bitirme/pcaps"
OUTPUT_DIR="$HOME/bitirme/results/community"

# ─── PCAP dosyaları ───
PCAP_FILES=(
    "Monday-WorkingHours.pcap"
    "Tuesday-WorkingHours.pcap"
    "Wednesday-workingHours.pcap"
    "Thursday-WorkingHours.pcap"
    "Friday-WorkingHours.pcap"
)

echo "============================================="
echo " Community Rules — CIC-IDS2017 PCAP Replay"
echo "============================================="
echo "Config:      $CONFIG"
echo "PCAP dizini: $PCAP_DIR"
echo "Çıktı:       $OUTPUT_DIR"
echo ""

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

    # NOT: --plugin-path yok — community rules plugin gerektirmez
    cd "$SNORT_ETC" && $SNORT_BIN \
        -c "$CONFIG" \
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
