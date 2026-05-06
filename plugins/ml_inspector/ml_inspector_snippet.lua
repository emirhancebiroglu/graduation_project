-- ml_inspector_snippet.lua
-- Bu dosya tam bir snort.lua değildir!
-- Mevcut snort_test.lua dosyanıza aşağıdaki bloğu ekleyin.
--
-- Kullanım:
--   snort3 -c snort_test.lua \
--          --plugin-path /home/$USER/bitirme/plugins/build \
--          -r test.pcap \
--          -A alert_csv
--
-- Not: --plugin-path, ml_inspector.so dosyasının bulunduğu dizini gösterir.

-- ML Inspector konfigürasyonu
ml_inspector =
{
    -- Anomaly threshold (0.0-1.0 arası)
    -- Stub modda inference her zaman 0.0 döner, alert üretilmez
    -- TFLite entegrasyonunda gerçek threshold kullanılacak
    threshold = 0.5,

    -- Bir flow'da kaç paket toplandıktan sonra inference tetiklensin
    -- Çok düşük tutulursa kısa flow'larda feature doğruluğu düşer
    -- Çok yüksek tutulursa uzun flow'lar geç tespit edilir
    max_packets = 100,
}
