// flow_tracker_dos_specialist.h — Snort3 DoS Specialist: Per-flow feature tracker
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// DoS Specialist (GID=302) için genişletilmiş 17-feature tracker.
// XgbFlowData'dan (11 feature) türetilmez — ODR çakışmasını önlemek için
// tamamen bağımsız sınıf: DosFlowData, DOS_FI_* enum.
//
// Eklenen 6 feature (mevcut 11 + 6 = 17):
//   12. flow_iat_mean  — Tüm paketlerin ortalama inter-arrival time (ms)
//   13. flow_iat_std   — IAT standart sapması (DoS flood = düşük std)
//   14. pkt_len_mean   — Ortalama paket boyutu (Hulk = büyük, GoldenEye = küçük)
//   15. pkt_len_std    — Paket boyutu varyansı
//   16. rst_flag_count — TCP RST bayrak sayısı (Hulk için kritik)
//   17. urg_flag_count — TCP URG bayrak sayısı
//
// [VARSAYIM] scaler parametreleri (median/iqr) mp_2 varyantı için
// Python eğitim çıktısındaki scaler.pkl'den güncellenmeli.
// Şu anki değerler placeholder — gerçek değerlerle değiştirilecek.

#ifndef DOS_SPECIALIST_FLOW_TRACKER_H
#define DOS_SPECIALIST_FLOW_TRACKER_H

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

#include "flow/flow_data.h"

// ---------------------------------------------------------------
// Feature indeks enum (eğitim sırasıyla birebir aynı olmalı)
// prepare_dos_specialist_dataset.py → feature_names.json sırası
// ---------------------------------------------------------------
enum DosFeatureIndex : unsigned {
    // Mevcut 11 (XGBoost generic ile aynı sıra)
    DOS_FI_DUR      = 0,   // Flow süresi (saniye)
    DOS_FI_SBYTES   = 1,   // Client → Server toplam byte
    DOS_FI_DBYTES   = 2,   // Server → Client toplam byte
    DOS_FI_SPKTS    = 3,   // Client → Server paket sayısı
    DOS_FI_DPKTS    = 4,   // Server → Client paket sayısı
    DOS_FI_SMEANSZ  = 5,   // Client ortalama paket boyutu
    DOS_FI_DMEANSZ  = 6,   // Server ortalama paket boyutu
    DOS_FI_SINTPKT  = 7,   // Client ortalama IAT (ms)
    DOS_FI_DINTPKT  = 8,  // Server ortalama IAT (ms)
    DOS_FI_SWIN     = 9,   // Client TCP window (ilk)
    DOS_FI_DWIN     = 10,   // Server TCP window (ilk)
    // Yeni 6 (DoS-spesifik)
    DOS_FI_FLOW_IAT_MEAN = 11,  // Tüm paketlerin ortalama IAT (ms)
    DOS_FI_FLOW_IAT_STD  = 12,  // Tüm paketlerin IAT std (ms)
    DOS_FI_PKT_LEN_MEAN  = 13,  // Tüm paketlerin ortalama boyutu (byte)
    DOS_FI_PKT_LEN_STD   = 14,  // Tüm paketlerin boyut std (byte)
    DOS_FI_RST_COUNT     = 15,  // TCP RST bayrak sayısı
    DOS_FI_URG_COUNT     = 16,  // TCP URG bayrak sayısı
    DOS_FI_COUNT         = 17   // Toplam feature sayısı
};

struct DosScalerParams {
    double median[DOS_FI_COUNT];
    double iqr[DOS_FI_COUNT];
};

// log1p dönüşümü gereken feature'lar
// XGBoost tree split-based olduğu için scaler GEREKMEZ,
// ancak eğitim pipeline ile tutarlılık için uygulanır.
inline bool dos_needs_log1p(unsigned idx) {
    return idx == DOS_FI_DUR      ||
           idx == DOS_FI_SPKTS    ||
           idx == DOS_FI_DPKTS    ||
           idx == DOS_FI_SBYTES   ||
           idx == DOS_FI_DBYTES   ||
           idx == DOS_FI_SINTPKT  ||
           idx == DOS_FI_DINTPKT  ||
           idx == DOS_FI_FLOW_IAT_MEAN ||
           idx == DOS_FI_FLOW_IAT_STD  ||
           idx == DOS_FI_PKT_LEN_MEAN  ||
           idx == DOS_FI_PKT_LEN_STD;
}

// ---------------------------------------------------------------
// DosFlowData: Snort3 FlowData alt sınıfı (DoS Specialist için)
// ---------------------------------------------------------------
class DosFlowData : public snort::FlowData {
public:
    DosFlowData(unsigned id) : snort::FlowData(id) { reset(); }
    ~DosFlowData() override = default;

    static unsigned inspector_id;

    void reset() {
        first_pkt_ts  = 0.0;
        last_pkt_ts   = 0.0;
        last_any_ts   = 0.0;
        spkts  = 0;  dpkts  = 0;
        sbytes = 0;  dbytes = 0;
        swin   = -1; dwin   = -1;
        last_src_ts  = 0.0;  last_dst_ts  = 0.0;
        src_iat_sum  = 0.0;  dst_iat_sum  = 0.0;
        // IAT std için M2 (Welford online algorithm)
        flow_iat_n    = 0;
        flow_iat_mean_acc = 0.0;
        flow_iat_M2   = 0.0;
        // Paket boyutu istatistikleri (Welford)
        pkt_len_n     = 0;
        pkt_len_mean_acc = 0.0;
        pkt_len_M2    = 0.0;
        // TCP bayraklar
        rst_count = 0;
        urg_count = 0;
        // Genel
        total_packets = 0;
        inference_done = false;
    }

    // Her pakette çağrılır
    void update(bool is_from_client, uint32_t payload_len,
                int32_t tcp_win, uint8_t tcp_flags, double pkt_ts) {

        if (total_packets == 0)
            first_pkt_ts = pkt_ts;
        last_pkt_ts = pkt_ts;

        // ── Yön-bazlı istatistikler ──────────────────────────────
        if (is_from_client) {
            spkts++;
            sbytes += payload_len;
            if (swin < 0 && tcp_win >= 0) swin = tcp_win;
            if (last_src_ts > 0.0) src_iat_sum += (pkt_ts - last_src_ts);
            last_src_ts = pkt_ts;
        } else {
            dpkts++;
            dbytes += payload_len;
            if (dwin < 0 && tcp_win >= 0) dwin = tcp_win;
            if (last_dst_ts > 0.0) dst_iat_sum += (pkt_ts - last_dst_ts);
            last_dst_ts = pkt_ts;
        }

        // ── Flow-level IAT (Welford online mean+variance) ────────
        if (last_any_ts > 0.0) {
            double iat_ms = (pkt_ts - last_any_ts) * 1000.0;
            flow_iat_n++;
            double delta  = iat_ms - flow_iat_mean_acc;
            flow_iat_mean_acc += delta / flow_iat_n;
            double delta2 = iat_ms - flow_iat_mean_acc;
            flow_iat_M2   += delta * delta2;
        }
        last_any_ts = pkt_ts;

        // ── Paket boyutu istatistikleri (Welford) ────────────────
        {
            double len = static_cast<double>(payload_len);
            pkt_len_n++;
            double delta  = len - pkt_len_mean_acc;
            pkt_len_mean_acc += delta / pkt_len_n;
            double delta2 = len - pkt_len_mean_acc;
            pkt_len_M2   += delta * delta2;
        }

        // ── TCP bayraklar ────────────────────────────────────────
        // tcp_flags: ham TCP flag byte (RST=0x04, URG=0x20)
        if (tcp_flags & 0x04) rst_count++;  // RST
        if (tcp_flags & 0x20) urg_count++;  // URG

        total_packets++;
    }

    // Ham feature vektörünü doldur
    void compute_features(double* raw) const {
        // --- Mevcut 11 ---
        raw[DOS_FI_DUR]     = last_pkt_ts - first_pkt_ts;
        raw[DOS_FI_SPKTS]   = static_cast<double>(spkts);
        raw[DOS_FI_DPKTS]   = static_cast<double>(dpkts);
        raw[DOS_FI_SBYTES]  = static_cast<double>(sbytes);
        raw[DOS_FI_DBYTES]  = static_cast<double>(dbytes);
        raw[DOS_FI_SMEANSZ] = (spkts > 0) ? static_cast<double>(sbytes) / spkts : 0.0;
        raw[DOS_FI_DMEANSZ] = (dpkts > 0) ? static_cast<double>(dbytes) / dpkts : 0.0;
        raw[DOS_FI_SWIN]    = (swin >= 0) ? static_cast<double>(swin) : 0.0;
        raw[DOS_FI_DWIN]    = (dwin >= 0) ? static_cast<double>(dwin) : 0.0;
        raw[DOS_FI_SINTPKT] = (spkts > 1) ? (src_iat_sum / (spkts - 1)) * 1000.0 : 0.0;
        raw[DOS_FI_DINTPKT] = (dpkts > 1) ? (dst_iat_sum / (dpkts - 1)) * 1000.0 : 0.0;

        // --- Yeni 6 ---
        raw[DOS_FI_FLOW_IAT_MEAN] = flow_iat_mean_acc;  // zaten ms cinsinden

        // Welford variance: M2 / n (population std; n>=2 yoksa 0)
        raw[DOS_FI_FLOW_IAT_STD]  = (flow_iat_n >= 2)
            ? std::sqrt(flow_iat_M2 / flow_iat_n) : 0.0;

        raw[DOS_FI_PKT_LEN_MEAN]  = pkt_len_mean_acc;

        raw[DOS_FI_PKT_LEN_STD]   = (pkt_len_n >= 2)
            ? std::sqrt(pkt_len_M2 / pkt_len_n) : 0.0;

        raw[DOS_FI_RST_COUNT]     = static_cast<double>(rst_count);
        raw[DOS_FI_URG_COUNT]     = static_cast<double>(urg_count);
    }

    // log1p + RobustScaler (eğitim pipeline ile aynı dönüşüm)
    // [VARSAYIM] scaler parametreleri mp_2 varyantı için geçerli
    static void preprocess(double* features, const DosScalerParams& params) {
        // Adım 1: log1p — negatif değer olamaz (sayaçlar/byte'lar)
        for (unsigned i = 0; i < DOS_FI_COUNT; i++) {
            if (dos_needs_log1p(i)) {
                // Güvenlik: negatif giriş koruma
                features[i] = std::log1p(std::max(0.0, features[i]));
            }
        }
        // Adım 2: RobustScaler
        for (unsigned i = 0; i < DOS_FI_COUNT; i++) {
            if (params.iqr[i] != 0.0)
                features[i] = (features[i] - params.median[i]) / params.iqr[i];
            else
                features[i] = 0.0;
        }
    }

    uint32_t get_total_packets() const { return total_packets; }
    bool     is_inference_done() const { return inference_done; }
    void     mark_inference_done()     { inference_done = true; }

private:
    // Timestamp'ler
    double first_pkt_ts;
    double last_pkt_ts;
    double last_any_ts;      // Flow-level IAT için son paket ts

    // Yön-bazlı sayaçlar
    uint32_t spkts, dpkts;
    uint64_t sbytes, dbytes;
    int32_t  swin, dwin;
    double   last_src_ts, last_dst_ts;
    double   src_iat_sum, dst_iat_sum;

    // Flow-level IAT — Welford online algorithm
    uint64_t flow_iat_n;
    double   flow_iat_mean_acc;
    double   flow_iat_M2;

    // Paket boyutu istatistikleri — Welford
    uint64_t pkt_len_n;
    double   pkt_len_mean_acc;
    double   pkt_len_M2;

    // TCP bayraklar
    uint32_t rst_count;
    uint32_t urg_count;

    // Genel
    uint32_t total_packets;
    bool     inference_done;
};

#endif // DOS_SPECIALIST_FLOW_TRACKER_H