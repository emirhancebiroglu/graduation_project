// flow_tracker.h — Snort3 ML Inspector: Per-flow feature tracker
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// Her TCP/UDP akışı için 11 özelliği toplar:
// dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz,
// swin, dwin, sintpkt, dintpkt

#ifndef ML_INSPECTOR_FLOW_TRACKER_H
#define ML_INSPECTOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>

#include "flow/flow_data.h"

// Feature vektörü indeksleri (Python eğitim sırasıyla aynı)
enum FeatureIndex : unsigned {
  FI_DUR = 0,
  FI_SPKTS,
  FI_DPKTS,
  FI_SBYTES,
  FI_DBYTES,
  FI_SMEANSZ,
  FI_DMEANSZ,
  FI_SWIN,
  FI_DWIN,
  FI_SINTPKT,
  FI_DINTPKT,
  FI_COUNT // = 11
};

// RobustScaler parametreleri — Python'dan export edilecek
// [VARSAYIM: Bu değerler prepare_lstmdataset.py çıktısındaki scaler.pkl'den
// alınacak.
//  Şimdilik placeholder, Faz 1 ikinci adımda Python script ile export
//  edeceğiz.]
struct ScalerParams {
  double median[FI_COUNT];
  double iqr[FI_COUNT]; // Q3 - Q1 (scale_ parametresi)
};

// Log1p dönüşümü uygulanacak kolonlar
// Python'daki: ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt',
// 'dintpkt']
inline bool needs_log1p(unsigned idx) {
  return idx == FI_DUR || idx == FI_SPKTS || idx == FI_DPKTS ||
         idx == FI_SBYTES || idx == FI_DBYTES || idx == FI_SINTPKT ||
         idx == FI_DINTPKT;
}

// ---------------------------------------------------------------
// MlFlowData: Snort3 FlowData alt sınıfı
// Her flow'a bağlanır, paket bazında güncellenir.
// ---------------------------------------------------------------
class MlFlowData : public snort::FlowData {
public:
  MlFlowData(unsigned id) : snort::FlowData(id) { reset(); }
  ~MlFlowData() override = default;

  // FlowData kimliği (inspector tarafından atanır)
  static unsigned inspector_id;

  void reset() {
    first_pkt_ts = 0.0;
    last_pkt_ts = 0.0;

    spkts = 0;
    dpkts = 0;
    sbytes = 0;
    dbytes = 0;

    swin = -1; // henüz görülmedi
    dwin = -1;

    // Inter-arrival time hesabı için
    last_src_ts = 0.0;
    last_dst_ts = 0.0;
    src_iat_sum = 0.0;
    dst_iat_sum = 0.0;

    total_packets = 0;
    inference_done = false;
  }

  // ----- Paket güncelleme -----
  // is_from_client: Snort3'ün Packet::is_from_client() sonucu
  // payload_len: Packet::dsize (payload byte sayısı)
  // tcp_win: TCP window değeri (TCP değilse 0)
  // pkt_ts: Paket timestamp (saniye, double)
  void update(bool is_from_client, uint32_t payload_len, int32_t tcp_win,
              double pkt_ts) {
    // İlk paket timestamp'i kaydet
    if (total_packets == 0)
      first_pkt_ts = pkt_ts;
    last_pkt_ts = pkt_ts;

    if (is_from_client) {
      spkts++;
      sbytes += payload_len;

      // İlk SYN paketinin window değeri
      if (swin < 0 && tcp_win >= 0)
        swin = tcp_win;

      // Inter-arrival time (src yönü)
      if (last_src_ts > 0.0)
        src_iat_sum += (pkt_ts - last_src_ts);
      last_src_ts = pkt_ts;
    } else {
      dpkts++;
      dbytes += payload_len;

      // İlk SYN-ACK paketinin window değeri
      if (dwin < 0 && tcp_win >= 0)
        dwin = tcp_win;

      // Inter-arrival time (dst yönü)
      if (last_dst_ts > 0.0)
        dst_iat_sum += (pkt_ts - last_dst_ts);
      last_dst_ts = pkt_ts;
    }

    total_packets++;
  }

  // ----- Feature vektörü oluşturma -----
  // raw_features[FI_COUNT] dizisine ham değerleri yazar
  void compute_features(double *raw_features) const {
    // dur: saniye cinsinden süre
    raw_features[FI_DUR] = last_pkt_ts - first_pkt_ts;

    // Paket ve byte sayıları
    raw_features[FI_SPKTS] = static_cast<double>(spkts);
    raw_features[FI_DPKTS] = static_cast<double>(dpkts);
    raw_features[FI_SBYTES] = static_cast<double>(sbytes);
    raw_features[FI_DBYTES] = static_cast<double>(dbytes);

    // Ortalama paket boyutları
    raw_features[FI_SMEANSZ] =
        (spkts > 0) ? static_cast<double>(sbytes) / spkts : 0.0;
    raw_features[FI_DMEANSZ] =
        (dpkts > 0) ? static_cast<double>(dbytes) / dpkts : 0.0;

    // TCP window (görülmediyse 0)
    raw_features[FI_SWIN] = (swin >= 0) ? static_cast<double>(swin) : 0.0;
    raw_features[FI_DWIN] = (dwin >= 0) ? static_cast<double>(dwin) : 0.0;

    // Ortalama inter-arrival time (milisaniye)
    // spkts-1 çünkü ilk paketin IAT'si yok
    if (spkts > 1)
      raw_features[FI_SINTPKT] = (src_iat_sum / (spkts - 1)) * 1000.0;
    else
      raw_features[FI_SINTPKT] = 0.0;

    if (dpkts > 1)
      raw_features[FI_DINTPKT] = (dst_iat_sum / (dpkts - 1)) * 1000.0;
    else
      raw_features[FI_DINTPKT] = 0.0;
  }

  // ----- Preprocessing: log1p + RobustScaler -----
  // Python pipeline ile aynı dönüşüm:
  //   1) Belirli kolonlara log1p uygula
  //   2) RobustScaler: (x - median) / iqr
  static void preprocess(double *features, const ScalerParams &params) {
    // Adım 1: log1p dönüşümü
    for (unsigned i = 0; i < FI_COUNT; i++) {
      if (needs_log1p(i))
        features[i] = std::log1p(features[i]);
    }

    if (features[FI_SWIN] > 1020.0)
      features[FI_SWIN] = 1020.0;
    if (features[FI_DWIN] > 1020.0)
      features[FI_DWIN] = 1020.0;

    // Adım 2: RobustScaler
    for (unsigned i = 0; i < FI_COUNT; i++) {
      if (params.iqr[i] != 0.0)
        features[i] = (features[i] - params.median[i]) / params.iqr[i];
      else
        features[i] = 0.0; // IQR sıfırsa (sabit kolon), sıfır yap
    }
  }

  // ----- Durum sorguları -----
  uint32_t get_total_packets() const { return total_packets; }
  bool is_inference_done() const { return inference_done; }
  void mark_inference_done() { inference_done = true; }

private:
  // Timestamp'ler (saniye, epoch)
  double first_pkt_ts;
  double last_pkt_ts;

  // Sayaçlar
  uint32_t spkts;
  uint32_t dpkts;
  uint64_t sbytes;
  uint64_t dbytes;

  // TCP window (ilk gelen)
  int32_t swin;
  int32_t dwin;

  // Inter-arrival time hesabı
  double last_src_ts;
  double last_dst_ts;
  double src_iat_sum;
  double dst_iat_sum;

  // Genel
  uint32_t total_packets;
  bool inference_done;
};

#endif // ML_INSPECTOR_FLOW_TRACKER_H
