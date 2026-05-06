// flow_tracker_xgboost.h — Snort3 XGBoost Inspector: Per-flow feature tracker
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// LSTM flow_tracker'dan ayrı tutulur — ODR çakışmasını önlemek için
// sınıf adı XgbFlowData, guard macro XGB_INSPECTOR_FLOW_TRACKER_H
// Fark: swin/dwin clamp YOK (XGBoost için kasıtlı)

#ifndef XGB_INSPECTOR_FLOW_TRACKER_H
#define XGB_INSPECTOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>

#include "flow/flow_data.h"

// Feature vektörü indeksleri (Python eğitim sırasıyla aynı)
// XGB_FI_ prefix ile LSTM enum'dan ayrıştırıldı
enum XgbFeatureIndex : unsigned {
    XGB_FI_DUR = 0,
    XGB_FI_SPKTS,
    XGB_FI_DPKTS,
    XGB_FI_SBYTES,
    XGB_FI_DBYTES,
    XGB_FI_SMEANSZ,
    XGB_FI_DMEANSZ,
    XGB_FI_SWIN,
    XGB_FI_DWIN,
    XGB_FI_SINTPKT,
    XGB_FI_DINTPKT,
    XGB_FI_COUNT  // = 11
};

struct XgbScalerParams {
    double median[XGB_FI_COUNT];
    double iqr[XGB_FI_COUNT];
};

inline bool xgb_needs_log1p(unsigned idx) {
    return idx == XGB_FI_DUR    || idx == XGB_FI_SPKTS  || idx == XGB_FI_DPKTS  ||
           idx == XGB_FI_SBYTES || idx == XGB_FI_DBYTES || idx == XGB_FI_SINTPKT ||
           idx == XGB_FI_DINTPKT;
}

// ---------------------------------------------------------------
// XgbFlowData: Snort3 FlowData alt sınıfı (XGBoost inspector için)
// ---------------------------------------------------------------
class XgbFlowData : public snort::FlowData {
public:
    XgbFlowData(unsigned id) : snort::FlowData(id) { reset(); }
    ~XgbFlowData() override = default;

    static unsigned inspector_id;

    void reset() {
        first_pkt_ts = 0.0;
        last_pkt_ts  = 0.0;
        spkts = 0; dpkts = 0;
        sbytes = 0; dbytes = 0;
        swin = -1; dwin = -1;
        last_src_ts = 0.0; last_dst_ts = 0.0;
        src_iat_sum = 0.0; dst_iat_sum = 0.0;
        total_packets = 0;
        inference_done = false;
    }

    void update(bool is_from_client, uint32_t payload_len,
                int32_t tcp_win, double pkt_ts) {
        if (total_packets == 0)
            first_pkt_ts = pkt_ts;
        last_pkt_ts = pkt_ts;

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
        total_packets++;
    }

    void compute_features(double* raw) const {
        raw[XGB_FI_DUR]     = last_pkt_ts - first_pkt_ts;
        raw[XGB_FI_SPKTS]   = static_cast<double>(spkts);
        raw[XGB_FI_DPKTS]   = static_cast<double>(dpkts);
        raw[XGB_FI_SBYTES]  = static_cast<double>(sbytes);
        raw[XGB_FI_DBYTES]  = static_cast<double>(dbytes);
        raw[XGB_FI_SMEANSZ] = (spkts > 0) ? static_cast<double>(sbytes) / spkts : 0.0;
        raw[XGB_FI_DMEANSZ] = (dpkts > 0) ? static_cast<double>(dbytes) / dpkts : 0.0;
        raw[XGB_FI_SWIN]    = (swin >= 0) ? static_cast<double>(swin) : 0.0;
        raw[XGB_FI_DWIN]    = (dwin >= 0) ? static_cast<double>(dwin) : 0.0;
        raw[XGB_FI_SINTPKT] = (spkts > 1) ? (src_iat_sum / (spkts - 1)) * 1000.0 : 0.0;
        raw[XGB_FI_DINTPKT] = (dpkts > 1) ? (dst_iat_sum / (dpkts - 1)) * 1000.0 : 0.0;
    }

    // log1p + RobustScaler — clamp YOK (XGBoost için kasıtlı)
    static void preprocess(double* features, const XgbScalerParams& params) {
        for (unsigned i = 0; i < XGB_FI_COUNT; i++) {
            if (xgb_needs_log1p(i))
                features[i] = std::log1p(features[i]);
        }
        for (unsigned i = 0; i < XGB_FI_COUNT; i++) {
            if (params.iqr[i] != 0.0)
                features[i] = (features[i] - params.median[i]) / params.iqr[i];
            else
                features[i] = 0.0;
        }
    }

    uint32_t get_total_packets() const { return total_packets; }
    bool is_inference_done() const     { return inference_done; }
    void mark_inference_done()         { inference_done = true; }

private:
    double   first_pkt_ts, last_pkt_ts;
    uint32_t spkts, dpkts;
    uint64_t sbytes, dbytes;
    int32_t  swin, dwin;
    double   last_src_ts, last_dst_ts;
    double   src_iat_sum, dst_iat_sum;
    uint32_t total_packets;
    bool     inference_done;
};

#endif // XGB_INSPECTOR_FLOW_TRACKER_H