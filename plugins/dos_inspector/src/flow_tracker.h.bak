// flow_tracker.h — Snort3 DoS Inspector: Per-flow feature tracker
// Bitirme Projesi: IDS Performans Karşılaştırma
//
// Fark: swin/dwin clamp YOK (XGBoost için kasıtlı)

#ifndef DOS_INSPECTOR_FLOW_TRACKER_H
#define DOS_INSPECTOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>

#include "flow/flow_data.h"
#include "protocols/tcp.h"

// Feature vektörü indeksleri (Python eğitim sırasıyla aynı)
enum DosFeatureIndex : unsigned {
    DOS_FI_DUR = 0,
    DOS_FI_SPKTS,
    DOS_FI_DPKTS,
    DOS_FI_SBYTES,
    DOS_FI_DBYTES,
    DOS_FI_SMEANSZ,
    DOS_FI_DMEANSZ,
    DOS_FI_SWIN,
    DOS_FI_DWIN,
    DOS_FI_SINTPKT,
    DOS_FI_DINTPKT,
    DOS_FI_COUNT  // = 11
};

struct DosScalerParams {
    double median[DOS_FI_COUNT];
    double iqr[DOS_FI_COUNT];
};

inline bool dos_needs_log1p(unsigned idx) {
    return idx == DOS_FI_DUR    || idx == DOS_FI_SPKTS  || idx == DOS_FI_DPKTS  ||
           idx == DOS_FI_SBYTES || idx == DOS_FI_DBYTES || idx == DOS_FI_SINTPKT ||
           idx == DOS_FI_DINTPKT;
}

// ---------------------------------------------------------------
// DosFlowData: Snort3 FlowData alt sınıfı (DoS inspector için)
// ---------------------------------------------------------------
class DosFlowData : public snort::FlowData {
public:
    DosFlowData(unsigned id) : snort::FlowData(id) { reset(); }
    ~DosFlowData() override = default;

    static unsigned inspector_id;

    enum FlowState : uint8_t { IDLE, WATCH, DONE };

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
        flow_state = IDLE;
        stage1_score = 0.0f;
        rst_count = 0; fin_count = 0; urg_count = 0; syn_count = 0;
    }

    void update(bool is_from_client, uint32_t payload_len,
                int32_t tcp_win, double pkt_ts,
                uint8_t tcp_flags = 0) {
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
        if (tcp_flags & TH_RST) rst_count++;
        if (tcp_flags & TH_FIN) fin_count++;
        if (tcp_flags & TH_URG) urg_count++;
        if (tcp_flags & TH_SYN) syn_count++;
    }

    void compute_features(double* raw) const {
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
        // Flag counts (rst/fin/urg/syn) tracked internally for future v2 model
    }

    // log1p + RobustScaler — clamp YOK (XGBoost için kasıtlı)
    static void preprocess(double* features, const DosScalerParams& params) {
        for (unsigned i = 0; i < DOS_FI_COUNT; i++) {
            if (dos_needs_log1p(i))
                features[i] = std::log1p(features[i]);
        }
        for (unsigned i = 0; i < DOS_FI_COUNT; i++) {
            if (params.iqr[i] != 0.0)
                features[i] = (features[i] - params.median[i]) / params.iqr[i];
            else
                features[i] = 0.0;
        }
    }

    uint32_t get_total_packets() const { return total_packets; }
    bool is_inference_done() const     { return inference_done; }
    void mark_inference_done()         { inference_done = true; }
    FlowState get_state() const        { return flow_state; }
    void set_state(FlowState s)        { flow_state = s; }
    float get_stage1_score() const     { return stage1_score; }
    void set_stage1_score(float s)     { stage1_score = s; }
    uint32_t get_rst_count() const     { return rst_count; }
    uint32_t get_fin_count() const     { return fin_count; }
    uint32_t get_urg_count() const     { return urg_count; }
    uint32_t get_syn_count() const     { return syn_count; }

private:
    double   first_pkt_ts, last_pkt_ts;
    uint32_t spkts, dpkts;
    uint64_t sbytes, dbytes;
    int32_t  swin, dwin;
    double   last_src_ts, last_dst_ts;
    double   src_iat_sum, dst_iat_sum;
    uint32_t  total_packets;
    bool      inference_done;
    FlowState flow_state;
    float     stage1_score;
    uint32_t  rst_count;
    uint32_t  fin_count;
    uint32_t  urg_count;
    uint32_t  syn_count;
};

#endif // DOS_INSPECTOR_FLOW_TRACKER_H