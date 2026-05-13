// portscan_flow_tracker.h — Snort3 PortScan Inspector: TCP SYN per-IP aggregation
// 7 features for XGBoost.

#ifndef PORTSCAN_INSPECTOR_FLOW_TRACKER_H
#define PORTSCAN_INSPECTOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "flow/flow_data.h"

static constexpr unsigned AGG_FEATURE_COUNT = 7;

enum PsiAggFeatureIndex : unsigned {
    AGG_FI_TOTAL_SYNS          = 0,
    AGG_FI_UNIQUE_DST_PORTS    = 1,
    AGG_FI_UNIQUE_DST_IPS      = 2,
    AGG_FI_DST_PORT_ENTROPY    = 3,
    AGG_FI_SRC_PORT_RANGE      = 4,
    AGG_FI_UNIQUE_PORT_RATIO   = 5,
    AGG_FI_SYN_RATE            = 6,
};

struct PsiAggScalerParams {
    double median[AGG_FEATURE_COUNT];
    double iqr[AGG_FEATURE_COUNT];
};

struct PsiAggProfile {
    uint32_t src_ip;
    double   window_start_ts;

    std::unordered_set<uint16_t> dst_ports;
    std::unordered_set<uint32_t> dst_ips;
    std::unordered_map<uint16_t, uint32_t> port_counts;
    uint32_t total_syns;
    uint16_t min_src_port;
    uint16_t max_src_port;
    bool     src_port_init;

    bool inference_done;

    void reset(uint32_t ip, double ts) {
        src_ip = ip;
        window_start_ts = ts;
        dst_ports.clear();
        dst_ips.clear();
        port_counts.clear();
        total_syns = 0;
        min_src_port = 0;
        max_src_port = 0;
        src_port_init = false;
        inference_done = false;
    }

    void add_packet(uint32_t dst_ip, uint16_t dst_port,
                    uint16_t src_port, uint8_t pkt_type_ignored,
                    uint8_t ttl_ignored = 0) {
        dst_ports.insert(dst_port);
        dst_ips.insert(dst_ip);
        port_counts[dst_port]++;
        total_syns++;
        if (!src_port_init) {
            min_src_port = src_port;
            max_src_port = src_port;
            src_port_init = true;
        } else {
            if (src_port < min_src_port) min_src_port = src_port;
            if (src_port > max_src_port) max_src_port = src_port;
        }
    }

    void compute_features(double* raw, double window_sec) const {
        double tf = static_cast<double>(total_syns);
        double np = static_cast<double>(dst_ports.size());
        raw[AGG_FI_TOTAL_SYNS]          = tf;
        raw[AGG_FI_UNIQUE_DST_PORTS]    = np;
        raw[AGG_FI_UNIQUE_DST_IPS]      = static_cast<double>(dst_ips.size());
        double entropy = 0.0;
        if (tf > 1 && !port_counts.empty()) {
            for (const auto& kv : port_counts) {
                double p = static_cast<double>(kv.second) / tf;
                entropy -= p * std::log2(p);
            }
        }
        raw[AGG_FI_DST_PORT_ENTROPY]    = entropy;
        raw[AGG_FI_SRC_PORT_RANGE]      = src_port_init ?
            static_cast<double>(max_src_port) - static_cast<double>(min_src_port) : 0.0;
        raw[AGG_FI_UNIQUE_PORT_RATIO]   = tf > 0 ? np / tf : 0.0;
        raw[AGG_FI_SYN_RATE]            = window_sec > 0 ? tf / window_sec : 0.0;
    }

    static void preprocess(double* features, const PsiAggScalerParams& params) {
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++)
            features[i] = std::log1p(features[i]);
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) {
            if (params.iqr[i] != 0.0)
                features[i] = (features[i] - params.median[i]) / params.iqr[i];
            else
                features[i] = 0.0;
        }
    }

    bool is_window_expired(double now, double window_sec) const {
        return total_syns > 0 && (now - window_start_ts) >= window_sec;
    }
};

#endif // PORTSCAN_INSPECTOR_FLOW_TRACKER_H
