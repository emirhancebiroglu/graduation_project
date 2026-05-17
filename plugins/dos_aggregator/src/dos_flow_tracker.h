// dos_flow_tracker.h — Cross-flow DoS aggregation (SYN rate per source IP)
// 7 features for XGBoost — same schema as PortScan aggregator

#ifndef DOS_AGGREGATOR_FLOW_TRACKER_H
#define DOS_AGGREGATOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "flow/flow_data.h"

static constexpr unsigned AGG_FEATURE_COUNT = 7;

struct DasAggScalerParams {
    double median[AGG_FEATURE_COUNT];
    double iqr[AGG_FEATURE_COUNT];
};

struct DasAggProfile {
    uint32_t src_ip;
    double   window_start_ts;

    uint32_t syn_count;
    std::unordered_set<uint16_t> syn_dst_ports;
    std::unordered_map<uint16_t, uint32_t> syn_port_counts;
    std::unordered_set<uint32_t> syn_dst_ips;
    uint16_t min_src_port, max_src_port;
    bool     src_port_init;

    bool inference_done;

    void reset(uint32_t ip, double ts) {
        src_ip = ip; window_start_ts = ts;
        syn_count = 0; syn_dst_ports.clear(); syn_port_counts.clear(); syn_dst_ips.clear();
        min_src_port = 0; max_src_port = 0; src_port_init = false;
        inference_done = false;
    }

    void add_syn(uint32_t dip, uint16_t dport, uint16_t sport) {
        syn_count++; syn_dst_ports.insert(dport); syn_port_counts[dport]++; syn_dst_ips.insert(dip);
        if (!src_port_init) { min_src_port=sport; max_src_port=sport; src_port_init=true; }
        else { if(sport<min_src_port) min_src_port=sport; if(sport>max_src_port) max_src_port=sport; }
    }

    void compute_features(double* raw, double window_sec) const {
        double tf = static_cast<double>(syn_count);
        raw[0] = tf;
        raw[1] = static_cast<double>(syn_dst_ports.size());
        raw[2] = static_cast<double>(syn_dst_ips.size());
        double entropy = 0.0;
        if (tf > 1 && !syn_port_counts.empty()) {
            for (const auto& kv : syn_port_counts) {
                double p = static_cast<double>(kv.second) / tf;
                entropy -= p * std::log2(p);
            }
        }
        raw[3] = entropy;
        raw[4] = src_port_init ? static_cast<double>(max_src_port) - static_cast<double>(min_src_port) : 0.0;
        raw[5] = tf > 0 ? static_cast<double>(syn_dst_ports.size()) / tf : 0.0;
        raw[6] = window_sec > 0 ? tf / window_sec : 0.0;
    }

    static void preprocess(double* f, const DasAggScalerParams& p) {
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) f[i] = std::log1p(f[i]);
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++)
            f[i] = (p.iqr[i] != 0.0) ? (f[i] - p.median[i]) / p.iqr[i] : 0.0;
    }

    bool is_window_expired(double now, double w) const {
        return syn_count > 0 && (now - window_start_ts) >= w;
    }
};

#endif
