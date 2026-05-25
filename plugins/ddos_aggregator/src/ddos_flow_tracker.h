// ddos_flow_tracker.h — Cross-flow DDoS (per destination IP:PORT)
// 7 features — tracks SYNs+UDP to a specific IP:PORT

#ifndef DDOS_AGGREGATOR_FLOW_TRACKER_H
#define DDOS_AGGREGATOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "flow/flow_data.h"

static constexpr unsigned AGG_FEATURE_COUNT = 7;

struct DdsAggScalerParams {
    double median[AGG_FEATURE_COUNT];
    double iqr[AGG_FEATURE_COUNT];
};

// Key: (dst_ip << 16) | dst_port — unique service endpoint
struct DdsAggProfile {
    uint64_t key;  // (dst_ip << 32) | dst_port
    double   window_start_ts;

    uint32_t syn_count;
    std::unordered_set<uint32_t> syn_src_ips;
    std::unordered_set<uint16_t> syn_src_ports;
    uint32_t total_packets;

    bool inference_done;

    void reset(uint64_t k, double ts) {
        key = k; window_start_ts = ts;
        syn_count = 0; syn_src_ips.clear(); syn_src_ports.clear();
        total_packets = 0;
        inference_done = false;
    }

    void add_syn(uint32_t src_ip, uint16_t src_port) {
        syn_count++; syn_src_ips.insert(src_ip); syn_src_ports.insert(src_port);
        total_packets++;
    }

    void add_udp(uint32_t src_ip) {
        total_packets++;
    }

    void compute_features(double* raw, double window_sec) const {
        double tf = static_cast<double>(syn_count + total_packets);
        raw[0] = tf;
        raw[1] = static_cast<double>(syn_src_ips.size());
        raw[2] = static_cast<double>(syn_src_ports.size());
        raw[3] = (syn_src_ips.size() > 0) ? static_cast<double>(syn_src_ports.size()) / syn_src_ips.size() : 0.0;  // ports per src
        raw[4] = 0.0;  // reserved placeholder
        raw[5] = tf > 0 ? static_cast<double>(syn_src_ips.size()) / tf : 0.0;
        raw[6] = window_sec > 0 ? tf / window_sec : 0.0;
    }

    static void preprocess(double* f, const DdsAggScalerParams& p) {
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) f[i] = std::log1p(f[i]);
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++)
            f[i] = (p.iqr[i] != 0.0) ? (f[i] - p.median[i]) / p.iqr[i] : 0.0;
    }

    bool is_window_expired(double now, double w) const {
        return (syn_count + total_packets) > 0 && (now - window_start_ts) >= w;
    }
};

#endif
