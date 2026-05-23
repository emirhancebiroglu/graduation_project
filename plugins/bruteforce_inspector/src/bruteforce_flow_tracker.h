#ifndef BRUTEFORCE_INSPECTOR_FLOW_TRACKER_H
#define BRUTEFORCE_INSPECTOR_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <unordered_set>

static constexpr unsigned AGG_FEATURE_COUNT = 7;

struct BfcScalerParams {
    double median[AGG_FEATURE_COUNT];
    double iqr[AGG_FEATURE_COUNT];
};

struct BfcProfile {
    uint32_t src_ip;
    double   window_start_ts;

    uint32_t syn_count;
    std::unordered_set<uint32_t> syn_dst_ips;
    std::unordered_set<uint16_t> syn_dst_ports;
    std::unordered_map<uint16_t, uint32_t> syn_dst_port_counts;
    std::deque<double> syn_timestamps;

    bool inference_done;

    void reset(uint32_t ip, double ts) {
        src_ip = ip; window_start_ts = ts;
        syn_count = 0; syn_dst_ips.clear();
        syn_dst_ports.clear(); syn_dst_port_counts.clear();
        syn_timestamps.clear();
        inference_done = false;
    }

    void add_syn(uint32_t dip, uint16_t dport, double ts) {
        syn_count++;
        syn_dst_ips.insert(dip);
        syn_dst_ports.insert(dport);
        syn_dst_port_counts[dport]++;
        syn_timestamps.push_back(ts);
    }

    double iat_cv() const {
        if (syn_timestamps.size() < 3) return 0.0;
        double sum = 0.0, sum_sq = 0.0;
        int n = 0;
        for (size_t i = 1; i < syn_timestamps.size(); i++) {
            double diff = syn_timestamps[i] - syn_timestamps[i-1];
            if (diff < 1e-6) continue;
            sum += diff; sum_sq += diff * diff;
            n++;
        }
        if (n < 2) return 0.0;
        double mean = sum / n;
        double var = (sum_sq / n) - (mean * mean);
        if (var < 0) var = 0;
        double std = std::sqrt(var);
        return (mean > 1e-6) ? std / mean : 0.0;
    }

    double single_port_score() const {
        if (syn_count == 0 || syn_dst_port_counts.empty()) return 0.0;
        uint32_t max_count = 0;
        for (const auto& kv : syn_dst_port_counts) {
            if (kv.second > max_count) max_count = kv.second;
        }
        return static_cast<double>(max_count) / static_cast<double>(syn_count);
    }

    void compute_features(double* raw, double window_sec) const {
        double tf = static_cast<double>(syn_count);
        raw[0] = tf;
        raw[1] = static_cast<double>(syn_dst_ips.size());
        raw[2] = static_cast<double>(syn_dst_ports.size());
        raw[3] = tf > 0 ? static_cast<double>(syn_dst_ports.size()) / tf : 0.0;
        raw[4] = single_port_score();
        raw[5] = window_sec > 0 ? tf / window_sec : 0.0;
        raw[6] = iat_cv();
    }

    static void preprocess(double* f, const BfcScalerParams& p) {
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) f[i] = std::log1p(f[i]);
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++)
            f[i] = (p.iqr[i] != 0.0) ? (f[i] - p.median[i]) / p.iqr[i] : 0.0;
    }

    bool is_window_expired(double now, double w) const {
        return syn_count > 0 && (now - window_start_ts) >= w;
    }
};

#endif
