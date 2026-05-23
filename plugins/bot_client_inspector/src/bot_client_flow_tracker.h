#ifndef BOT_CLIENT_FLOW_TRACKER_H
#define BOT_CLIENT_FLOW_TRACKER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

static constexpr unsigned AGG_FEATURE_COUNT = 22;

struct BclScalerParams {
    double median[AGG_FEATURE_COUNT];
    double iqr[AGG_FEATURE_COUNT];
};

struct BclProfile {
    uint32_t src_ip;
    double   window_start_ts;

    uint32_t syn_count;
    std::unordered_set<uint32_t> syn_dst_ips;
    std::unordered_set<uint16_t> syn_dst_ports;
    std::unordered_map<uint16_t, uint32_t> syn_dst_port_counts;
    std::unordered_map<uint32_t, uint32_t> syn_dst_ip_counts;
    std::deque<double> syn_timestamps;
    
    uint32_t rst_count;
    uint32_t internal_dst_count;
    uint32_t handshake_count;
    uint32_t incoming_pkt_count;
    uint64_t incoming_bytes;
    uint32_t fin_count;
    uint32_t push_count;
    double   tcp_window_sum;
    uint32_t tcp_window_count;

    bool inference_done;
    double last_alert_time = 0;

    void reset(uint32_t ip, double ts) {
        src_ip = ip; window_start_ts = ts;
        syn_count = 0;
        syn_dst_ips.clear(); syn_dst_ports.clear();
        syn_dst_port_counts.clear(); syn_dst_ip_counts.clear();
        syn_timestamps.clear();
        rst_count = 0;
        internal_dst_count = 0;
        handshake_count = 0;
        incoming_pkt_count = 0;
        incoming_bytes = 0;
        fin_count = 0;
        push_count = 0;
        tcp_window_sum = 0;
        tcp_window_count = 0;
        inference_done = false;
        // last_alert_time preserved across resets
    }

    static bool is_rfc1918(uint32_t ip) {
        uint8_t a = (ip >> 24) & 0xFF;
        uint8_t b = (ip >> 16) & 0xFF;
        return (a == 10) ||
               (a == 172 && b >= 16 && b <= 31) ||
               (a == 192 && b == 168);
    }

    void add_syn(uint32_t dip, uint16_t dport, double ts) {
        syn_count++;
        syn_dst_ips.insert(dip);
        syn_dst_ports.insert(dport);
        syn_dst_port_counts[dport]++;
        syn_dst_ip_counts[dip]++;
        syn_timestamps.push_back(ts);
        if (is_rfc1918(dip)) internal_dst_count++;
    }

    void add_rst() {
        rst_count++;
    }

    void add_handshake() {
        handshake_count++;
    }

    void add_incoming_pkt() {
        incoming_pkt_count++;
    }

    void add_incoming_bytes(uint32_t bytes) {
        incoming_bytes += bytes;
    }

    void add_fin() {
        fin_count++;
    }

    void add_push() {
        push_count++;
    }

    void add_window(uint16_t win) {
        tcp_window_sum += static_cast<double>(win);
        tcp_window_count++;
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

    double iat_q90_q10_ratio() const {
        if (syn_timestamps.size() < 3) return 0.0;
        std::vector<double> diffs;
        for (size_t i = 1; i < syn_timestamps.size(); i++) {
            double diff = syn_timestamps[i] - syn_timestamps[i-1];
            if (diff > 1e-6) diffs.push_back(diff);
        }
        if (diffs.size() < 4) return 0.0;
        std::sort(diffs.begin(), diffs.end());
        size_t p10_idx = diffs.size() / 10;
        size_t p90_idx = (9 * diffs.size()) / 10;
        double p10 = diffs[p10_idx];
        double p90 = diffs[p90_idx];
        return (p10 > 1e-6) ? p90 / p10 : 0.0;
    }

    double ip_concentration() const {
        if (syn_count == 0 || syn_dst_ip_counts.empty()) return 0.0;
        uint32_t max_count = 0;
        for (const auto& kv : syn_dst_ip_counts) {
            if (kv.second > max_count) max_count = kv.second;
        }
        return static_cast<double>(max_count) / syn_count;
    }

    double ip_entropy() const {
        if (syn_count < 2 || syn_dst_ip_counts.empty()) return 0.0;
        double entropy = 0.0;
        for (const auto& kv : syn_dst_ip_counts) {
            double p = static_cast<double>(kv.second) / syn_count;
            if (p > 0) entropy -= p * std::log2(p);
        }
        return entropy;
    }

    double time_density() const {
        if (syn_timestamps.size() < 2) return 0.0;
        std::unordered_set<int> buckets;
        for (double ts : syn_timestamps) {
            buckets.insert(static_cast<int>(ts));
        }
        return static_cast<double>(buckets.size()) / syn_timestamps.size();
    }

    void compute_features(double* raw, double window_sec) const {
        double tf = static_cast<double>(syn_count);
        raw[0] = tf;
        raw[1] = static_cast<double>(syn_dst_ips.size());
        raw[2] = static_cast<double>(syn_dst_ports.size());
        raw[3] = iat_cv();
        
        double port_entropy = 0.0;
        if (tf > 1.0 && !syn_dst_port_counts.empty()) {
            for (const auto& kv : syn_dst_port_counts) {
                double p = static_cast<double>(kv.second) / tf;
                if (p > 0) port_entropy -= p * std::log2(p);
            }
        }
        raw[4] = port_entropy;
        
        raw[5] = tf > 0 ? static_cast<double>(syn_dst_ports.size()) / tf : 0.0;
        raw[6] = window_sec > 0 ? tf / window_sec : 0.0;
        raw[7] = ip_concentration();
        raw[8] = tf > 0 ? static_cast<double>(syn_dst_ips.size()) / tf : 0.0;
        raw[9] = ip_entropy();
        raw[10] = iat_q90_q10_ratio();
        raw[11] = time_density();
        raw[12] = syn_dst_ips.size() > 0 ? static_cast<double>(syn_dst_ports.size()) / syn_dst_ips.size() : 0.0;
        raw[13] = tf > 0 ? static_cast<double>(handshake_count) / tf : 0.0;
        double total_pkts = tf + static_cast<double>(incoming_pkt_count);
        raw[14] = total_pkts > 0 ? static_cast<double>(incoming_pkt_count) / total_pkts : 0.0;
        raw[15] = tf > 0 ? static_cast<double>(incoming_pkt_count) / tf : 0.0;
        raw[16] = syn_count > 0 ? static_cast<double>(rst_count) / syn_count : 0.0;
        raw[17] = syn_count > 0 ? static_cast<double>(internal_dst_count) / syn_count : 0.0;
        raw[18] = tf > 0 ? static_cast<double>(incoming_bytes) / tf : 0.0;  // bytes per SYN
        raw[19] = tf > 0 ? static_cast<double>(fin_count) / tf : 0.0;  // FIN ratio
        raw[20] = tf > 0 ? static_cast<double>(push_count) / tf : 0.0;  // PUSH ratio
        raw[21] = tcp_window_count > 0 ? tcp_window_sum / tcp_window_count : 0.0;  // mean window
    }

    static void preprocess(double* f, const BclScalerParams& p) {
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++)
            f[i] = (p.iqr[i] != 0.0) ? (f[i] - p.median[i]) / p.iqr[i] : 0.0;
    }

    bool is_window_expired(double now, double w) const {
        return syn_count > 0 && (now - window_start_ts) >= w;
    }
};

#endif
