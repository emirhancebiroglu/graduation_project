// dos_inspector.cc — Snort3 DoS Inspector Plugin
// Bitirme Projesi: IDS Performans Karşılaştırma
//
// Per-flow XGBoost model trained on UNSW-NB15 → fine-tuned on CIC-IDS2017
// 11 features, per-flow inference at packet 2 (or flow close)
// H2 state machine: stage 1 at pkt 2, stage 2 at pkt 8
// Filter rules: dst_port IN {53, 137, 389} → suppressed
// Multi-SID: SID=1 generic DoS, SID=2 volumetric, SID=3 slow-rate

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <xgboost/c_api.h>

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "flow_tracker.h"
#include "scaler_loader.h"

// ---------------------------------------------------------------
// Sabitler
// ---------------------------------------------------------------
static const char* s_name = "dos_inspector";
static const char* s_help = "per-flow DoS detection via XGBoost (15 features, v3b)";

static const uint32_t DOS_GID           = 301;
static const uint32_t DOS_SID_GENERIC   = 1;
static const uint32_t DOS_SID_VOLUMETRIC = 2;
static const uint32_t DOS_SID_SLOWRATE  = 3;

unsigned DosFlowData::inspector_id = 0;

// ---------------------------------------------------------------
// RobustScaler parametreleri (15 features — v3b)
// Sıra: dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz,
//       sintpkt, dintpkt,
//       fwd_pkt_mean, bwd_pkt_mean, fin_cnt, ack_cnt, syn_cnt, bwd_iat
// Kaynak: train/train_dos_fpr_opt_v3b.py — CIC+UNSW combined benign scaler
// ---------------------------------------------------------------
DosScalerParams g_scaler_params = {
    // median[15]
    { 0.068405, 1.791759, 1.609438, 6.070738, 7.520235, 67.000000, 174.000000,
      2.646551, 2.324991, 4.219508, 5.164786, 0.000000, 0.000000, 0.000000, 2.324991 },
    // iqr[15]
    { 0.219837, 1.223775, 1.558145, 2.352108, 3.130624, 64.800003, 618.000000,
      3.353946, 3.112733, 0.751934, 2.200156, 1.000000, 2.079442, 1.098612, 3.112733 }
};

// ---------------------------------------------------------------
// Cross-flow SYN rate tracker (Layer 2 FP suppression)
// ---------------------------------------------------------------
static constexpr double   SYN_WINDOW     = 60.0;
static constexpr uint32_t SYN_RATE_MIN   = 30;
static constexpr uint32_t EVICT_INTERVAL = 500;
static constexpr size_t   MAX_TRACKERS   = 10000;

struct SynTracker {
    uint32_t syn_count[2] = {0, 0};
    double   window_start[2] = {0, 0};
    std::unordered_set<uint32_t> dst_ips;
    std::unordered_set<uint16_t> dst_ports;

    void add(uint32_t dst_ip, uint16_t dst_port, double now) {
        dst_ips.insert(dst_ip);
        dst_ports.insert(dst_port);
        for (int i = 0; i < 2; i++) {
            if (window_start[i] == 0) {
                window_start[i] = now;
                syn_count[i] = 1;
            } else if (now - window_start[i] >= SYN_WINDOW) {
                window_start[i] = now;
                syn_count[i] = 1;
            } else {
                syn_count[i]++;
            }
        }
    }

    uint32_t max_rate() const {
        return std::max(syn_count[0], syn_count[1]);
    }

    bool is_attack_pattern() const {
        if (max_rate() < SYN_RATE_MIN) return false;
        double ip_ratio = (double)dst_ips.size() / (double)max_rate();
        if (ip_ratio >= 0.5) return false;
        double port_ratio = (double)dst_ports.size() / (double)max_rate();
        if (port_ratio >= 0.3) return false;
        return true;
    }

    bool is_stale(double now) const {
        return window_start[0] > 0 && (now - window_start[0]) > SYN_WINDOW * 2
            && window_start[1] > 0 && (now - window_start[1]) > SYN_WINDOW * 2;
    }
};

// ---------------------------------------------------------------
// Rule map (multi-SID)
// ---------------------------------------------------------------
static const snort::RuleMap dos_rules[] = {
    { DOS_SID_GENERIC,     "DoS per-flow detected" },
    { DOS_SID_VOLUMETRIC,  "DoS volumetric detected" },
    { DOS_SID_SLOWRATE,    "DoS slow-rate detected" },
    { 0, nullptr }
};

// ---------------------------------------------------------------
// DosModule
// ---------------------------------------------------------------
static const snort::Parameter dos_params[] = {
    { "threshold",   snort::Parameter::PT_REAL,   "0.0:1.0", "0.5",
      "DoS anomaly threshold (0.0-1.0)" },
    { "max_packets", snort::Parameter::PT_INT,    "1:10000", "100",
      "max packets per flow before triggering inference" },
    { "model_path",  snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/dos_fpr_opt_v3b.json",
      "path to stage-1 XGBoost JSON model file" },
    { "dump_path",   snort::Parameter::PT_STRING, nullptr, "none",
      "path for feature dump CSV (training data); set to 'none' to disable" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DosModule : public snort::Module {
public:
    DosModule() : snort::Module(s_name, s_help, dos_params) {}

    const snort::RuleMap* get_rules() const override { return dos_rules; }

    bool set(const char*, snort::Value& val, snort::SnortConfig*) override {
        if      (val.is("threshold"))     threshold   = val.get_real();
        else if (val.is("max_packets"))   max_packets = static_cast<uint32_t>(val.get_int64());
        else if (val.is("model_path"))    model_path  = val.get_string();
        else if (val.is("dump_path"))     dump_path   = val.get_string();
        else return false;
        return true;
    }

    Usage get_usage() const override { return INSPECT; }

    double      threshold     = 0.5;
    uint32_t    max_packets   = 100;
    std::string model_path    = "/home/emirhan/bitirme/models/dos_fpr_opt_v3b.json";
    std::string dump_path     = "none";
};

// ---------------------------------------------------------------
// XGBoost RAII wrapper
// ---------------------------------------------------------------
class XGBoostEngine {
public:
    XGBoostEngine() = default;
    ~XGBoostEngine() { if (booster) XGBoosterFree(booster); }
    XGBoostEngine(const XGBoostEngine&) = delete;
    XGBoostEngine& operator=(const XGBoostEngine&) = delete;

    bool load(const std::string& path) {
        if (XGBoosterCreate(nullptr, 0, &booster) != 0) {
            snort::ErrorMessage("[dos_inspector] Booster olusturulamadi: %s\n",
                XGBGetLastError());
            return false;
        }
        if (XGBoosterLoadModel(booster, path.c_str()) != 0) {
            snort::ErrorMessage("[dos_inspector] Model yuklenemedi: %s - %s\n",
                path.c_str(), XGBGetLastError());
            XGBoosterFree(booster);
            booster = nullptr;
            return false;
        }
        XGBoosterSetParam(booster, "nthread", "1");
        snort::LogMessage("[dos_inspector] Model yuklendi: %s\n", path.c_str());
        ready = true;
        return true;
    }

    bool run(const float* features, float& score) {
        if (!ready) return false;
        DMatrixHandle dmat = nullptr;
        if (XGDMatrixCreateFromMat(features, 1, DOS_FI_COUNT, NAN, &dmat) != 0 || !dmat) {
            snort::ErrorMessage("[dos_inspector] DMatrix hatasi: %s\n", XGBGetLastError());
            return false;
        }
        bst_ulong out_len = 0;
        const float* out_result = nullptr;
        int ret = XGBoosterPredict(booster, dmat, 0, 0, 0, &out_len, &out_result);
        if (ret != 0 || out_len == 0 || !out_result) {
            snort::ErrorMessage("[dos_inspector] Predict hatasi: %s\n", XGBGetLastError());
            XGDMatrixFree(dmat);
            return false;
        }
        score = out_result[0];
        XGDMatrixFree(dmat);
        return true;
    }

    bool is_ready() const { return ready; }

private:
    BoosterHandle booster = nullptr;
    bool          ready   = false;
};

// ---------------------------------------------------------------
// DosInspector
// ---------------------------------------------------------------
class DosInspector : public snort::Inspector {
public:
    DosInspector(DosModule* mod) {
        threshold     = mod->threshold;
        max_packets   = mod->max_packets;
        model_path    = mod->model_path;
        dump_path     = mod->dump_path;
    }

    void show(const snort::SnortConfig*) const override {
        snort::LogMessage("    threshold:     %f\n", threshold);
        snort::LogMessage("    max_packets:   %u\n", max_packets);
        snort::LogMessage("    model_path:    %s\n", model_path.c_str());
    }

    bool configure(snort::SnortConfig*) override {
        DosFlowData::inspector_id = snort::FlowData::create_flow_data_id();
        if (!engine.load(model_path))
            snort::ErrorMessage("[dos_inspector] Model failed.\n");
        if (load_scaler_json(model_path, g_scaler_params, DOS_FI_COUNT))
            snort::LogMessage("[dos_inspector] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[dos_inspector] Using hardcoded scaler params\n");
        if (!dump_path.empty() && dump_path != "none") {
            dump_file.open(dump_path, std::ios::out | std::ios::trunc);
            if (dump_file.is_open()) {
                // Header: 15 raw features + score (v3b: swin/dwin removed)
                dump_file << "src_ip,src_port,dst_ip,dst_port,proto,"
                             "dur,spkts,dpkts,sbytes,dbytes,smeansz,dmeansz,"
                             "sintpkt,dintpkt,"
                             "fwd_pkt_mean,bwd_pkt_mean,fin_cnt,ack_cnt,syn_cnt,bwd_iat,"
                             "score\n";
                snort::LogMessage("[dos_inspector] Dump CSV: %s\n", dump_path.c_str());
            } else {
                snort::ErrorMessage("[dos_inspector] Cannot open dump file: %s\n",
                    dump_path.c_str());
            }
        }
        return true;
    }

    void eval(snort::Packet* pkt) override {
        if (!pkt || !pkt->has_ip()) return;

        double pkt_ts = 0.0;
        if (pkt->pkth)
            pkt_ts = static_cast<double>(pkt->pkth->ts.tv_sec) +
                     static_cast<double>(pkt->pkth->ts.tv_usec) / 1e6;

        // Layer 2: cross-flow SYN rate tracking
        if (pkt->ptrs.tcph && pkt->ptrs.tcph->is_syn_only()) {
            uint32_t syn_src = 0, syn_dst = 0;
            uint16_t syn_dport = 0;
            const snort::SfIp* sip = pkt->ptrs.ip_api.get_src();
            const snort::SfIp* dip = pkt->ptrs.ip_api.get_dst();
            if (sip && sip->is_ip4()) syn_src = ntohl(sip->get_ip4_value());
            if (dip && dip->is_ip4()) syn_dst = ntohl(dip->get_ip4_value());
            syn_dport = pkt->ptrs.tcph->dst_port();
            if (syn_src != 0) update_syn_rate(syn_src, syn_dst, syn_dport, pkt_ts);
        }

        if (!pkt->flow) return;

        DosFlowData* fd = static_cast<DosFlowData*>(
            pkt->flow->get_flow_data(DosFlowData::inspector_id));

        if (!fd) {
            fd = new DosFlowData(DosFlowData::inspector_id);
            pkt->flow->set_flow_data(fd);
        }

        if (fd->is_inference_done())
            return;

        bool     from_client = pkt->is_from_client();
        uint32_t payload_len = pkt->dsize;
        int32_t  tcp_win     = -1;
        uint8_t  tcp_flags   = 0;
        if (pkt->ptrs.tcph) {
            tcp_win   = static_cast<int32_t>(pkt->ptrs.tcph->win());
            tcp_flags = pkt->ptrs.tcph->th_flags;
        }

        fd->update(from_client, payload_len, tcp_win, pkt_ts, tcp_flags);

        bool flow_closing = false;
        if (pkt->flow) {
            uint32_t flags = pkt->flow->ssn_state.session_flags;
            flow_closing = flags & (SSNFLAG_CLIENT_FIN | SSNFLAG_SERVER_FIN |
                                    SSNFLAG_RESET | SSNFLAG_TIMEDOUT | SSNFLAG_PRUNED);
        }

        uint32_t total = fd->get_total_packets();

        if (fd->get_state() == DosFlowData::WATCH) {
            if (total >= 8 || flow_closing)
                run_stage2(pkt, fd);
        } else {
            if (total >= max_packets || flow_closing)
                run_stage1(pkt, fd);
        }
    }

private:
    double       threshold;
    uint32_t     max_packets;
    std::string  model_path;
    std::string  dump_path;
    std::ofstream dump_file;
    std::mutex   dump_mutex;
    XGBoostEngine engine;

    static const float STAGE1_HIGH_CONF;

    std::unordered_map<uint32_t, SynTracker> syn_trackers;
    static uint32_t evict_counter;

    void update_syn_rate(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port, double now) {
        auto& st = syn_trackers[src_ip];
        if (st.window_start[0] == 0 && st.window_start[1] == 0) {
            st.dst_ips.clear();
            st.dst_ports.clear();
        }
        st.add(dst_ip, dst_port, now);
        if (++evict_counter % EVICT_INTERVAL == 0) {
            for (auto it = syn_trackers.begin(); it != syn_trackers.end(); ) {
                if (it->second.is_stale(now) || syn_trackers.size() > MAX_TRACKERS)
                    it = syn_trackers.erase(it);
                else
                    ++it;
            }
        }
    }

    bool is_attack_syn_rate(uint32_t src_ip) {
        auto it = syn_trackers.find(src_ip);
        if (it == syn_trackers.end()) return false;
        return it->second.is_attack_pattern();
    }

    bool compute_scaled(DosFlowData* fd, float features_f[DOS_FI_COUNT],
                        double raw[DOS_FI_COUNT]) {
        fd->compute_features(raw);
        double processed[DOS_FI_COUNT];
        std::memcpy(processed, raw, DOS_FI_COUNT * sizeof(double));
        DosFlowData::preprocess(processed, g_scaler_params);
        for (unsigned i = 0; i < DOS_FI_COUNT; i++)
            features_f[i] = static_cast<float>(processed[i]);
        return true;
    }

    bool is_rule3_suppressed(snort::Packet* pkt) {
        if (!pkt || !pkt->ptrs.tcph) return false;
        uint16_t dp = pkt->ptrs.tcph->dst_port();
        return (dp == 53 || dp == 137 || dp == 389);
    }

    static bool is_rule4_suppressed(double /*raw*/[DOS_FI_COUNT]) {
        // swin/dwin removed in v3b — rule4 no longer applicable
        return false;
    }

    uint32_t classify_attack_type(double raw[DOS_FI_COUNT], float score,
                                   uint32_t total_packets, bool is_stage2) {
        // Stage 1 (2 packets): insufficient data → always generic
        if (!is_stage2)
            return DOS_SID_GENERIC;

        double dur     = raw[DOS_FI_DUR];
        double spkts   = raw[DOS_FI_SPKTS];
        double dpkts   = raw[DOS_FI_DPKTS];
        double sintpkt = raw[DOS_FI_SINTPKT];
        double total_pkts = spkts + dpkts;

        // Stage 2 (8+ packets): use feature-based classification
        // Volumetric: many packets, extremely low IAT, short duration
        if (total_pkts > 6.0 && sintpkt < 0.001 && dur < 1.0)
            return DOS_SID_VOLUMETRIC;
        // Slow-rate: long duration, few packets, high IAT
        if (dur > 5.0 && total_pkts <= 6.0 && sintpkt > 0.5)
            return DOS_SID_SLOWRATE;
        return DOS_SID_GENERIC;
    }

    void emit_alert(snort::Packet* pkt, DosFlowData* fd,
                    float score, const char* stage, double raw[DOS_FI_COUNT],
                    bool is_stage2) {
        bool r3 = is_rule3_suppressed(pkt);
        bool r4 = is_rule4_suppressed(raw);

        if (score > static_cast<float>(threshold) && !r3 && !r4) {
            uint32_t alert_src = 0;
            if (pkt->flow && pkt->flow->client_ip.is_ip4())
                alert_src = ntohl(pkt->flow->client_ip.get_ip4_value());
            bool high_syn = (alert_src != 0) && is_attack_syn_rate(alert_src);
            uint32_t sid;
            if (high_syn)
                sid = DOS_SID_VOLUMETRIC;
            else
                sid = classify_attack_type(raw, score, fd->get_total_packets(), is_stage2);
            snort::DetectionEngine::queue_event(DOS_GID, sid);
            // Demo SHAP: emit feature log for live explain (parsed by demo-app)
            snort::LogMessage("[dos_inspector] s1-high pkts=%u score=%.4f | "
                "dur=%.6f sp=%.0f dp=%.0f sb=%.0f db=%.0f smsz=%.2f dmsz=%.2f "
                "si=%.4f di=%.4f fwd=%.2f bwd=%.2f fin=%.0f ack=%.0f syn=%.0f biat=%.4f sid=%u\n",
                fd->get_total_packets(), score,
                raw[DOS_FI_DUR], raw[DOS_FI_SPKTS], raw[DOS_FI_DPKTS],
                raw[DOS_FI_SBYTES], raw[DOS_FI_DBYTES],
                raw[DOS_FI_SMEANSZ], raw[DOS_FI_DMEANSZ],
                raw[DOS_FI_SINTPKT], raw[DOS_FI_DINTPKT],
                raw[DOS_FI_FWD_PKT_MEAN], raw[DOS_FI_BWD_PKT_MEAN],
                raw[DOS_FI_FIN_CNT], raw[DOS_FI_ACK_CNT], raw[DOS_FI_SYN_CNT],
                raw[DOS_FI_BWD_IAT], sid);
        }

        // Dump raw features + score if dump_path configured
        if (dump_file.is_open()) {
            std::lock_guard<std::mutex> lk(dump_mutex);
            // Write 5-tuple for label joining
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint8_t proto = 0;
            if (pkt->flow) {
                if (pkt->flow->client_ip.is_ip4())
                    src_ip = ntohl(pkt->flow->client_ip.get_ip4_value());
                if (pkt->flow->server_ip.is_ip4())
                    dst_ip = ntohl(pkt->flow->server_ip.get_ip4_value());
                src_port = pkt->flow->client_port;
                dst_port = pkt->flow->server_port;
                proto    = static_cast<uint8_t>(pkt->flow->ip_proto);
            }
            // IP as dotted-decimal
            auto ip2s = [](uint32_t ip, char* buf) {
                snprintf(buf, 16, "%u.%u.%u.%u",
                    (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);
            };
            char s_ip[16], d_ip[16];
            ip2s(src_ip, s_ip); ip2s(dst_ip, d_ip);
            dump_file << s_ip << ',' << src_port << ','
                      << d_ip << ',' << dst_port << ','
                      << (int)proto << ',';
            for (unsigned i = 0; i < DOS_FI_COUNT; i++)
                dump_file << raw[i] << ',';
            dump_file << score << '\n';
        }

        fd->mark_inference_done();
        fd->set_state(DosFlowData::DONE);
    }

    void run_stage1(snort::Packet* pkt, DosFlowData* fd) {
        float  features_f[DOS_FI_COUNT];
        double raw[DOS_FI_COUNT];
        compute_scaled(fd, features_f, raw);

        float score = 0.0f;
        if (engine.is_ready())
            engine.run(features_f, score);

        fd->set_stage1_score(score);

        if (score >= STAGE1_HIGH_CONF) {
            emit_alert(pkt, fd, score, "s1-high", raw, false);
        } else {
            fd->mark_inference_done();
            fd->set_state(DosFlowData::DONE);
        }
    }

    void run_stage2(snort::Packet* pkt, DosFlowData* fd) {
        float  features_f[DOS_FI_COUNT];
        double raw[DOS_FI_COUNT];
        compute_scaled(fd, features_f, raw);

        float score = 0.0f;
        if (engine.is_ready())
            engine.run(features_f, score);

        emit_alert(pkt, fd, score, "s2-confirm", raw, true);
    }
};

uint32_t DosInspector::evict_counter{0};
const float DosInspector::STAGE1_HIGH_CONF = 0.90f;  // v2: match threshold, disable deferral

// ---------------------------------------------------------------
// Plugin API
// ---------------------------------------------------------------
static snort::Module*   mod_ctor()                  { return new DosModule; }
static void             mod_dtor(snort::Module* m)  { delete m; }
static snort::Inspector* dos_ctor(snort::Module* m) { return new DosInspector(static_cast<DosModule*>(m)); }
static void              dos_dtor(snort::Inspector* p) { delete p; }

static const snort::InspectApi dos_api = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    snort::IT_PACKET,
    PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    dos_ctor,
    dos_dtor,
    nullptr, nullptr
};

SO_PUBLIC const snort::BaseApi* snort_plugins[] = { &dos_api.base, nullptr };
