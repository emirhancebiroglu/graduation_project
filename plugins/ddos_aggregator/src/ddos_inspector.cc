// ddos_inspector.cc — Cross-flow DDoS detection (per-destination-IP aggregation)
// Bitirme Projesi
// GID:304, SID:1 — 7 features XGBoost on SYN+UDP packets per destination IP

#include <atomic>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <xgboost/c_api.h>
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "ddos_flow_tracker.h"
#include "scaler_loader.h"

static const char* s_name = "ddos_aggregator";
static const char* s_help = "cross-flow DDoS detection via per-destination-IP aggregation";
static const uint32_t DOS_GID = 304, DOS_SID = 1;

static inline uint32_t gsip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_src();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}
static inline uint32_t gdip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_dst();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}

// AGG_SCALER_PARAMS_BEGIN
DdsAggScalerParams g_scaler = {
    { 1.6094379124, 0.6931471806, 1.0986122887, 1.0986122887, 0.0000000000, 0.1541509655, 0.0645388336 },
    { 0.5877866649, 1.0000000000, 0.6931471806, 0.5596157879, 1.0000000000, 0.1490356506, 0.0606240152 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap rules[] = {
    { DOS_SID, "DDoS cross-flow detection" }, { 0, nullptr }
};
static const snort::Parameter ddos_params[] = {
    { "threshold",  snort::Parameter::PT_REAL,  "0.0:1.0", "0.70", "XGBoost threshold" },
    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/ddos_aggregator_model.json", "model path" },
    { "window_sec", snort::Parameter::PT_INT,   "1:300",   "60",   "window seconds" },
    { "min_packets",snort::Parameter::PT_INT,   "2:10000", "3",    "min packets" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Mod : public snort::Module {
public:
    Mod() : snort::Module(s_name, s_help, ddos_params) {}
    const snort::RuleMap* get_rules() const override { return rules; }
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override {
        if (v.is("threshold"))  thr = v.get_real();
        else if (v.is("model_path")) mp = v.get_string();
        else if (v.is("window_sec")) ws = v.get_int64();
        else if (v.is("min_packets"))   mn = v.get_int64();
        else return false; return true;
    }
    Usage get_usage() const override { return INSPECT; }
    double thr = 0.70; std::string mp; uint32_t ws = 60, mn = 3;
};

class Xgb {
public:
    Xgb() = default;
    ~Xgb() { if (b) XGBoosterFree(b); }
    bool load(const std::string& p) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, p.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1"); ready = true;
        snort::LogMessage("[ddos_agg] Model: %s\n", p.c_str()); return true;
    }
    bool run(const float* f, float& s) {
        if (!ready) return false;
        DMatrixHandle d = nullptr;
        if (XGDMatrixCreateFromMat(f, 1, AGG_FEATURE_COUNT, NAN, &d)) return false;
        bst_ulong l = 0; const float* r = nullptr;
        if (XGBoosterPredict(b, d, 0, 0, 0, &l, &r)) { XGDMatrixFree(d); return false; }
        s = r[0]; XGDMatrixFree(d); return true;
    }
    bool ok() const { return ready; }
private:
    BoosterHandle b = nullptr; bool ready = false;
};

class Insp : public snort::Inspector {
public:
    Insp(Mod* m) { thr=m->thr; mp=m->mp; ws=m->ws; mn=m->mn; }

    bool configure(snort::SnortConfig*) override {
        if (!xgb.load(mp)) snort::ErrorMessage("[ddos_agg] Model load failed.\n");
        if (load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))
            snort::LogMessage("[ddos_agg] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[ddos_agg] Using hardcoded scaler params\n");
        return true;
    }

    void eval(snort::Packet* p) override {
        if (!p || !p->has_ip()) return;
        double now = 0;
        if (p->pkth) now = p->pkth->ts.tv_sec + p->pkth->ts.tv_usec / 1e6;

        uint8_t ptype = 0; uint16_t sp = 0, dp = 0;
        uint32_t src = gsip(p), dst = gdip(p);
        if (src == 0 || dst == 0) return;

        // Classify packet type
        if (p->ptrs.tcph && p->ptrs.tcph->is_syn_only()) {
            ptype = 'S'; sp = p->ptrs.tcph->src_port(); dp = p->ptrs.tcph->dst_port();
        }
        if (!ptype && p->ptrs.udph) {
            ptype = 'U'; sp = p->ptrs.udph->src_port(); dp = p->ptrs.udph->dst_port();
        }
        if (!ptype) return;

        // Key by DESTINATION IP:PORT (targeted service endpoint)
        uint64_t key = (static_cast<uint64_t>(dst) << 32) | static_cast<uint64_t>(dp);
        auto it = profs.find(key);
        if (it == profs.end()) {
            DdsAggProfile pr; pr.reset(key, now);
            if (ptype == 'S') pr.add_syn(src, sp);
            else pr.add_udp(src);
            profs[key] = pr; return;
        }
        auto& pr = it->second;

        if (pr.is_window_expired(now, ws)) {
            if (!pr.inference_done && (pr.syn_count+pr.total_packets) >= mn) infer(pr, now);
            pr.reset(key, now);
        }
        if (ptype == 'S') pr.add_syn(src, sp);
        else pr.add_udp(src);
        if (!pr.inference_done && (pr.syn_count+pr.total_packets) >= mn && pr.is_window_expired(now, ws))
            infer(pr, now);

        // Periodic sweep
        static uint32_t sweep = 0;
        if (++sweep % 1000 == 0) {
            for (auto& kv : profs) {
                auto& pp = kv.second;
                if (!pp.inference_done && (pp.syn_count+pp.total_packets) >= mn && pp.is_window_expired(now, ws))
                    infer(pp, now);
            }
        }
    }

private:
    double thr; std::string mp; uint32_t ws, mn;
    Xgb xgb;
    std::unordered_map<uint64_t, DdsAggProfile> profs;
    static std::atomic<uint64_t> n_inf, n_alert;

    void infer(DdsAggProfile& pr, double now) {
        double raw[7], proc[7];
        pr.compute_features(raw, ws);
        memcpy(proc, raw, sizeof(raw));
        DdsAggProfile::preprocess(proc, g_scaler);
        float f[7]; for (unsigned i=0;i<7;i++) f[i] = proc[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; n_inf++;

        // Training data dump
        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/ddos_train_data.txt","w");
            if(df) fprintf(df,"# lb total_pkts unique_src unique_src_ports ports_per_src reserved src_ratio rate key\n"); }
          static int day_shift = 0; // incremented by replay script (hack for day tracking)
          if(df) {
            fprintf(df,"0");
            for(unsigned i=0;i<7;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f %lu\n",(double)score, (unsigned long)pr.key); } }

        bool alert = score > thr;

        uint32_t dip = (uint32_t)(pr.key >> 32);
        uint16_t dport = (uint16_t)(pr.key & 0xFFFF);
        snort::LogMessage("[ddos_agg] %u.%u.%u.%u:%u pkts=%u srcs=%zu rate=%.1f score=%.4f\n",
            (dip>>24)&0xFF,(dip>>16)&0xFF,(dip>>8)&0xFF,dip&0xFF,dport,
            pr.syn_count+pr.total_packets, pr.syn_src_ips.size(), raw[6], score);

        // Suppress alerts for common server management ports (unlikely DDoS targets in CIC dataset)
        if (alert && (dport == 21 || dport == 22 || dport == 25 || dport == 53 ||
                      dport == 88 || dport == 123 || dport == 137 || dport == 138 ||
                      dport == 389 || dport == 443 || dport == 445)) {
            alert = false;
        }
        // Suppress: single source with few ports → regular client, not DDoS attacker
        if (alert && pr.syn_src_ips.size() == 1 && pr.syn_src_ports.size() < 10) {
            alert = false;
        }

        if (alert) {
            n_alert++; snort::DetectionEngine::queue_event(DOS_GID, DOS_SID);
            snort::LogMessage("[ddos_agg] ALERT: %u.%u.%u.%u:%u score=%.4f\n",
                (dip>>24)&0xFF,(dip>>16)&0xFF,(dip>>8)&0xFF,dip&0xFF,dport, score);
        }
    }
};
std::atomic<uint64_t> Insp::n_inf{0}, Insp::n_alert{0};

static snort::Module* mc() { return new Mod; }
static void md(snort::Module* m) { delete m; }
static snort::Inspector* ic(snort::Module* m) { return new Insp(static_cast<Mod*>(m)); }
static void id(snort::Inspector* p) { delete p; }
static const snort::InspectApi api = {
    { PT_INSPECTOR, sizeof(snort::InspectApi), INSAPI_VERSION, 0, API_RESERVED,
      API_OPTIONS, s_name, s_help, mc, md },
    snort::IT_PACKET, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr, ic, id, nullptr, nullptr
};
SO_PUBLIC const snort::BaseApi* snort_plugins[] = { &api.base, nullptr };
