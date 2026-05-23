// dos_inspector.cc — Cross-flow DoS detection via SYN rate aggregation
// Bitirme Projesi
// GID:303, SID:1 — 7 features XGBoost on SYN packets per source IP

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
#include "dos_flow_tracker.h"
#include "scaler_loader.h"

static const char* s_name = "dos_aggregator";
static const char* s_help = "cross-flow DoS detection via SYN rate aggregation";
static const uint32_t DOS_GID = 303, DOS_SID = 1;

static inline uint32_t gsip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_src();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}

// AGG_SCALER_PARAMS_BEGIN
DasAggScalerParams g_scaler = {
    { 2.6390573296, 1.0986122887, 1.6094379124, 0.9023930000, 71.0000000000, 0.1818180000, 0.1961151529 },
    { 1.9859154837, 0.2876820725, 1.7346010554, 0.8858057500, 15495.7500000000, 0.3071430000, 0.5108254419 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap rules[] = {
    { DOS_SID, "DoS cross-flow detection" }, { 0, nullptr }
};
static const snort::Parameter dos_params[] = {
    { "threshold",  snort::Parameter::PT_REAL,  "0.0:1.0", "0.30", "XGBoost threshold" },
    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/dos_aggregator_model.json", "model path" },
    { "window_sec", snort::Parameter::PT_INT,   "1:300",   "60",   "window seconds" },
    { "min_syns",   snort::Parameter::PT_INT,   "2:10000", "3",    "min SYNs" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Mod : public snort::Module {
public:
    Mod() : snort::Module(s_name, s_help, dos_params) {}
    const snort::RuleMap* get_rules() const override { return rules; }
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override {
        if (v.is("threshold"))  thr = v.get_real();
        else if (v.is("model_path")) mp = v.get_string();
        else if (v.is("window_sec")) ws = v.get_int64();
        else if (v.is("min_syns"))   mn = v.get_int64();
        else return false; return true;
    }
    Usage get_usage() const override { return INSPECT; }
    double thr = 0.30; std::string mp; uint32_t ws = 60, mn = 3;
};

class Xgb {
public:
    Xgb() = default;
    ~Xgb() { if (b) XGBoosterFree(b); }
    bool load(const std::string& p) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, p.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1"); ready = true;
        snort::LogMessage("[dos_agg] Model: %s\n", p.c_str()); return true;
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
        if (!xgb.load(mp)) snort::ErrorMessage("[dos_agg] Model load failed.\n");
        if (load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))
            snort::LogMessage("[dos_agg] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[dos_agg] Using hardcoded scaler params\n");
        return true;
    }

    void eval(snort::Packet* p) override {
        if (!p || !p->has_ip()) return;
        double now = 0;
        if (p->pkth) now = p->pkth->ts.tv_sec + p->pkth->ts.tv_usec / 1e6;

        // Count every TCP SYN-only packet per source IP
        if (!p->ptrs.tcph || !p->ptrs.tcph->is_syn_only()) return;

        uint32_t src = gsip(p);
        uint32_t dst = 0;
        const snort::SfIp* dip = p->ptrs.ip_api.get_dst();
        if (dip && dip->is_ip4()) dst = ntohl(dip->get_ip4_value());
        if (src == 0) return;

        uint16_t sp = p->ptrs.tcph->src_port();
        uint16_t dp = p->ptrs.tcph->dst_port();

        auto it = profs.find(src);
        if (it == profs.end()) {
            DasAggProfile pr; pr.reset(src, now);
            pr.add_syn(dst, dp, sp);
            profs[src] = pr; return;
        }
        auto& pr = it->second;

        if (pr.is_window_expired(now, ws)) {
            if (!pr.inference_done && pr.syn_count >= mn) infer(pr, now);
            pr.reset(src, now);
        }
        pr.add_syn(dst, dp, sp);
        if (!pr.inference_done && pr.syn_count >= mn && pr.is_window_expired(now, ws))
            infer(pr, now);

        // Periodic sweep for expired windows
        static uint32_t sweep = 0;
        if (++sweep % 1000 == 0) {
            for (auto& kv : profs) {
                auto& pp = kv.second;
                if (!pp.inference_done && pp.syn_count >= mn && pp.is_window_expired(now, ws))
                    infer(pp, now);
            }
        }
    }

private:
    double thr; std::string mp; uint32_t ws, mn;
    Xgb xgb;
    std::unordered_map<uint32_t, DasAggProfile> profs;
    static std::atomic<uint64_t> n_inf, n_alert;

    void infer(DasAggProfile& pr, double now) {
        double raw[7], proc[7];
        pr.compute_features(raw, ws);
        memcpy(proc, raw, sizeof(raw));
        DasAggProfile::preprocess(proc, g_scaler);
        float f[7]; for (unsigned i=0;i<7;i++) f[i] = proc[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; n_inf++;

        // Training data dump (with src_ip for labeling)
        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/dos_train_data.txt","w");
            if(df) fprintf(df,"# lb syn_cnt syn_uports syn_uips entropy src_prange pratio srate score src_ip\n"); }
          if(df) { int lbl=0;
            fprintf(df,"%d",lbl);
            for(unsigned i=0;i<7;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f %u\n",(double)score, pr.src_ip); } }

        bool alert = score > thr;

        snort::LogMessage("[dos_agg] %u.%u.%u.%u syns=%u ports=%zu ips=%zu rate=%.1f score=%.4f\n",
            (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
            pr.syn_count, pr.syn_dst_ports.size(), pr.syn_dst_ips.size(),
            raw[6], score);

        if (alert) {
            n_alert++; snort::DetectionEngine::queue_event(DOS_GID, DOS_SID);
            snort::LogMessage("[dos_agg] ALERT: %u.%u.%u.%u score=%.4f\n",
                (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF, score);
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
    snort::IT_PACKET, PROTO_BIT__TCP,
    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr, ic, id, nullptr, nullptr
};
SO_PUBLIC const snort::BaseApi* snort_plugins[] = { &api.base, nullptr };
