// bruteforce_inspector.cc — Per-source-IP brute force SSH/FTP detection
// GID:307, SID:1 — 7 features XGBoost on outgoing SYNs per src IP

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
#include "bruteforce_flow_tracker.h"
#include "scaler_loader.h"

static const char* s_name = "bruteforce_inspector";
static const char* s_help = "per-source-IP brute force detection via SYN aggregation";
static const uint32_t BFC_GID = 307, BFC_SID = 1;

static inline uint32_t gsip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_src();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}
static inline uint32_t gdip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_dst();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}

// AGG_SCALER_PARAMS_BEGIN
BfcScalerParams g_scaler = {
    { 3.044522, 1.791759, 1.098612, 0.105360, 0.559616, 0.287682, 1.106009 },
    { 1.836550, 1.945910, 0.287682, 0.202415, 0.180537, 0.567857, 0.556752 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap rules[] = {
    { BFC_SID, "Brute force SSH/FTP detection" }, { 0, nullptr }
};
static const snort::Parameter bfc_params[] = {
    { "threshold",  snort::Parameter::PT_REAL,  "0.0:1.0", "0.50", "XGBoost threshold" },
    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/bruteforce_model.json", "model path" },
    { "window_sec", snort::Parameter::PT_INT,   "1:600",   "60",   "window seconds" },
    { "min_syns",   snort::Parameter::PT_INT,   "2:10000", "5",    "min outgoing SYNs" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Mod : public snort::Module {
public:
    Mod() : snort::Module(s_name, s_help, bfc_params) {}
    const snort::RuleMap* get_rules() const override { return rules; }
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override {
        if (v.is("threshold"))  thr = v.get_real();
        else if (v.is("model_path")) mp = v.get_string();
        else if (v.is("window_sec")) ws = v.get_int64();
        else if (v.is("min_syns"))   mn = v.get_int64();
        else return false; return true;
    }
    Usage get_usage() const override { return INSPECT; }
    double thr = 0.50; std::string mp; uint32_t ws = 60, mn = 5;
};

class Xgb {
public:
    Xgb() = default;
    ~Xgb() { if (b) XGBoosterFree(b); }
    bool load(const std::string& p) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, p.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1"); ready = true;
        snort::LogMessage("[bfc] Model: %s\n", p.c_str()); return true;
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
        if (!xgb.load(mp)) snort::ErrorMessage("[bfc] Model load failed.\n");
        if (load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))
            snort::LogMessage("[bfc] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[bfc] Using hardcoded scaler params\n");
        return true;
    }

    void eval(snort::Packet* p) override {
        if (!p || !p->has_ip()) return;
        double now = 0;
        if (p->pkth) now = p->pkth->ts.tv_sec + p->pkth->ts.tv_usec / 1e6;

        // Track outgoing TCP SYN-only packets per source IP
        if (!p->ptrs.tcph || !p->ptrs.tcph->is_syn_only()) return;

        uint32_t src = gsip(p);
        uint32_t dst = gdip(p);
        if (src == 0 || dst == 0) return;

        uint16_t dp = p->ptrs.tcph->dst_port();

        auto it = profs.find(src);
        if (it == profs.end()) {
            BfcProfile pr; pr.reset(src, now);
            pr.add_syn(dst, dp, now);
            profs[src] = pr; return;
        }
        auto& pr = it->second;

        if (pr.is_window_expired(now, ws)) {
            if (!pr.inference_done && pr.syn_count >= mn) infer(pr, now);
            pr.reset(src, now);
        }
        pr.add_syn(dst, dp, now);
        if (!pr.inference_done && pr.syn_count >= mn && pr.is_window_expired(now, ws))
            infer(pr, now);

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
    std::unordered_map<uint32_t, BfcProfile> profs;
    static std::atomic<uint64_t> n_inf, n_alert;

    void infer(BfcProfile& pr, double now) {
        double raw[7], proc[7];
        pr.compute_features(raw, ws);
        memcpy(proc, raw, sizeof(raw));
        BfcProfile::preprocess(proc, g_scaler);
        float f[7]; for (unsigned i=0;i<7;i++) f[i] = proc[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; n_inf++;

        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/bfc_train_data.txt","w");
            if(df) fprintf(df,"# lb syn_cnt dst_ips dst_ports port_ratio single_port_rate rate iat_cv score src_ip\n"); }
          if(df) { int lbl=0;
            fprintf(df,"%d",lbl);
            for(unsigned i=0;i<7;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f %u\n",(double)score, pr.src_ip); } }

        bool alert = score > thr;

        snort::LogMessage("[bfc] %u.%u.%u.%u syns=%u dsts=%zu ports=%zu sps=%.3f score=%.4f\n",
            (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
            pr.syn_count, pr.syn_dst_ips.size(), pr.syn_dst_ports.size(),
            pr.single_port_score(), score);

        if (alert) {
            n_alert++; snort::DetectionEngine::queue_event(BFC_GID, BFC_SID);
            snort::LogMessage("[bfc] ALERT: %u.%u.%u.%u score=%.4f syns=%u ports=%zu\n",
                (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
                score, pr.syn_count, pr.syn_dst_ports.size());
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
