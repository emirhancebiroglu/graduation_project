// portscan_inspector.cc — TCP SYN-only cross-flow PortScan detection
// Bitirme Projesi
// GID:302, SID:1 — 7-feature XGBoost on SYN packets per source IP

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

#include "portscan_flow_tracker.h"

static const char* s_name = "portscan_inspector";
static const char* s_help = "TCP SYN cross-flow port scan detection";

static const uint32_t PSI_GID       = 302;
static const uint32_t PSI_SID       = 1;

static inline uint32_t get_src_ip_pkt(snort::Packet* pkt) {
    if (!pkt) return 0;
    const snort::SfIp* ip = pkt->ptrs.ip_api.get_src();
    if (ip && ip->is_ip4()) return ntohl(ip->get_ip4_value());
    return 0;
}

static inline uint32_t get_dst_ip_pkt(snort::Packet* pkt) {
    if (!pkt) return 0;
    const snort::SfIp* ip = pkt->ptrs.ip_api.get_dst();
    if (ip && ip->is_ip4()) return ntohl(ip->get_ip4_value());
    return 0;
}

// AGG_SCALER_PARAMS_BEGIN
static PsiAggScalerParams g_agg_scaler_params = {
    { 2.3978952728, 1.0986122887, 1.3862943611, 0.970951, 11.0, 0.25, 0.1541509655 },
    { 1.6916760107, 0.2876820725, 1.8718021769, 1.053367, 5809.0, 0.283636, 0.3850564427 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap psi_rules[] = {
    { PSI_SID, "PortScan TCP SYN cross-flow detection" },
    { 0, nullptr }
};

static const snort::Parameter psi_params[] = {
    { "threshold",   snort::Parameter::PT_REAL,   "0.0:1.0", "0.70",
      "XGBoost threshold (trained=0.70)" },
    { "model_path",  snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/portscan_aggregator_model.json",
      "path to XGBoost JSON model" },
    { "window_sec",  snort::Parameter::PT_INT,    "1:300",   "60",
      "aggregation window (seconds)" },
    { "min_syns",    snort::Parameter::PT_INT,    "2:10000", "3",
      "minimum SYNs before inference" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class PsiModule : public snort::Module {
public:
    PsiModule() : snort::Module(s_name, s_help, psi_params) {}
    const snort::RuleMap* get_rules() const override { return psi_rules; }

    bool set(const char*, snort::Value& val, snort::SnortConfig*) override {
        if      (val.is("threshold"))  threshold  = val.get_real();
        else if (val.is("model_path")) model_path = val.get_string();
        else if (val.is("window_sec")) window_sec = static_cast<uint32_t>(val.get_int64());
        else if (val.is("min_syns"))   min_syns   = static_cast<uint32_t>(val.get_int64());
        else return false;
        return true;
    }

    Usage get_usage() const override { return INSPECT; }

    double      threshold   = 0.70;
    std::string model_path  = "/home/emirhan/bitirme/models/portscan_aggregator_model.json";
    uint32_t    window_sec  = 60;
    uint32_t    min_syns    = 3;
};

class PsiXGBoost {
public:
    PsiXGBoost() = default;
    ~PsiXGBoost() { if (b) XGBoosterFree(b); }
    PsiXGBoost(const PsiXGBoost&) = delete;
    PsiXGBoost& operator=(const PsiXGBoost&) = delete;

    bool load(const std::string& path) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, path.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1");
        snort::LogMessage("[portscan] Model: %s\n", path.c_str());
        ready = true; return true;
    }

    bool predict(const float* features, float& score) {
        if (!ready) return false;
        DMatrixHandle d = nullptr;
        if (XGDMatrixCreateFromMat(features, 1, AGG_FEATURE_COUNT, NAN, &d) != 0 || !d) return false;
        bst_ulong l = 0; const float* r = nullptr;
        if (XGBoosterPredict(b, d, 0, 0, 0, &l, &r) != 0) { XGDMatrixFree(d); return false; }
        score = r[0]; XGDMatrixFree(d); return true;
    }

    bool is_ready() const { return ready; }
private:
    BoosterHandle b = nullptr;
    bool ready = false;
};

class PsiInspector : public snort::Inspector {
public:
    PsiInspector(PsiModule* m) {
        threshold = m->threshold; model_path = m->model_path;
        window_sec = m->window_sec; min_syns = m->min_syns;
    }

    void show(const snort::SnortConfig*) const override {
        snort::LogMessage("    threshold=%.2f model=%s window=%u min=%u\n",
            threshold, model_path.c_str(), window_sec, min_syns);
    }

    bool configure(snort::SnortConfig*) override {
        if (!xgb.load(model_path))
            snort::ErrorMessage("[portscan] Model load failed.\n");
        return true;
    }

    void eval(snort::Packet* pkt) override {
        if (!pkt || !pkt->has_ip()) return;
        if (!pkt->ptrs.tcph) return;
        if (!pkt->ptrs.tcph->is_syn_only()) return;

        double now = 0;
        if (pkt->pkth) now = pkt->pkth->ts.tv_sec + pkt->pkth->ts.tv_usec / 1e6;

        uint32_t src = get_src_ip_pkt(pkt);
        uint32_t dst = get_dst_ip_pkt(pkt);
        uint16_t sp = pkt->ptrs.tcph->src_port();
        uint16_t dp = pkt->ptrs.tcph->dst_port();
        if (src == 0 || dst == 0) return;

        auto it = profs.find(src);
        if (it == profs.end()) {
            PsiAggProfile p; p.reset(src, now);
            p.add_packet(dst, dp, sp, 0, 0);
            profs[src] = p; return;
        }

        auto& p = it->second;
        if (p.is_window_expired(now, window_sec)) {
            if (!p.inference_done && p.total_syns >= min_syns) infer(p, now);
            p.reset(src, now);
        }
        p.add_packet(dst, dp, sp, 0, 0);
        if (!p.inference_done && p.total_syns >= min_syns && p.is_window_expired(now, window_sec))
            infer(p, now);
    }

private:
    double      threshold;
    std::string model_path;
    uint32_t    window_sec, min_syns;
    PsiXGBoost xgb;
    std::unordered_map<uint32_t, PsiAggProfile> profs;
    static std::atomic<uint64_t> n_inf, n_alert;

    void infer(PsiAggProfile& p, double now) {
        double raw[AGG_FEATURE_COUNT], proc[AGG_FEATURE_COUNT];
        p.compute_features(raw, window_sec);
        memcpy(proc, raw, sizeof(raw));
        PsiAggProfile::preprocess(proc, g_agg_scaler_params);
        float f[AGG_FEATURE_COUNT];
        for (unsigned i = 0; i < AGG_FEATURE_COUNT; i++) f[i] = proc[i];
        float score = 0;
        if (xgb.is_ready()) xgb.predict(f, score);
        p.inference_done = true; n_inf++;

        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/portscan_train_data.txt","w");
            if(df) fprintf(df,"# label total_syns unique_dst_ports unique_dst_ips dst_port_entropy src_port_range unique_port_ratio syn_rate score\n"); }
          if(df) { int lbl=(p.src_ip==0xAC100001)?1:0;
            fprintf(df,"%d",lbl);
            for(unsigned i=0;i<AGG_FEATURE_COUNT;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f\n",(double)score); } }

        snort::LogMessage("[portscan] %u.%u.%u.%u syns=%u ports=%zu ips=%zu score=%.4f\n",
            (p.src_ip>>24)&0xFF,(p.src_ip>>16)&0xFF,(p.src_ip>>8)&0xFF,p.src_ip&0xFF,
            p.total_syns, p.dst_ports.size(), p.dst_ips.size(), score);

        if (score > threshold) {
            n_alert++;
            snort::DetectionEngine::queue_event(PSI_GID, PSI_SID);
            snort::LogMessage("[portscan] ALERT: %u.%u.%u.%u score=%.4f\n",
                (p.src_ip>>24)&0xFF,(p.src_ip>>16)&0xFF,(p.src_ip>>8)&0xFF,p.src_ip&0xFF, score);
        }
    }
};

std::atomic<uint64_t> PsiInspector::n_inf{0};
std::atomic<uint64_t> PsiInspector::n_alert{0};

static snort::Module*    mc() { return new PsiModule; }
static void              md(snort::Module* m) { delete m; }
static snort::Inspector* ic(snort::Module* m) { return new PsiInspector(static_cast<PsiModule*>(m)); }
static void              id(snort::Inspector* p) { delete p; }

static const snort::InspectApi api = {
    { PT_INSPECTOR, sizeof(snort::InspectApi), INSAPI_VERSION, 0, API_RESERVED,
      API_OPTIONS, s_name, s_help, mc, md },
    snort::IT_PACKET, PROTO_BIT__TCP,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, ic, id, nullptr, nullptr
};

SO_PUBLIC const snort::BaseApi* snort_plugins[] = { &api.base, nullptr };
