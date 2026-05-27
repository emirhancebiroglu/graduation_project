// portscan_inspector.cc â€” SYN ML (7-feature) + NULL/XMAS heuristic
// Bitirme Projesi
// GID:302, SID:1

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
#include "scaler_loader.h"

static const char* s_name = "portscan_inspector";

static void write_score_file(uint32_t src_ip, float score, const char* engine,
                             const double* feats, unsigned n_feats) {
    static FILE* sf = nullptr;
    if (!sf) sf = fopen("/tmp/aegis_scores.jsonl", "a");
    if (!sf) return;
    fprintf(sf, "{\"engine\":\"%s\",\"src_ip\":\"%u.%u.%u.%u\",\"score\":%.6f,\"features\":[",
        engine,
        (src_ip>>24)&0xFF,(src_ip>>16)&0xFF,(src_ip>>8)&0xFF,src_ip&0xFF,
        score);
    for (unsigned i = 0; i < n_feats; i++) {
        if (i > 0) fprintf(sf, ",");
        fprintf(sf, "%.6f", feats[i]);
    }
    fprintf(sf, "]}\n");
    fflush(sf);
}
static const char* s_help = "SYN ML + NULL/XMAS heuristic port scan detection";
static const uint32_t PSI_GID = 302, PSI_SID = 1;

static inline uint32_t gsip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_src();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}
static inline uint32_t gdip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_dst();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}

// AGG_SCALER_PARAMS_BEGIN
PsiAggScalerParams g_scaler = {
    { 2.0794415417, 1.0986122887, 1.0986122887, 0.5940327422, 1.7917594692, 0.2876820725, 0.1103480572 },
    { 2.5649493575, 0.6931471806, 1.0986122887, 0.8632909694, 7.7916225259, 0.3053816496, 0.5663954749 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap rules[] = {
    { PSI_SID, "PortScan detection" }, { 0, nullptr }
};
static const snort::Parameter psi_params[] = {
    { "threshold",  snort::Parameter::PT_REAL,  "0.0:1.0", "0.50", "XGBoost threshold" },
    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/portscan_aggregator_model.json", "model path" },
    { "window_sec", snort::Parameter::PT_INT,   "1:300",   "60",   "window seconds" },
    { "min_packets", snort::Parameter::PT_INT,   "2:10000", "3",    "min SYNs" },
    { "min_dst_ports", snort::Parameter::PT_INT, "1:1000",  "30",   "min unique dst ports before ML" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Mod : public snort::Module {
public:
    Mod() : snort::Module(s_name, s_help, psi_params) {}
    const snort::RuleMap* get_rules() const override { return rules; }
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override {
        if (v.is("threshold"))  thr = v.get_real();
        else if (v.is("model_path")) mp = v.get_string();
        else if (v.is("window_sec")) ws = v.get_int64();
        else if (v.is("min_packets"))   mn = v.get_int64();
        else if (v.is("min_dst_ports")) mdp = v.get_int64();
        else return false; return true;
    }
    Usage get_usage() const override { return INSPECT; }
    double thr = 0.50; std::string mp; uint32_t ws = 60, mn = 3, mdp = 30;
};

class Xgb {
public:
    Xgb() = default;
    ~Xgb() { if (b) XGBoosterFree(b); }
    bool load(const std::string& p) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, p.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1"); ready = true; snort::LogMessage("[portscan] Model: %s\n", p.c_str()); return true;
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
    Insp(Mod* m) { thr=m->thr; mp=m->mp; ws=m->ws; mn=m->mn; mdp=m->mdp; }

    bool configure(snort::SnortConfig*) override {
        if (!xgb.load(mp)) snort::ErrorMessage("[portscan] Model load failed.\n");
        if (load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))
            snort::LogMessage("[portscan] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[portscan] Using hardcoded scaler params\n");
        return true;
    }

    void eval(snort::Packet* p) override {
        if (!p || !p->has_ip()) return;
        double now = 0;
        if (p->pkth) now = p->pkth->ts.tv_sec + p->pkth->ts.tv_usec / 1e6;

        uint32_t src = gsip(p);
        uint32_t dst = gdip(p);
        if (src == 0) return;

        // Emit deferred alert on the attacker's own packet (correct src in alert_csv).
        {
            auto it = profs.find(src);
            if (it != profs.end() && it->second.alert_pending) {
                auto& pp = it->second;
                pp.alert_pending = false;
                alert++;
                snort::DetectionEngine::queue_event(PSI_GID, PSI_SID);
                snort::LogMessage("[portscan] ALERT (deferred): %u.%u.%u.%u score=%.4f\n",
                    (pp.src_ip>>24)&0xFF,(pp.src_ip>>16)&0xFF,(pp.src_ip>>8)&0xFF,pp.src_ip&0xFF,
                    pp.pending_score);
            }
        }

        // Periodic sweep: run inference on expired windows, mark alert_pending.
        {
            static uint32_t sweep = 0;
            if (++sweep % 1000 == 0) {
                for (auto& kv : profs) {
                    auto& pp = kv.second;
                    if (!pp.inference_done && pp.syn_count >= mn && pp.is_window_expired(now, ws))
                        infer_deferred(pp, now);
                }
            }
        }

        // Check window expiry for any packet from tracked src.
        {
            auto it = profs.find(src);
            if (it != profs.end()) {
                auto& pr = it->second;
                if (pr.is_window_expired(now, ws)) {
                    if (!pr.inference_done && pr.syn_count >= mn) infer(pr, now);
                    pr.reset(src, now);
                }
            }
        }

        // Classify packet
        uint8_t ptype = 0; uint16_t sp = 0, dp = 0;
        if (p->ptrs.tcph) {
            uint8_t f = p->ptrs.tcph->th_flags;
            if ((f & 0x16) == 0x02) { ptype = 'S'; sp=p->ptrs.tcph->src_port(); dp=p->ptrs.tcph->dst_port(); }
            else if ((!(f & 0x16) && (f & 0x29)) || f == 0) { ptype = 'F'; }
        }
        if (!ptype) return;

        auto it = profs.find(src);
        if (it == profs.end()) {
            PsiAggProfile pr; pr.reset(src, now);
            if (ptype=='S') pr.add_syn(dst, dp, sp); else pr.add_fnx();
            profs[src] = pr; return;
        }
        auto& pr = it->second;

        if (ptype=='S') {
            pr.add_syn(dst, dp, sp);
            if (!pr.inference_done && pr.syn_count >= mn && pr.is_window_expired(now, ws))
                infer(pr, now);
            // Early-fire for high-volume scanners — no need to wait for window expiry.
            if (!pr.inference_done && pr.syn_count >= 500 && pr.syn_dst_ports.size() >= static_cast<size_t>(mdp))
                infer(pr, now);
        } else {
            pr.add_fnx();
            if (!pr.inference_done && pr.is_null_xmas()) {
                pr.inference_done = true; inf++;
                snort::LogMessage("[portscan] %u.%u.%u.%u syn=%u fnx=%u score=0.999 [null/xmas]\n",
                    (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
                    pr.syn_count, pr.fnx_count);
                alert++; snort::DetectionEngine::queue_event(PSI_GID, PSI_SID);
                snort::LogMessage("[portscan] ALERT: %u.%u.%u.%u score=0.999 [null/xmas]\n",
                    (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF);
            }
        }
    }

private:
    double thr; std::string mp; uint32_t ws, mn, mdp;
    Xgb xgb;
    std::unordered_map<uint32_t, PsiAggProfile> profs;
    static std::atomic<uint64_t> inf, alert;

    void infer_deferred(PsiAggProfile& pr, double now) {
        if (pr.syn_dst_ports.size() < mdp) { pr.inference_done = true; return; }
        double raw[7], proc[7];
        pr.compute_features(raw, ws);
        memcpy(proc, raw, sizeof(raw));
        PsiAggProfile::preprocess(proc, g_scaler);
        float f[7]; for (unsigned i=0;i<7;i++) f[i] = proc[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; inf++;
        snort::LogMessage("[portscan] %u.%u.%u.%u syn=%u/%zu fnx=%u score=%.4f\n",
            (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
            pr.syn_count, pr.syn_dst_ports.size(), pr.fnx_count, score);
        bool ip_sweep = (pr.syn_dst_ips.size() >= 100 && pr.syn_count >= 500);
        if (score > thr || ip_sweep) {
            float report_score = ip_sweep ? 0.990f : score;
            write_score_file(pr.src_ip, report_score, "portscan", raw, 7);
            pr.alert_pending = true;
            pr.pending_score = report_score;
            snort::LogMessage("[portscan] ALERT pending: %u.%u.%u.%u score=%.4f\n",
                (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF, report_score);
        }
    }

    void infer(PsiAggProfile& pr, double now) {
        // Skip ML if too few unique dst ports (avoids FP on normal heavy traffic)
        if (pr.syn_dst_ports.size() < mdp) { pr.inference_done = true; return; }
        double raw[7], proc[7];
        pr.compute_features(raw, ws);
        memcpy(proc, raw, sizeof(raw));
        PsiAggProfile::preprocess(proc, g_scaler);
        float f[7]; for (unsigned i=0;i<7;i++) f[i] = proc[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; inf++;

        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/portscan_train_data.txt","w");
            if(df) fprintf(df,"# lb syn_cnt syn_uports syn_uips entropy src_prange pratio srate score\n"); }
          if(df) { int lbl=(pr.src_ip==0xAC100001)?1:0;
            fprintf(df,"%d",lbl);
            for(unsigned i=0;i<7;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f\n",(double)score); } }

        snort::LogMessage("[portscan] %u.%u.%u.%u syn=%u/%zu fnx=%u score=%.4f\n",
            (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
            pr.syn_count, pr.syn_dst_ports.size(), pr.fnx_count, score);

        // IP-sweep heuristic: internet-wide scanners (masscan/zmap) hit many IPs, few ports.
        // ML score is low for these because port diversity is low, but threat is real.
        bool ip_sweep = (pr.syn_dst_ips.size() >= 100 && pr.syn_count >= 500);
        if (score > thr || ip_sweep) {
            float report_score = ip_sweep ? 0.990f : score;
            write_score_file(pr.src_ip, report_score, "portscan", raw, 7);
            alert++; snort::DetectionEngine::queue_event(PSI_GID, PSI_SID);
            snort::LogMessage("[portscan] ALERT: %u.%u.%u.%u score=%.4f%s\n",
                (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
                report_score, ip_sweep ? " [ip-sweep]" : "");
        }
    }
};
std::atomic<uint64_t> Insp::inf{0}, Insp::alert{0};

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
