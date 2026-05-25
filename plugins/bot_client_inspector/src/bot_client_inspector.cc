// bot_client_inspector.cc — Per-source-IP bot client detection
// GID:306, SID:1 — 7 features XGBoost on outgoing SYNs per src IP

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
#include "bot_client_flow_tracker.h"
#include "scaler_loader.h"

static const char* s_name = "bot_client_inspector";
static const char* s_help = "per-source-IP bot client detection via outgoing SYN aggregation";
static const uint32_t BCL_GID = 306, BCL_SID = 1;

static inline uint32_t gsip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_src();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}
static inline uint32_t gdip(snort::Packet* p) {
    if (!p) return 0; auto* ip = p->ptrs.ip_api.get_dst();
    return (ip && ip->is_ip4()) ? ntohl(ip->get_ip4_value()) : 0;
}
// Only track RFC1918 internal IPs as potential bot clients
static inline bool is_private_ip(uint32_t ip) {
    return ((ip & 0xFF000000) == 0x0A000000) ||   // 10.0.0.0/8
           ((ip & 0xFFF00000) == 0xAC100000) ||   // 172.16.0.0/12
           ((ip & 0xFFFF0000) == 0xC0A80000);      // 192.168.0.0/16
}

// AGG_SCALER_PARAMS_BEGIN
BclScalerParams g_scaler = {
    { 1.3862943611, 1.0986122887, 1.0986122887, 0.6931446806, 0.6514372920,
      0.2876818225, 0.0099503309, 0.5108258238, 0.3364722366, 0.6514372920,
      0.0000000000, 0.5108258238, 0.6931471806, 0.5108258238, 0.6547301044,
      2.5852546487, 0.0000000000, 0.0000000000, 7.6095317727, 0.5108258238,
      1.6094379124, 10.2737053763 },
    { 0.8109302162, 0.6931471806, 0.4054651081, 0.2918230646, 0.6514372920,
      0.2876822725, 0.0163673021, 0.4054653581, 0.2231440013, 0.9497111945,
      8.0586476891, 0.2231440013, 0.2876820725, 0.1177828357, 0.0569154484,
      1.4328143654, 0.2876818225, 0.6097156100, 2.0050006437, 0.8964884787,
      1.1700712871, 0.6854398830 }
};
// AGG_SCALER_PARAMS_END

static const snort::RuleMap rules[] = {
    { BCL_SID, "Bot client detection" }, { 0, nullptr }
};
static const snort::Parameter bcl_params[] = {
    { "threshold",  snort::Parameter::PT_REAL,  "0.0:1.0", "0.50", "XGBoost threshold" },
    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/bot_client_model.json", "model path" },
    { "window_sec", snort::Parameter::PT_INT,   "1:600",   "300",  "window seconds" },
    { "min_syns",   snort::Parameter::PT_INT,   "2:10000", "3",    "min outgoing SYNs" },
    { "suppress_ips", snort::Parameter::PT_STRING, nullptr,
      "none", "comma-separated IPs to suppress alerts for" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Mod : public snort::Module {
public:
    Mod() : snort::Module(s_name, s_help, bcl_params) {}
    const snort::RuleMap* get_rules() const override { return rules; }
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override {
        if (v.is("threshold"))  thr = v.get_real();
        else if (v.is("model_path")) mp = v.get_string();
        else if (v.is("window_sec")) ws = v.get_int64();
        else if (v.is("min_syns"))   mn = v.get_int64();
        else if (v.is("suppress_ips")) { sp = v.get_string(); if (sp == "none") sp = ""; }
        else return false; return true;
    }
    Usage get_usage() const override { return INSPECT; }
    double thr = 0.50; std::string mp, sp; uint32_t ws = 300, mn = 3;
};

class Xgb {
public:
    Xgb() = default;
    ~Xgb() { if (b) XGBoosterFree(b); }
    bool load(const std::string& p) {
        if (XGBoosterCreate(nullptr, 0, &b) != 0) return false;
        if (XGBoosterLoadModel(b, p.c_str()) != 0) { XGBoosterFree(b); b=nullptr; return false; }
        XGBoosterSetParam(b, "nthread", "1"); ready = true;
        snort::LogMessage("[botcl] Model: %s\n", p.c_str()); return true;
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
    Insp(Mod* m) { thr=m->thr; mp=m->mp; ws=m->ws; mn=m->mn; parse_whitelist(m->sp); }

    void parse_whitelist(const std::string& csv) {
        suppress_set.clear();
        if (csv.empty()) return;
        std::string s = csv;
        size_t pos = 0;
        while ((pos = s.find(',')) != std::string::npos) {
            std::string token = s.substr(0, pos);
            suppress_set.insert(parse_ip(token));
            s.erase(0, pos + 1);
        }
        if (!s.empty()) suppress_set.insert(parse_ip(s));
        if (!suppress_set.empty())
            snort::LogMessage("[botcl] Whitelist: %zu IPs\n", suppress_set.size());
    }

    static uint32_t parse_ip(const std::string& s) {
        uint32_t a,b,c,d;
        if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
            return (a<<24)|(b<<16)|(c<<8)|d;
        return 0;
    }

    bool configure(snort::SnortConfig*) override {
        if (!xgb.load(mp)) snort::ErrorMessage("[botcl] Model load failed.\n");
        if (load_scaler_json(mp, g_scaler, AGG_FEATURE_COUNT))
            snort::LogMessage("[botcl] Loaded scaler from JSON\n");
        else
            snort::LogMessage("[botcl] Using hardcoded scaler params\n");
        return true;
    }

    void eval(snort::Packet* p) override {
        if (!p || !p->has_ip()) return;
        double now = 0;
        if (p->pkth) now = p->pkth->ts.tv_sec + p->pkth->ts.tv_usec / 1e6;

        if (!p->ptrs.tcph) return;
        
        uint32_t src = gsip(p);
        uint32_t dst = gdip(p);
        if (src == 0 || dst == 0) return;
        uint16_t dp = p->ptrs.tcph->dst_port();
        
        // Process SYN-only packets for profile tracking (internal IPs only)
        if (p->ptrs.tcph->is_syn_only() && is_private_ip(src)) {
            auto it = profs.find(src);
            if (it == profs.end()) {
                BclProfile pr; pr.reset(src, now);
                pr.add_syn(dst, dp, now);
                profs[src] = pr;
            } else {
                auto& pr = it->second;
                if (pr.is_window_expired(now, ws)) {
                    if (!pr.inference_done && pr.syn_count >= mn) infer(pr, now);
                    pr.reset(src, now);
                }
                pr.add_syn(dst, dp, now);
                
                if (!pr.inference_done && pr.syn_count >= mn) {
                    double elapsed = now - pr.window_start_ts;
                    if (elapsed >= 30.0 || pr.syn_count >= 30)
                        infer(pr, now);
                }
            }
        }
        
        // Track incoming SYN-ACK as handshake completion + capture TCP window
        if (p->ptrs.tcph->is_syn_ack()) {
            auto it = profs.find(dst);
            if (it != profs.end() && !it->second.inference_done) {
                it->second.add_handshake();
                it->second.add_window(p->ptrs.tcph->win());
            }
        }
        
        // Track RST on any packet from a tracked IP (SYN-only tracking misses most RSTs)
        if (p->ptrs.tcph->is_rst()) {
            auto it = profs.find(src);
            if (it != profs.end() && !it->second.inference_done) {
                it->second.add_rst();
            }
        }
        
        // Track incoming packets to tracked IPs (for inc_ratio + bytes)
        {
            auto it = profs.find(dst);
            if (it != profs.end() && !it->second.inference_done) {
                it->second.add_incoming_pkt();
                if (p->dsize > 0) it->second.add_incoming_bytes(p->dsize);
            }
        }
        
        // Track FIN and PUSH on outgoing packets from tracked IPs
        {
            auto it = profs.find(src);
            if (it != profs.end() && !it->second.inference_done) {
                if (p->ptrs.tcph->is_fin()) it->second.add_fin();
                if (p->ptrs.tcph->is_psh()) it->second.add_push();
            }
        }
        
        // Sweep: check ALL profiles for stalled low-volume bots
        static uint32_t sweep = 0;
        if (++sweep % 500 == 0) {
            for (auto& kv : profs) {
                auto& pp = kv.second;
                double pp_elapsed = now - pp.window_start_ts;
                if (!pp.inference_done && pp.syn_count >= mn && pp_elapsed >= 60.0)
                    infer(pp, now);
                if (pp.is_window_expired(now, ws))
                    pp.reset(kv.first, now);
            }
        }
    }

private:
    double thr; std::string mp; uint32_t ws, mn;
    std::unordered_set<uint32_t> suppress_set;
    Xgb xgb;
    std::unordered_map<uint32_t, BclProfile> profs;
    static std::atomic<uint64_t> n_inf, n_alert;

    void infer(BclProfile& pr, double now) {
        double raw[22];
        pr.compute_features(raw, ws);
        float f[22]; for (unsigned i=0;i<22;i++) f[i] = raw[i];
        float score = 0; if (xgb.ok()) xgb.run(f, score);
        pr.inference_done = true; n_inf++;

        { static FILE* df = nullptr;
          if (!df) { df = fopen("/tmp/botcl_train_data.txt","w");
            if(df) fprintf(df,"# lb syn_cnt dst_ips dst_ports iat_cv entropy port_ratio rate ip_conc ip_ratio ip_ent iat_q90 time_den p_ip_r hshake inc_r data_d rst_r int_ratio in_bytes fin_ratio push_ratio tcp_win score src_ip\n"); }
          if(df) { int lbl=0;
            fprintf(df,"%d",lbl);
            for(unsigned i=0;i<22;i++) fprintf(df," %.6f",raw[i]);
            fprintf(df," %.6f %u\n",(double)score, pr.src_ip); } }

        double hshake_ratio = pr.syn_count > 0 ? (double)pr.handshake_count/pr.syn_count : 0.0;
        double inc_ratio = (pr.syn_count + pr.incoming_pkt_count) > 0 ? (double)pr.incoming_pkt_count/(pr.syn_count + pr.incoming_pkt_count) : 0.0;
        double rst_rate = pr.syn_count > 0 ? (double)pr.rst_count/pr.syn_count : 0.0;
        double int_ratio = pr.syn_count > 0 ? (double)pr.internal_dst_count/pr.syn_count : 0.0;
        double in_bytes = pr.syn_count > 0 ? (double)pr.incoming_bytes/pr.syn_count : 0.0;
        double fin_r = pr.syn_count > 0 ? (double)pr.fin_count/pr.syn_count : 0.0;
        double push_r = pr.syn_count > 0 ? (double)pr.push_count/pr.syn_count : 0.0;
        double win_m = pr.tcp_window_count > 0 ? pr.tcp_window_sum/pr.tcp_window_count : 0.0;
        
        // ─── Heuristic suppression rules ────────────────────────────────
        bool alert = score > thr;
        bool suppressed = false;
        const char* suppress_reason = "";
        
        // Rule 0: Whitelist - suppress alerts for known benign IPs
        if (alert && suppress_set.find(pr.src_ip) != suppress_set.end()) {
            suppressed = true;
            suppress_reason = "whitelist";
        }
        // Rule 1: Extreme RST rate (>5 RSTs per SYN) → broken connections, not bot C2
        if (alert && rst_rate > 5.0 && pr.syn_count >= 3) {
            suppressed = true;
            suppress_reason = "high_rst";
        }
        // Rule 2: Zero incoming traffic → idle/scanner, not active C2 client
        else if (alert && pr.incoming_pkt_count == 0 && pr.syn_count >= 3 && score < 0.3) {
            suppressed = true;
            suppress_reason = "no_incoming";
        }
        // Rule 3: High internal ratio (>0.6) with low-moderate score → internal server
        else if (alert && int_ratio > 0.6 && score < 0.3 && pr.syn_count >= 3) {
            suppressed = true;
            suppress_reason = "high_int_ratio";
        }
        // Rule 4: Zero handshake (no connections succeeded) with low score → scanning, not C2
        else if (alert && hshake_ratio < 0.1 && score < 0.2 && pr.syn_count >= 3) {
            suppressed = true;
            suppress_reason = "no_handshake";
        }
        // Rule 5: Zero handshake AND negligible incoming bytes → SYN-only, no real data exchange
        else if (alert && pr.handshake_count == 0 && pr.incoming_bytes < 10) {
            suppressed = true;
            suppress_reason = "no_data";
        }
        
        // ─── Alert dedup (30-minute cooldown per IP) ────────────────────
        if (alert && !suppressed) {
            double cooldown = 1800.0; // 30 minutes
            // Allow first alert always; suppress subsequent ones within cooldown
            if (pr.last_alert_time > 0 && now - pr.last_alert_time < cooldown) {
                suppressed = true;
                suppress_reason = "dedup";
            }
        }

        snort::LogMessage("[botcl] %u.%u.%u.%u syns=%u dsts=%zu ports=%zu iat_cv=%.3f hshake=%.3f inc_r=%.3f rst_r=%.3f int_r=%.3f byt=%.0f fin=%.3f psh=%.3f win=%.0f score=%.4f%s%s\n",
            (pr.src_ip>>24)&0xFF,(pr.src_ip>>16)&0xFF,(pr.src_ip>>8)&0xFF,pr.src_ip&0xFF,
            pr.syn_count, pr.syn_dst_ips.size(), pr.syn_dst_ports.size(), pr.iat_cv(),
            hshake_ratio, inc_ratio, rst_rate, int_ratio, in_bytes, fin_r, push_r, win_m, score,
            suppressed ? " SUPPRESSED:" : "",
            suppressed ? suppress_reason : "");

        if (alert && !suppressed) {
            n_alert++; 
            pr.last_alert_time = now;
            snort::DetectionEngine::queue_event(BCL_GID, BCL_SID);
            snort::LogMessage("[botcl] ALERT: %u.%u.%u.%u score=%.4f\n",
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
