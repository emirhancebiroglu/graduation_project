// xgb_inspector.cc — Snort3 XGBoost Inspector Plugin
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// Değişiklikler (combined run için):
//   - flow_tracker.h kullanır (XgbFlowData, XGB_FI_* enum)
//   - MlFlowData/FI_* ile isim çakışması yok — aynı process'e yüklenebilir
//   - swin/dwin clamp YOK (kasıtlı)
//   - flow_closing flag kontrolü korundu

#include <atomic>
#include <cstdio>
#include <cstring>

#include <xgboost/c_api.h>

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "flow_tracker.h"

// ---------------------------------------------------------------
// Sabitler
// ---------------------------------------------------------------
static const char* s_name = "xgb_inspector";
static const char* s_help = "flow-level XGBoost-based intrusion detection inspector";

static const uint32_t XGB_GID         = 301;
static const uint32_t XGB_SID_ANOMALY = 1;

unsigned XgbFlowData::inspector_id = 0;

// ---------------------------------------------------------------
// RobustScaler parametreleri (LSTM ile aynı pipeline, clamp yok)
// ---------------------------------------------------------------
static XgbScalerParams g_scaler_params = {
    // median
    { 0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206, 7.5071410797,
      73.0, 89.0, 255.0, 255.0, 0.3841277437, 0.3471507323 },
    // iqr
    { 0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192, 4.4213950593,
      72.0, 496.0, 255.0, 255.0, 2.1157851784, 1.9696133626 }
};

// ---------------------------------------------------------------
// Rule stub
// ---------------------------------------------------------------
static const snort::RuleMap xgb_rules[] = {
    { XGB_SID_ANOMALY, "XGBoost anomaly detected" },
    { 0, nullptr }
};

// ---------------------------------------------------------------
// XgbModule
// ---------------------------------------------------------------
static const snort::Parameter xgb_params[] = {
    { "threshold",   snort::Parameter::PT_REAL,   "0.0:1.0", "0.5",
      "XGBoost anomaly threshold (0.0-1.0)" },
    { "max_packets", snort::Parameter::PT_INT,    "2:10000", "100",
      "max packets per flow before triggering inference" },
    { "model_path",  snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/fine_tuned_xgb_model.json",
      "path to XGBoost JSON model file" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class XgbModule : public snort::Module {
public:
    XgbModule() : snort::Module(s_name, s_help, xgb_params) {}

    const snort::RuleMap* get_rules() const override { return xgb_rules; }

    bool set(const char*, snort::Value& val, snort::SnortConfig*) override {
        if      (val.is("threshold"))   threshold   = val.get_real();
        else if (val.is("max_packets")) max_packets = static_cast<uint32_t>(val.get_int64());
        else if (val.is("model_path"))  model_path  = val.get_string();
        else return false;
        return true;
    }

    Usage get_usage() const override { return INSPECT; }

    double      threshold   = 0.5;
    uint32_t    max_packets = 100;
    std::string model_path  = "/home/emirhan/bitirme/models/fine_tuned_xgb_model.json";
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
            snort::ErrorMessage("[xgb_inspector] Booster oluşturulamadı: %s\n",
                XGBGetLastError());
            return false;
        }
        if (XGBoosterLoadModel(booster, path.c_str()) != 0) {
            snort::ErrorMessage("[xgb_inspector] Model yüklenemedi: %s — %s\n",
                path.c_str(), XGBGetLastError());
            XGBoosterFree(booster);
            booster = nullptr;
            return false;
        }
        XGBoosterSetParam(booster, "nthread", "1");
        snort::LogMessage("[xgb_inspector] Model yüklendi: %s\n", path.c_str());
        ready = true;
        return true;
    }

    bool run(const float* features, float& score) {
        if (!ready) return false;

        DMatrixHandle dmat = nullptr;
        if (XGDMatrixCreateFromMat(features, 1, XGB_FI_COUNT, NAN, &dmat) != 0 || !dmat) {
            snort::ErrorMessage("[xgb_inspector] DMatrix hatası: %s\n", XGBGetLastError());
            return false;
        }

        bst_ulong out_len = 0;
        const float* out_result = nullptr;
        int ret = XGBoosterPredict(booster, dmat, 0, 0, 0, &out_len, &out_result);

        if (ret != 0 || out_len == 0 || !out_result) {
            snort::ErrorMessage("[xgb_inspector] Predict hatası: %s\n", XGBGetLastError());
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
// XgbInspector
// ---------------------------------------------------------------
class XgbInspector : public snort::Inspector {
public:
    XgbInspector(XgbModule* mod) {
        threshold   = mod->threshold;
        max_packets = mod->max_packets;
        model_path  = mod->model_path;
    }

    void show(const snort::SnortConfig*) const override {
        snort::LogMessage("    threshold:   %f\n", threshold);
        snort::LogMessage("    max_packets: %u\n", max_packets);
        snort::LogMessage("    model_path:  %s\n", model_path.c_str());
    }

    bool configure(snort::SnortConfig*) override {
        XgbFlowData::inspector_id = snort::FlowData::create_flow_data_id();
        if (!engine.load(model_path)) {
            snort::ErrorMessage("[xgb_inspector] Model yüklenemedi, devre dışı.\n");
        }
        return true;
    }

    void eval(snort::Packet* pkt) override {
        if (!pkt->flow || !pkt->has_ip())
            return;

        XgbFlowData* fd = static_cast<XgbFlowData*>(
            pkt->flow->get_flow_data(XgbFlowData::inspector_id));

        if (!fd) {
            fd = new XgbFlowData(XgbFlowData::inspector_id);
            pkt->flow->set_flow_data(fd);
        }

        if (fd->is_inference_done())
            return;

        bool     from_client = pkt->is_from_client();
        uint32_t payload_len = pkt->dsize;
        int32_t  tcp_win     = -1;
        if (pkt->ptrs.tcph)
            tcp_win = static_cast<int32_t>(pkt->ptrs.tcph->win());

        double pkt_ts = 0.0;
        if (pkt->pkth)
            pkt_ts = static_cast<double>(pkt->pkth->ts.tv_sec) +
                     static_cast<double>(pkt->pkth->ts.tv_usec) / 1e6;

        fd->update(from_client, payload_len, tcp_win, pkt_ts);

        // Flow kapanış kontrolü
        bool flow_closing = false;
        if (pkt->flow) {
            uint32_t flags = pkt->flow->ssn_state.session_flags;
            flow_closing = flags & (SSNFLAG_CLIENT_FIN | SSNFLAG_SERVER_FIN |
                                    SSNFLAG_RESET | SSNFLAG_TIMEDOUT | SSNFLAG_PRUNED);
        }

        if (fd->get_total_packets() >= max_packets || flow_closing)
            run_inference(pkt, fd);
    }

private:
    double       threshold;
    uint32_t     max_packets;
    std::string  model_path;
    XGBoostEngine engine;

    // Score dağılımı istatistikleri
    static std::atomic<uint64_t> cnt_total;
    static std::atomic<uint64_t> cnt_above;

    void run_inference(snort::Packet* pkt, XgbFlowData* fd) {
        double raw[XGB_FI_COUNT];
        fd->compute_features(raw);

        double processed[XGB_FI_COUNT];
        std::memcpy(processed, raw, sizeof(raw));
        XgbFlowData::preprocess(processed, g_scaler_params);

        float features_f[XGB_FI_COUNT];
        for (unsigned i = 0; i < XGB_FI_COUNT; i++)
            features_f[i] = static_cast<float>(processed[i]);

        float score = 0.0f;
        bool  ok    = false;

        if (engine.is_ready())
            ok = engine.run(features_f, score);

        cnt_total++;
        if (score > static_cast<float>(threshold)) cnt_above++;

        if (cnt_total % 50000 == 0) {
            snort::LogMessage("[xgb_inspector] total=%lu above_thresh=%lu (%.1f%%)\n",
                cnt_total.load(), cnt_above.load(),
                100.0 * cnt_above.load() / cnt_total.load());
        }

        snort::LogMessage(
            "[xgb_inspector] pkts=%u score=%.4f engine=%s | "
            "dur=%.4f sp=%.0f dp=%.0f sb=%.0f db=%.0f "
            "smsz=%.0f dmsz=%.0f sw=%.0f dw=%.0f si=%.4f di=%.4f\n",
            fd->get_total_packets(), score, ok ? "xgboost" : "stub",
            raw[XGB_FI_DUR],    raw[XGB_FI_SPKTS],   raw[XGB_FI_DPKTS],
            raw[XGB_FI_SBYTES], raw[XGB_FI_DBYTES],  raw[XGB_FI_SMEANSZ],
            raw[XGB_FI_DMEANSZ],raw[XGB_FI_SWIN],    raw[XGB_FI_DWIN],
            raw[XGB_FI_SINTPKT],raw[XGB_FI_DINTPKT]);

        if (score > static_cast<float>(threshold))
            snort::DetectionEngine::queue_event(XGB_GID, XGB_SID_ANOMALY);

        fd->mark_inference_done();
    }
};

std::atomic<uint64_t> XgbInspector::cnt_total{0};
std::atomic<uint64_t> XgbInspector::cnt_above{0};

// ---------------------------------------------------------------
// Plugin API
// ---------------------------------------------------------------
static snort::Module*   mod_ctor()                  { return new XgbModule; }
static void             mod_dtor(snort::Module* m)  { delete m; }
static snort::Inspector* xgb_ctor(snort::Module* m) { return new XgbInspector(static_cast<XgbModule*>(m)); }
static void              xgb_dtor(snort::Inspector* p) { delete p; }

static const snort::InspectApi xgb_api = {
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
    xgb_ctor,
    xgb_dtor,
    nullptr, nullptr
};

SO_PUBLIC const snort::BaseApi* snort_plugins[] = { &xgb_api.base, nullptr };