// dos_specialist_inspector.cc — Snort3 DoS Specialist Inspector Plugin
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// GID=302 — DoS Hulk + GoldenEye specialist
// 17-feature genişletilmiş XGBoost modeli (mp_2 varyantı, threshold=0.50)
//
// ODR durumu: bu plugin xgb_inspector (GID=301) ve ml_inspector (GID=300) ile
// aynı process'e yüklenebilir. Sınıf/enum isimleri çakışmaz:
//   DosFlowData / DOS_FI_* (bu dosya)
//   XgbFlowData / XGB_FI_* (xgb_inspector)
//   MlFlowData  / FI_*     (ml_inspector/LSTM)
//
// [VARSAYIM] scaler parametreleri (g_scaler_params): mp_2 varyantı
// eğitim çıktısında models/dos_specialist/mp_2_scaler.json olarak
// kaydedilecek — değerler oradan kopyalanmalı. Şu anki değerler
// placeholder (sıfır median, birim IQR = no-op transform).
// Gerçek değerler kopyalandıktan sonra bu uyarıyı sil.

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

#include "flow_tracker_dos_specialist.h"

// ---------------------------------------------------------------
// Sabitler
// ---------------------------------------------------------------
static const char* s_name = "dos_specialist";
static const char* s_help = "DoS Hulk+GoldenEye specialist XGBoost inspector (GID=302)";

static const uint32_t DOS_GID         = 302;
static const uint32_t DOS_SID_ANOMALY = 1;

unsigned DosFlowData::inspector_id = 0;

static DosScalerParams g_scaler_params = {
    { 37065.0, 42.0, 105.0, 1.0, 1.0, 59.259132385253906, 1067.2523193359375, 4382.0, 48.0,
      251.0, 62.0, 30403.0, 18600.35546875, 93.06349182128906, 45.033321380615234, 0.0, 0.0 },
    { 12114364.5, 53.07692337036133, 1656.4285888671875, 0.3333333730697632, 0.3333333134651184, 16239.996387004852, 38703.4501953125, 12099997.0, 37112.5,
      1024.0, 236.0, 6531627.25, 23000000.0, 849.0714111328125, 1524.348876953125, 1.0, 1.0 }
};

// ---------------------------------------------------------------
// Rule stub
// ---------------------------------------------------------------
static const snort::RuleMap dos_rules[] = {
    { DOS_SID_ANOMALY, "DoS Specialist: Hulk/GoldenEye anomaly detected" },
    { 0, nullptr }
};

// ---------------------------------------------------------------
// DosModule — Lua konfigürasyon parametreleri
// ---------------------------------------------------------------
static const snort::Parameter dos_params[] = {
    { "threshold",   snort::Parameter::PT_REAL,   "0.0:1.0", "0.5",
      "DoS anomaly score threshold (mp_2 optimal = 0.50)" },
    { "max_packets", snort::Parameter::PT_INT,    "2:10000", "2",
      "max packets before inference (mp_2 trained = 2)" },
    { "model_path",  snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/dos_specialist/mp_2_xgb_model.json",
      "path to DoS specialist XGBoost JSON model" },
    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DosModule : public snort::Module {
public:
    DosModule() : snort::Module(s_name, s_help, dos_params) {}

    const snort::RuleMap* get_rules() const override { return dos_rules; }

    bool set(const char*, snort::Value& val, snort::SnortConfig*) override {
        if      (val.is("threshold"))   threshold   = val.get_real();
        else if (val.is("max_packets")) max_packets = static_cast<uint32_t>(val.get_int64());
        else if (val.is("model_path"))  model_path  = val.get_string();
        else return false;
        return true;
    }

    Usage get_usage() const override { return INSPECT; }

    double      threshold   = 0.5;
    uint32_t    max_packets = 2;
    std::string model_path  = "/home/emirhan/bitirme/models/dos_specialist/mp_2_xgb_model.json";
};

// ---------------------------------------------------------------
// XGBoost engine wrapper (DosFlowData::DOS_FI_COUNT = 17)
// ---------------------------------------------------------------
class DosXGBoostEngine {
public:
    DosXGBoostEngine() = default;
    ~DosXGBoostEngine() { if (booster) XGBoosterFree(booster); }
    DosXGBoostEngine(const DosXGBoostEngine&) = delete;
    DosXGBoostEngine& operator=(const DosXGBoostEngine&) = delete;

    bool load(const std::string& path) {
        if (XGBoosterCreate(nullptr, 0, &booster) != 0) {
            snort::ErrorMessage("[dos_specialist] Booster oluşturulamadı: %s\n",
                XGBGetLastError());
            return false;
        }
        if (XGBoosterLoadModel(booster, path.c_str()) != 0) {
            snort::ErrorMessage("[dos_specialist] Model yüklenemedi: %s — %s\n",
                path.c_str(), XGBGetLastError());
            XGBoosterFree(booster);
            booster = nullptr;
            return false;
        }
        XGBoosterSetParam(booster, "nthread", "1");
        snort::LogMessage("[dos_specialist] Model yüklendi: %s\n", path.c_str());
        ready = true;
        return true;
    }

    bool run(const float* features, float& score) {
        if (!ready) return false;

        DMatrixHandle dmat = nullptr;
        if (XGDMatrixCreateFromMat(features, 1, DOS_FI_COUNT, NAN, &dmat) != 0 || !dmat) {
            snort::ErrorMessage("[dos_specialist] DMatrix hatası: %s\n", XGBGetLastError());
            return false;
        }

        bst_ulong    out_len    = 0;
        const float* out_result = nullptr;
        int ret = XGBoosterPredict(booster, dmat, 0, 0, 0, &out_len, &out_result);

        if (ret != 0 || out_len == 0 || !out_result) {
            snort::ErrorMessage("[dos_specialist] Predict hatası: %s\n", XGBGetLastError());
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
// DosInspector — Ana inspector sınıfı
// ---------------------------------------------------------------
class DosInspector : public snort::Inspector {
public:
    DosInspector(DosModule* mod) {
        threshold   = mod->threshold;
        max_packets = mod->max_packets;
        model_path  = mod->model_path;
    }

    void show(const snort::SnortConfig*) const override {
        snort::LogMessage("    [dos_specialist] threshold:   %f\n", threshold);
        snort::LogMessage("    [dos_specialist] max_packets: %u\n", max_packets);
        snort::LogMessage("    [dos_specialist] model_path:  %s\n", model_path.c_str());
    }

    bool configure(snort::SnortConfig*) override {
        DosFlowData::inspector_id = snort::FlowData::create_flow_data_id();
        if (!engine.load(model_path)) {
            snort::ErrorMessage("[dos_specialist] Model yüklenemedi, devre dışı.\n");
        }
        return true;
    }

    void eval(snort::Packet* pkt) override {
        if (!pkt->flow || !pkt->has_ip())
            return;

        // Flow data al ya da oluştur
        DosFlowData* fd = static_cast<DosFlowData*>(
            pkt->flow->get_flow_data(DosFlowData::inspector_id));

        if (!fd) {
            fd = new DosFlowData(DosFlowData::inspector_id);
            pkt->flow->set_flow_data(fd);
        }

        if (fd->is_inference_done())
            return;

        // Paket meta bilgilerini çıkar
        bool     from_client = pkt->is_from_client();
        uint32_t payload_len = pkt->dsize;
        int32_t  tcp_win     = -1;
        uint8_t  tcp_flags   = 0;

        if (pkt->ptrs.tcph) {
            tcp_win   = static_cast<int32_t>(pkt->ptrs.tcph->win());
            tcp_flags = pkt->ptrs.tcph->th_flags;
        }

        double pkt_ts = 0.0;
        if (pkt->pkth)
            pkt_ts = static_cast<double>(pkt->pkth->ts.tv_sec) +
                     static_cast<double>(pkt->pkth->ts.tv_usec) / 1e6;

        fd->update(from_client, payload_len, tcp_win, tcp_flags, pkt_ts);

        // Inference tetikleme: max_packets dolunca VEYA flow kapanınca
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
    double        threshold;
    uint32_t      max_packets;
    std::string   model_path;
    DosXGBoostEngine engine;

    static std::atomic<uint64_t> cnt_total;
    static std::atomic<uint64_t> cnt_above;

    void run_inference(snort::Packet* pkt, DosFlowData* fd) {
        // Ham feature vektörü
        double raw[DOS_FI_COUNT];
        fd->compute_features(raw);

        // Preprocessing (log1p + RobustScaler)
        double processed[DOS_FI_COUNT];
        std::memcpy(processed, raw, sizeof(raw));
        DosFlowData::preprocess(processed, g_scaler_params);

        // double → float (XGBoost C API float ister)
        float features_f[DOS_FI_COUNT];
        for (unsigned i = 0; i < DOS_FI_COUNT; i++)
            features_f[i] = static_cast<float>(processed[i]);

        float score = 0.0f;
        bool  ok    = engine.run(features_f, score);

        cnt_total++;
        if (score > static_cast<float>(threshold)) cnt_above++;

        // Periyodik istatistik logu (her 50K flow)
        if (cnt_total % 50000 == 0) {
            snort::LogMessage(
                "[dos_specialist] total=%lu above_thresh=%lu (%.1f%%)\n",
                cnt_total.load(), cnt_above.load(),
                100.0 * cnt_above.load() / cnt_total.load());
        }

        // Detaylı flow logu (alert_csv ve confusion matrix için gerekli)
        snort::LogMessage(
            "[dos_specialist] pkts=%u score=%.4f engine=%s | "
            "dur=%.4f sp=%.0f dp=%.0f sb=%.0f db=%.0f "
            "smsz=%.1f dmsz=%.1f sw=%.0f dw=%.0f "
            "si=%.2f di=%.2f "
            "iat_mean=%.2f iat_std=%.2f "
            "plen_mean=%.1f plen_std=%.1f "
            "rst=%.0f urg=%.0f\n",
            fd->get_total_packets(), score, ok ? "dos_xgb" : "stub",
            raw[DOS_FI_DUR],           raw[DOS_FI_SPKTS],
            raw[DOS_FI_DPKTS],         raw[DOS_FI_SBYTES],
            raw[DOS_FI_DBYTES],        raw[DOS_FI_SMEANSZ],
            raw[DOS_FI_DMEANSZ],       raw[DOS_FI_SWIN],
            raw[DOS_FI_DWIN],          raw[DOS_FI_SINTPKT],
            raw[DOS_FI_DINTPKT],       raw[DOS_FI_FLOW_IAT_MEAN],
            raw[DOS_FI_FLOW_IAT_STD],  raw[DOS_FI_PKT_LEN_MEAN],
            raw[DOS_FI_PKT_LEN_STD],   raw[DOS_FI_RST_COUNT],
            raw[DOS_FI_URG_COUNT]);

        // Eşik aşıldıysa alert üret (GID=302, SID=1)
        if (score > static_cast<float>(threshold))
            snort::DetectionEngine::queue_event(DOS_GID, DOS_SID_ANOMALY);

        fd->mark_inference_done();
    }
};

std::atomic<uint64_t> DosInspector::cnt_total{0};
std::atomic<uint64_t> DosInspector::cnt_above{0};

// ---------------------------------------------------------------
// Plugin API (Snort3 dinamik yükleme için zorunlu)
// ---------------------------------------------------------------
static snort::Module*    mod_ctor()                   { return new DosModule; }
static void              mod_dtor(snort::Module* m)   { delete m; }
static snort::Inspector* dos_ctor(snort::Module* m)   { return new DosInspector(static_cast<DosModule*>(m)); }
static void              dos_dtor(snort::Inspector* p){ delete p; }

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