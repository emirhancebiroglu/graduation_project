// ml_inspector.cc — Snort3 ML Inspector Plugin
// Bitirme Projesi: IDS Performans Karşılaştırma (LSTM/XGBoost/Snort3)
//
// Flow-level özellik toplayıp TFLite LSTM inference tetikleyen Snort3 inspector.
// Model: fine_tuned_lstm_model.tflite
// Input shape:  [1, 1, 11]  (batch=1, timesteps=1, features=11)
// Output shape: [1, 1]      (sigmoid anomaly score)

#include <cstdio>
#include <cstring>

// TFLite C API
#include "tensorflow/lite/c/c_api.h"
#include "tensorflow/lite/c/c_api_types.h"

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "detection/detection_engine.h"

#include "flow_tracker.h"

// ---------------------------------------------------------------
// Sabitler
// ---------------------------------------------------------------
static const char* s_name = "ml_inspector";
static const char* s_help = "flow-level LSTM-based intrusion detection inspector";

static const uint32_t ML_GID         = 300;
static const uint32_t ML_SID_ANOMALY = 1;

unsigned MlFlowData::inspector_id = 0;

// ---------------------------------------------------------------
// RobustScaler parametreleri — export_scaler.py ile doğrulandı
// Feature sırası: dur, spkts, dpkts, sbytes, dbytes,
//                 smeansz, dmeansz, swin, dwin, sintpkt, dintpkt
// ---------------------------------------------------------------
static ScalerParams g_scaler_params = {
    // median (center_)
    {
        0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206,
        7.5071410797, 73.0000000000, 89.0000000000, 255.0000000000,
        255.0000000000, 0.3841277437, 0.3471507323
    },
    // iqr (scale_)
    {
        0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192,
        4.4213950593, 72.0000000000, 496.0000000000, 255.0000000000,
        255.0000000000, 2.1157851784, 1.9696133626
    }
};

// ---------------------------------------------------------------
// Rule stub
// ---------------------------------------------------------------
static const snort::RuleMap ml_rules[] =
{
    { ML_SID_ANOMALY, "ML LSTM anomaly detected" },
    { 0, nullptr }
};

// ---------------------------------------------------------------
// MlModule — Lua konfigürasyon parametreleri
// ---------------------------------------------------------------
static const snort::Parameter ml_params[] =
{
    { "threshold", snort::Parameter::PT_REAL, "0.0:1.0", "0.5",
      "LSTM anomaly threshold (0.0-1.0)" },

    { "max_packets", snort::Parameter::PT_INT, "2:10000", "100",
      "max packets per flow before triggering inference" },

    { "model_path", snort::Parameter::PT_STRING, nullptr,
      "/home/emirhan/bitirme/models/fine_tuned_lstm_model_v5.tflite",
      "path to TFLite model file" },

    { nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class MlModule : public snort::Module
{
public:
    MlModule() : snort::Module(s_name, s_help, ml_params) { }

    const snort::RuleMap* get_rules() const override
    { return ml_rules; }

    bool set(const char*, snort::Value& val, snort::SnortConfig*) override
    {
        if (val.is("threshold"))
            threshold = val.get_real();
        else if (val.is("max_packets"))
            max_packets = static_cast<uint32_t>(val.get_int64());
        else if (val.is("model_path"))
            model_path = val.get_string();
        else
            return false;
        return true;
    }

    Usage get_usage() const override { return INSPECT; }

    double      threshold   = 0.5;
    uint32_t    max_packets = 100;
    std::string model_path  = "/home/emirhan/bitirme/models/fine_tuned_lstm_model_v5.tflite";
};

// ---------------------------------------------------------------
// TFLite RAII wrapper
// ---------------------------------------------------------------
class TFLiteEngine
{
public:
    TFLiteEngine() = default;

    ~TFLiteEngine()
    {
        if (interpreter) TfLiteInterpreterDelete(interpreter);
        if (model)       TfLiteModelDelete(model);
    }

    // Kopyalamayı engelle
    TFLiteEngine(const TFLiteEngine&) = delete;
    TFLiteEngine& operator=(const TFLiteEngine&) = delete;

    bool load(const std::string& path)
    {
        model = TfLiteModelCreateFromFile(path.c_str());
        if (!model)
        {
            snort::ErrorMessage("[ml_inspector] TFLite model yüklenemedi: %s\n",
                path.c_str());
            return false;
        }

        TfLiteInterpreterOptions* opts = TfLiteInterpreterOptionsCreate();
        TfLiteInterpreterOptionsSetNumThreads(opts, 1);
        interpreter = TfLiteInterpreterCreate(model, opts);
        TfLiteInterpreterOptionsDelete(opts);

        if (!interpreter)
        {
            snort::ErrorMessage("[ml_inspector] TFLite interpreter oluşturulamadı\n");
            return false;
        }

        if (TfLiteInterpreterAllocateTensors(interpreter) != kTfLiteOk)
        {
            snort::ErrorMessage("[ml_inspector] TFLite tensor allocate başarısız\n");
            return false;
        }

        // Input tensor doğrulama: shape [1, 1, 11]
        TfLiteTensor* input_tensor =
            TfLiteInterpreterGetInputTensor(interpreter, 0);

        if (!input_tensor)
        {
            snort::ErrorMessage("[ml_inspector] Input tensor alınamadı\n");
            return false;
        }

        int ndims = TfLiteTensorNumDims(input_tensor);
        if (ndims != 3 ||
            TfLiteTensorDim(input_tensor, 1) != 1 ||
            TfLiteTensorDim(input_tensor, 2) != (int)FI_COUNT)
        {
            snort::ErrorMessage(
                "[ml_inspector] Beklenmeyen input shape. "
                "Beklenen: [1,1,%u], ndims=%d\n", FI_COUNT, ndims);
            return false;
        }

        snort::LogMessage("[ml_inspector] TFLite model yüklendi: %s\n",
            path.c_str());
        ready = true;
        return true;
    }

    // inference: processed[FI_COUNT] → score
    // Dönüş: true = başarılı, score güncellendi
    bool run(const float* features, float& score)
    {
        if (!ready) return false;

        // Input tensor'a features'ı kopyala
        TfLiteTensor* input_tensor =
            TfLiteInterpreterGetInputTensor(interpreter, 0);

        if (TfLiteTensorCopyFromBuffer(input_tensor,
                features, FI_COUNT * sizeof(float)) != kTfLiteOk)
            return false;

        // Inference
        if (TfLiteInterpreterInvoke(interpreter) != kTfLiteOk)
            return false;

        // Output tensor'dan skoru oku — shape [1, 1]
        const TfLiteTensor* output_tensor =
            TfLiteInterpreterGetOutputTensor(interpreter, 0);

        float result = 0.0f;
        if (TfLiteTensorCopyToBuffer(output_tensor,
                &result, sizeof(float)) != kTfLiteOk)
            return false;

        score = result;
        return true;
    }

    bool is_ready() const { return ready; }

private:
    TfLiteModel*       model       = nullptr;
    TfLiteInterpreter* interpreter = nullptr;
    bool               ready       = false;
};

// ---------------------------------------------------------------
// MlInspector — Ana inspector sınıfı
// ---------------------------------------------------------------
class MlInspector : public snort::Inspector
{
public:
    MlInspector(MlModule* mod)
    {
        threshold   = mod->threshold;
        max_packets = mod->max_packets;
        model_path  = mod->model_path;
    }

    void show(const snort::SnortConfig*) const override
    {
        snort::LogMessage("    threshold:   %f\n", threshold);
        snort::LogMessage("    max_packets: %u\n", max_packets);
        snort::LogMessage("    model_path:  %s\n", model_path.c_str());
    }

    bool configure(snort::SnortConfig*) override
    {
        MlFlowData::inspector_id =
            snort::FlowData::create_flow_data_id();

        // TFLite modelini yükle
        if (!engine.load(model_path))
        {
            snort::ErrorMessage(
                "[ml_inspector] Model yüklenemedi, inspector devre dışı.\n");
            // configure false döndürürse Snort3 başlamaz —
            // bunu istemiyoruz, stub moduna düş
            return true;
        }
        return true;
    }

    void eval(snort::Packet* pkt) override
    {
        if (!pkt->flow || !pkt->has_ip())
            return;

        MlFlowData* fd = static_cast<MlFlowData*>(
            pkt->flow->get_flow_data(MlFlowData::inspector_id));

        if (!fd)
        {
            fd = new MlFlowData(MlFlowData::inspector_id);
            pkt->flow->set_flow_data(fd);
        }

        if (fd->is_inference_done())
            return;

        // Paket bilgilerini çıkar
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

        bool is_fin_rst = pkt->ptrs.tcph &&
                  (pkt->ptrs.tcph->th_flags & (TH_FIN | TH_RST));

        if (fd->get_total_packets() >= max_packets ||
            (is_fin_rst && fd->get_total_packets() >= 2))
            run_inference(pkt, fd);
    }

private:
    double      threshold;
    uint32_t    max_packets;
    std::string model_path;
    TFLiteEngine engine;

    void run_inference(snort::Packet* pkt, MlFlowData* fd)
    {
        // Ham feature vektörü
        double raw[FI_COUNT];
        fd->compute_features(raw);

        // Preprocessing: log1p + RobustScaler
        double processed_d[FI_COUNT];
        std::memcpy(processed_d, raw, sizeof(raw));
        MlFlowData::preprocess(processed_d, g_scaler_params);

        // double → float (TFLite float32 bekler)
        float features_f[FI_COUNT];
        for (unsigned i = 0; i < FI_COUNT; i++)
            features_f[i] = static_cast<float>(processed_d[i]);

        float score = 0.0f;
        bool  ok    = false;

        if (engine.is_ready())
            ok = engine.run(features_f, score);

        // Log: her zaman yaz (debug)
        snort::LogMessage(
            "[ml_inspector] flow_pkts=%u score=%.4f inference=%s | "
            "dur=%.4f spkts=%.1f dpkts=%.1f sbytes=%.1f dbytes=%.1f "
            "smeansz=%.1f dmeansz=%.1f swin=%.1f dwin=%.1f "
            "sintpkt=%.4f dintpkt=%.4f\n",
            fd->get_total_packets(),
            score,
            ok ? "tflite" : "stub",
            raw[FI_DUR],   raw[FI_SPKTS],  raw[FI_DPKTS],
            raw[FI_SBYTES], raw[FI_DBYTES],
            raw[FI_SMEANSZ], raw[FI_DMEANSZ],
            raw[FI_SWIN],  raw[FI_DWIN],
            raw[FI_SINTPKT], raw[FI_DINTPKT]);

        if (score > static_cast<float>(threshold))
            snort::DetectionEngine::queue_event(ML_GID, ML_SID_ANOMALY);

        fd->mark_inference_done();
    }
};

// ---------------------------------------------------------------
// Plugin API
// ---------------------------------------------------------------
static snort::Module* mod_ctor()  { return new MlModule; }
static void mod_dtor(snort::Module* m) { delete m; }

static snort::Inspector* ml_ctor(snort::Module* m)
{ return new MlInspector(static_cast<MlModule*>(m)); }

static void ml_dtor(snort::Inspector* p) { delete p; }

static const snort::InspectApi ml_api =
{
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
    ml_ctor,
    ml_dtor,
    nullptr, nullptr
};

SO_PUBLIC const snort::BaseApi* snort_plugins[] =
{
    &ml_api.base,
    nullptr
};
