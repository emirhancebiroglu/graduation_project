// scaler_loader.h — JSON sidecar scaler loader
// Loads median/iqr arrays from <model_path>_scaler.json
// Returns true if loaded, false if file missing or parse error

#ifndef SCALER_LOADER_H
#define SCALER_LOADER_H

#include <algorithm>
#include <fstream>
#include <string>

#include "json.hpp"

template<typename ScalerT>
bool load_scaler_json(const std::string& model_path, ScalerT& scaler, unsigned count) {
    std::string sp = model_path;
    auto dot = sp.rfind('.');
    if (dot != std::string::npos)
        sp = sp.substr(0, dot) + "_scaler.json";
    else
        sp += "_scaler.json";

    std::ifstream f(sp);
    if (!f.is_open()) {
        fprintf(stderr, "[scaler] Cannot open: %s\n", sp.c_str());
        return false;
    }

    try {
        nlohmann::json j;
        f >> j;

        auto med = j["median"];
        auto iq  = j["iqr"];
        if (!med.is_array() || !iq.is_array())
            return false;

        unsigned n = std::min(med.size(), static_cast<size_t>(count));
        n = std::min(n, static_cast<unsigned>(iq.size()));
        for (unsigned i = 0; i < n; i++) {
            scaler.median[i] = med[i].get<double>();
            scaler.iqr[i]    = iq[i].get<double>();
        }
        return true;
    } catch (...) {
        return false;
    }
}

#endif
