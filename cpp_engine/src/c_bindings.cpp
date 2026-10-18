#include "../include/c_bindings.h"
#include "../include/binary_feature_extractor.hpp"
#include "../include/entropy_calculator.hpp"
#include <cstring>

extern "C" {

bool extract_features_from_buffer(
    const uint8_t* data, 
    size_t size, 
    CSimpleFeatures* out_features
) {
    if (!data || size == 0 || !out_features) return false;
    memset(out_features, 0, sizeof(CSimpleFeatures));

    Analyzer::CompleteBinaryReport rep = Analyzer::BinaryFeatureExtractor::analyze_buffer(data, size);

    out_features->overall_entropy = rep.overall_entropy;
    out_features->max_window_entropy = rep.max_window_entropy;
    out_features->is_packed = rep.is_packed ? 1 : 0;
    out_features->file_size = rep.file_size;
    out_features->total_strings = static_cast<uint32_t>(rep.total_strings);
    out_features->suspicious_apis_count = static_cast<uint32_t>(rep.iocs.suspicious_apis.size());
    out_features->urls_count = static_cast<uint32_t>(rep.iocs.urls.size());
    out_features->ip_count = static_cast<uint32_t>(rep.iocs.ip_addresses.size());
    out_features->has_injection = rep.signatures.has_injection_pattern ? 1 : 0;
    out_features->has_ransomware = rep.signatures.has_ransomware_pattern ? 1 : 0;
    out_features->has_evasion = rep.signatures.has_evasion_pattern ? 1 : 0;
    out_features->threat_score = static_cast<uint32_t>(rep.signatures.cumulative_threat_score);

    for (size_t i = 0; i < 12 && i < rep.ml_feature_vector.size(); ++i) {
        out_features->ml_features[i] = rep.ml_feature_vector[i];
    }

    return true;
}

bool extract_features_from_file(
    const char* filepath, 
    CSimpleFeatures* out_features
) {
    if (!filepath || !out_features) return false;
    memset(out_features, 0, sizeof(CSimpleFeatures));

    Analyzer::CompleteBinaryReport rep = Analyzer::BinaryFeatureExtractor::analyze_file(filepath);

    out_features->overall_entropy = rep.overall_entropy;
    out_features->max_window_entropy = rep.max_window_entropy;
    out_features->is_packed = rep.is_packed ? 1 : 0;
    out_features->file_size = rep.file_size;
    out_features->total_strings = static_cast<uint32_t>(rep.total_strings);
    out_features->suspicious_apis_count = static_cast<uint32_t>(rep.iocs.suspicious_apis.size());
    out_features->urls_count = static_cast<uint32_t>(rep.iocs.urls.size());
    out_features->ip_count = static_cast<uint32_t>(rep.iocs.ip_addresses.size());
    out_features->has_injection = rep.signatures.has_injection_pattern ? 1 : 0;
    out_features->has_ransomware = rep.signatures.has_ransomware_pattern ? 1 : 0;
    out_features->has_evasion = rep.signatures.has_evasion_pattern ? 1 : 0;
    out_features->threat_score = static_cast<uint32_t>(rep.signatures.cumulative_threat_score);

    for (size_t i = 0; i < 12 && i < rep.ml_feature_vector.size(); ++i) {
        out_features->ml_features[i] = rep.ml_feature_vector[i];
    }

    return true;
}

bool analyze_to_json_c(
    const uint8_t* data, 
    size_t size, 
    const char* filepath,
    char* json_out_buf, 
    size_t max_buf_len
) {
    if (!json_out_buf || max_buf_len == 0) return false;

    Analyzer::CompleteBinaryReport rep;
    if (data && size > 0) {
        rep = Analyzer::BinaryFeatureExtractor::analyze_buffer(data, size, filepath ? filepath : "buffer");
    } else if (filepath) {
        rep = Analyzer::BinaryFeatureExtractor::analyze_file(filepath);
    } else {
        return false;
    }

    std::string json_str = rep.to_json();
    if (json_str.length() + 1 > max_buf_len) {
        // Buffer too small
        return false;
    }

    std::memcpy(json_out_buf, json_str.c_str(), json_str.length() + 1);
    return true;
}

double calculate_shannon_entropy_c(const uint8_t* data, size_t size) {
    return Analyzer::EntropyCalculator::calculate_buffer_entropy(data, size);
}

} // extern "C"

