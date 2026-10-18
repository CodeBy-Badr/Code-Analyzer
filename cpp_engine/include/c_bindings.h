#ifndef C_BINDINGS_H
#define C_BINDINGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
    #define EXPORT_API __declspec(dllexport)
#else
    #define EXPORT_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double overall_entropy;
    double max_window_entropy;
    uint32_t is_packed;
    uint64_t file_size;
    uint32_t total_strings;
    uint32_t suspicious_apis_count;
    uint32_t urls_count;
    uint32_t ip_count;
    uint32_t has_injection;
    uint32_t has_ransomware;
    uint32_t has_evasion;
    uint32_t threat_score;
    double ml_features[12];
} CSimpleFeatures;

// Direct C-compatible feature extraction
EXPORT_API bool extract_features_from_buffer(
    const uint8_t* data, 
    size_t size, 
    CSimpleFeatures* out_features
);

EXPORT_API bool extract_features_from_file(
    const char* filepath, 
    CSimpleFeatures* out_features
);

// Extract full JSON report
EXPORT_API bool analyze_to_json_c(
    const uint8_t* data, 
    size_t size, 
    const char* filepath,
    char* json_out_buf, 
    size_t max_buf_len
);

EXPORT_API double calculate_shannon_entropy_c(
    const uint8_t* data, 
    size_t size
);

#ifdef __cplusplus
}
#endif

#endif // C_BINDINGS_H

