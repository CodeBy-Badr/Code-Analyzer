#ifndef BINARY_FEATURE_EXTRACTOR_HPP
#define BINARY_FEATURE_EXTRACTOR_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include "entropy_calculator.hpp"
#include "string_tokenizer.hpp"
#include "signature_detector.hpp"

namespace Analyzer {

struct CompleteBinaryReport {
    std::string file_path;
    uint64_t file_size;
    bool is_pe;
    bool is_elf;
    
    // Entropy metrics
    double overall_entropy;
    double max_window_entropy;
    bool is_packed;
    
    // String metrics
    size_t total_strings;
    size_t ascii_strings;
    size_t unicode_strings;
    double avg_string_len;
    
    // IOCs
    ExtractedIOCs iocs;
    
    // Structural signatures
    SignatureAnalysisResult signatures;
    
    // Numeric Feature Vector for ML Model (12 normalized dimensions)
    std::vector<double> ml_feature_vector;
    
    // JSON representation
    std::string to_json() const;
};

class BinaryFeatureExtractor {
public:
    static CompleteBinaryReport analyze_buffer(
        const uint8_t* buffer, 
        size_t size, 
        const std::string& source_path = "memory_buffer"
    );

    static CompleteBinaryReport analyze_file(const std::string& filepath);
};

} // namespace Analyzer

#endif // BINARY_FEATURE_EXTRACTOR_HPP

