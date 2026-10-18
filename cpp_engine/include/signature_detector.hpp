#ifndef SIGNATURE_DETECTOR_HPP
#define SIGNATURE_DETECTOR_HPP

#include <string>
#include <vector>
#include <cstdint>
#include "string_tokenizer.hpp"

namespace Analyzer {

struct RuleMatch {
    std::string rule_name;
    std::string category;     // e.g., "PACKER", "INJECTION", "RANSOMWARE", "EVASION"
    std::string description;
    std::string mitre_technique_id; // e.g., "T1055"
    int severity;             // 1 = Low, 2 = Medium, 3 = High, 4 = Critical
};

struct SignatureAnalysisResult {
    std::vector<RuleMatch> matches;
    bool has_injection_pattern;
    bool has_ransomware_pattern;
    bool has_evasion_pattern;
    bool has_persistence_pattern;
    bool has_shadow_copy_tampering;
    int cumulative_threat_score; // 0 to 100
};

class SignatureDetector {
public:
    static SignatureAnalysisResult evaluate(
        const uint8_t* data, 
        size_t size, 
        const ExtractedIOCs& iocs,
        bool is_high_entropy
    );
};

} // namespace Analyzer

#endif // SIGNATURE_DETECTOR_HPP

