#include "../include/binary_feature_extractor.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace Analyzer {

static std::string escape_json_str(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) <= 0x1f) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
        } else {
            o << c;
        }
    }
    return o.str();
}

std::string CompleteBinaryReport::to_json() const {
    std::ostringstream json;
    json << std::fixed << std::setprecision(4);
    json << "{\n";
    json << "  \"file_path\": \"" << escape_json_str(file_path) << "\",\n";
    json << "  \"file_size\": " << file_size << ",\n";
    json << "  \"is_pe\": " << (is_pe ? "true" : "false") << ",\n";
    json << "  \"is_elf\": " << (is_elf ? "true" : "false") << ",\n";
    json << "  \"overall_entropy\": " << overall_entropy << ",\n";
    json << "  \"max_window_entropy\": " << max_window_entropy << ",\n";
    json << "  \"is_packed\": " << (is_packed ? "true" : "false") << ",\n";
    json << "  \"total_strings\": " << total_strings << ",\n";
    json << "  \"ascii_strings\": " << ascii_strings << ",\n";
    json << "  \"unicode_strings\": " << unicode_strings << ",\n";
    json << "  \"avg_string_len\": " << avg_string_len << ",\n";
    json << "  \"cumulative_threat_score\": " << signatures.cumulative_threat_score << ",\n";

    // ML Feature Vector
    json << "  \"ml_feature_vector\": [";
    for (size_t i = 0; i < ml_feature_vector.size(); ++i) {
        json << ml_feature_vector[i] << (i + 1 < ml_feature_vector.size() ? ", " : "");
    }
    json << "],\n";

    // IOCs
    json << "  \"iocs\": {\n";
    
    // URLs
    json << "    \"urls\": [";
    for (size_t i = 0; i < iocs.urls.size(); ++i) {
        json << "\"" << escape_json_str(iocs.urls[i]) << "\"" << (i + 1 < iocs.urls.size() ? ", " : "");
    }
    json << "],\n";

    // IPs
    json << "    \"ip_addresses\": [";
    for (size_t i = 0; i < iocs.ip_addresses.size(); ++i) {
        json << "\"" << escape_json_str(iocs.ip_addresses[i]) << "\"" << (i + 1 < iocs.ip_addresses.size() ? ", " : "");
    }
    json << "],\n";

    // Suspicious Commands
    json << "    \"suspicious_commands\": [";
    for (size_t i = 0; i < iocs.suspicious_commands.size(); ++i) {
        json << "\"" << escape_json_str(iocs.suspicious_commands[i]) << "\"" << (i + 1 < iocs.suspicious_commands.size() ? ", " : "");
    }
    json << "],\n";

    // Suspicious APIs
    json << "    \"suspicious_apis\": [";
    for (size_t i = 0; i < iocs.suspicious_apis.size(); ++i) {
        json << "\"" << escape_json_str(iocs.suspicious_apis[i]) << "\"" << (i + 1 < iocs.suspicious_apis.size() ? ", " : "");
    }
    json << "],\n";

    // Registry Keys
    json << "    \"registry_keys\": [";
    for (size_t i = 0; i < iocs.registry_keys.size(); ++i) {
        json << "\"" << escape_json_str(iocs.registry_keys[i]) << "\"" << (i + 1 < iocs.registry_keys.size() ? ", " : "");
    }
    json << "]\n";
    json << "  },\n";

    // Signatures
    json << "  \"rule_matches\": [\n";
    for (size_t i = 0; i < signatures.matches.size(); ++i) {
        const auto& m = signatures.matches[i];
        json << "    {\n";
        json << "      \"rule_name\": \"" << escape_json_str(m.rule_name) << "\",\n";
        json << "      \"category\": \"" << escape_json_str(m.category) << "\",\n";
        json << "      \"mitre\": \"" << escape_json_str(m.mitre_technique_id) << "\",\n";
        json << "      \"severity\": " << m.severity << ",\n";
        json << "      \"description\": \"" << escape_json_str(m.description) << "\"\n";
        json << "    }" << (i + 1 < signatures.matches.size() ? "," : "") << "\n";
    }
    json << "  ]\n";
    json << "}";

    return json.str();
}

CompleteBinaryReport BinaryFeatureExtractor::analyze_buffer(
    const uint8_t* buffer, 
    size_t size, 
    const std::string& source_path
) {
    CompleteBinaryReport report;
    report.file_path = source_path;
    report.file_size = static_cast<uint64_t>(size);
    report.is_pe = false;
    report.is_elf = false;

    if (!buffer || size == 0) {
        report.overall_entropy = 0.0;
        report.max_window_entropy = 0.0;
        report.is_packed = false;
        report.total_strings = 0;
        report.ascii_strings = 0;
        report.unicode_strings = 0;
        report.avg_string_len = 0.0;
        report.ml_feature_vector = std::vector<double>(12, 0.0);
        return report;
    }

    // 1. Check Magic Format
    if (size >= 64 && *(const uint16_t*)buffer == 0x5A4D) {
        report.is_pe = true;
    } else if (size >= 4 && *(const uint32_t*)buffer == 0x464C457F) {
        report.is_elf = true;
    }

    // 2. Entropy Analysis
    EntropyResult ent_res = EntropyCalculator::analyze_entropy(buffer, size);
    report.overall_entropy = ent_res.overall_entropy;
    report.max_window_entropy = ent_res.max_window_entropy;
    report.is_packed = ent_res.is_likely_packed;

    // 3. String Tokenization & IOC Extraction
    StringAnalysisResult str_res = StringTokenizer::extract_and_tokenize(buffer, size);
    report.total_strings = str_res.total_strings_count;
    report.ascii_strings = str_res.ascii_strings_count;
    report.unicode_strings = str_res.unicode_strings_count;
    report.avg_string_len = str_res.average_string_length;
    report.iocs = str_res.iocs;

    // 4. Structural Signatures
    report.signatures = SignatureDetector::evaluate(buffer, size, report.iocs, report.is_packed);

    // 5. Construct 12-Dimensional Normalized ML Feature Vector
    report.ml_feature_vector.resize(12);
    report.ml_feature_vector[0] = std::clamp(report.overall_entropy / 8.0, 0.0, 1.0);
    report.ml_feature_vector[1] = std::clamp(report.max_window_entropy / 8.0, 0.0, 1.0);
    report.ml_feature_vector[2] = report.is_packed ? 1.0 : 0.0;
    report.ml_feature_vector[3] = std::clamp(std::log10(static_cast<double>(size) + 1.0) / 10.0, 0.0, 1.0);
    report.ml_feature_vector[4] = std::clamp(std::log10(static_cast<double>(report.total_strings) + 1.0) / 6.0, 0.0, 1.0);
    report.ml_feature_vector[5] = std::clamp(report.avg_string_len / 50.0, 0.0, 1.0);
    report.ml_feature_vector[6] = std::clamp(static_cast<double>(report.iocs.suspicious_apis.size()) / 15.0, 0.0, 1.0);
    report.ml_feature_vector[7] = std::clamp(static_cast<double>(report.iocs.urls.size() + report.iocs.ip_addresses.size()) / 8.0, 0.0, 1.0);
    report.ml_feature_vector[8] = report.signatures.has_injection_pattern ? 1.0 : 0.0;
    report.ml_feature_vector[9] = report.signatures.has_ransomware_pattern ? 1.0 : 0.0;
    report.ml_feature_vector[10] = report.signatures.has_evasion_pattern ? 1.0 : 0.0;
    report.ml_feature_vector[11] = std::clamp(static_cast<double>(report.signatures.cumulative_threat_score) / 100.0, 0.0, 1.0);

    return report;
}

CompleteBinaryReport BinaryFeatureExtractor::analyze_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        CompleteBinaryReport report;
        report.file_path = filepath;
        report.file_size = 0;
        report.ml_feature_vector = std::vector<double>(12, 0.0);
        return report;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size <= 0) {
        CompleteBinaryReport report;
        report.file_path = filepath;
        report.file_size = 0;
        report.ml_feature_vector = std::vector<double>(12, 0.0);
        return report;
    }

    // Limit buffer read to 32MB max for high speed
    std::streamsize to_read = std::min(size, static_cast<std::streamsize>(32 * 1024 * 1024));
    std::vector<uint8_t> buffer(static_cast<size_t>(to_read));

    if (file.read(reinterpret_cast<char*>(buffer.data()), to_read)) {
        CompleteBinaryReport r = analyze_buffer(buffer.data(), buffer.size(), filepath);
        r.file_size = static_cast<uint64_t>(size);
        return r;
    }

    CompleteBinaryReport report;
    report.file_path = filepath;
    return report;
}

} // namespace Analyzer

