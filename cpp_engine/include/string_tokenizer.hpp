#ifndef STRING_TOKENIZER_HPP
#define STRING_TOKENIZER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <regex>

namespace Analyzer {

struct ExtractedIOCs {
    std::vector<std::string> urls;
    std::vector<std::string> ip_addresses;
    std::vector<std::string> onion_domains;
    std::vector<std::string> suspicious_commands;
    std::vector<std::string> registry_keys;
    std::vector<std::string> suspicious_apis;
    std::vector<std::string> ransomware_keywords;
};

struct StringAnalysisResult {
    size_t total_strings_count;
    size_t ascii_strings_count;
    size_t unicode_strings_count;
    double average_string_length;
    ExtractedIOCs iocs;
    std::vector<std::string> sample_strings; // First 50 strings for inspection
};

class StringTokenizer {
public:
    static constexpr size_t MIN_STRING_LEN = 4;
    static constexpr size_t MAX_SAMPLE_STRINGS = 50;

    static StringAnalysisResult extract_and_tokenize(
        const uint8_t* data, 
        size_t size, 
        size_t min_len = MIN_STRING_LEN
    );

private:
    static void extract_ascii_strings(
        const uint8_t* data, 
        size_t size, 
        size_t min_len, 
        std::vector<std::string>& out
    );

    static void extract_unicode_strings(
        const uint8_t* data, 
        size_t size, 
        size_t min_len, 
        std::vector<std::string>& out
    );

    static void classify_tokens(
        const std::vector<std::string>& strings, 
        ExtractedIOCs& iocs
    );
};

} // namespace Analyzer

#endif // STRING_TOKENIZER_HPP

