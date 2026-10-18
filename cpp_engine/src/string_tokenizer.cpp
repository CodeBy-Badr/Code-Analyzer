#include "../include/string_tokenizer.hpp"
#include <cctype>
#include <algorithm>
#include <set>

namespace Analyzer {

static std::string to_lower_str(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lower;
}

void StringTokenizer::extract_ascii_strings(
    const uint8_t* data, 
    size_t size, 
    size_t min_len, 
    std::vector<std::string>& out
) {
    if (!data || size < min_len) return;

    std::string current;
    current.reserve(64);

    for (size_t i = 0; i < size; ++i) {
        uint8_t byte = data[i];
        // Printable ASCII (space through tilde)
        if (byte >= 32 && byte <= 126) {
            current.push_back(static_cast<char>(byte));
        } else {
            if (current.length() >= min_len) {
                out.push_back(current);
            }
            current.clear();
        }
    }
    if (current.length() >= min_len) {
        out.push_back(current);
    }
}

void StringTokenizer::extract_unicode_strings(
    const uint8_t* data, 
    size_t size, 
    size_t min_len, 
    std::vector<std::string>& out
) {
    if (!data || size < (min_len * 2)) return;

    std::string current;
    current.reserve(64);

    for (size_t i = 0; i + 1 < size; i += 2) {
        uint8_t b1 = data[i];
        uint8_t b2 = data[i + 1];

        // UTF-16LE ASCII subset (character followed by null byte)
        if ((b1 >= 32 && b1 <= 126) && b2 == 0) {
            current.push_back(static_cast<char>(b1));
        } else {
            if (current.length() >= min_len) {
                out.push_back(current);
            }
            current.clear();
        }
    }
    if (current.length() >= min_len) {
        out.push_back(current);
    }
}

void StringTokenizer::classify_tokens(
    const std::vector<std::string>& strings, 
    ExtractedIOCs& iocs
) {
    static const std::regex url_regex(R"(https?:\/\/[a-zA-Z0-9\-\.]+(\:[0-9]+)?(\/[^\s]*)?)", std::regex::optimize);
    static const std::regex ip_regex(R"(\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)", std::regex::optimize);
    static const std::regex onion_regex(R"([a-z2-7]{16,56}\.onion)", std::regex::icase | std::regex::optimize);

    static const std::vector<std::string> SUSPICIOUS_COMMANDS = {
        "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "schtasks",
        "vssadmin delete shadows", "bcdedit /set", "invoke-expression",
        "iex", "downloadstring", "bypass", "-enc", "-encodedcommand"
    };

    static const std::vector<std::string> REGISTRY_KEYS = {
        "currentversion\\run", "currentversion\\runonce",
        "system\\currentcontrolset\\services",
        "software\\microsoft\\windows nt\\currentversion\\winlogon"
    };

    static const std::vector<std::string> HIGH_RISK_APIS = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "OpenProcess", "QueueUserAPC", "SetThreadContext", "GetThreadContext",
        "NtMapViewOfSection", "ZwMapViewOfSection", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "CreateProcessA", "CreateProcessW", "RegSetValueExA",
        "RegSetValueExW", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "InternetOpenA", "InternetOpenUrlA",
        "URLDownloadToFileA", "URLDownloadToFileW", "CryptEncrypt", "CryptDecrypt",
        "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW"
    };

    static const std::vector<std::string> RANSOM_WORDS = {
        "ransom", "decrypt", "encrypted", "bitcoin", "wallet", "restore files",
        "private key", "tor browser", "pay to recover", "locked your files"
    };

    std::set<std::string> seen_urls;
    std::set<std::string> seen_ips;
    std::set<std::string> seen_onions;
    std::set<std::string> seen_cmds;
    std::set<std::string> seen_regs;
    std::set<std::string> seen_apis;
    std::set<std::string> seen_ransoms;

    for (const auto& s : strings) {
        if (s.empty()) continue;

        // 1. Regex URL search
        std::smatch match;
        if (std::regex_search(s, match, url_regex)) {
            std::string url = match.str();
            if (seen_urls.insert(url).second) {
                iocs.urls.push_back(url);
            }
        }

        // 2. Regex IP search
        if (std::regex_search(s, match, ip_regex)) {
            std::string ip = match.str();
            // Filter local zero or standard localhost if preferred
            if (ip != "0.0.0.0" && ip != "255.255.255.255") {
                if (seen_ips.insert(ip).second) {
                    iocs.ip_addresses.push_back(ip);
                }
            }
        }

        // 3. Onion search
        if (std::regex_search(s, match, onion_regex)) {
            std::string onion = match.str();
            if (seen_onions.insert(onion).second) {
                iocs.onion_domains.push_back(onion);
            }
        }

        std::string lower = to_lower_str(s);

        // 4. Command execution strings
        for (const auto& cmd : SUSPICIOUS_COMMANDS) {
            if (lower.find(cmd) != std::string::npos) {
                if (seen_cmds.insert(s).second) {
                    iocs.suspicious_commands.push_back(s);
                }
                break;
            }
        }

        // 5. Registry persistence strings
        for (const auto& reg : REGISTRY_KEYS) {
            if (lower.find(reg) != std::string::npos) {
                if (seen_regs.insert(s).second) {
                    iocs.registry_keys.push_back(s);
                }
                break;
            }
        }

        // 6. Suspicious API exact / sub match
        for (const auto& api : HIGH_RISK_APIS) {
            if (s.find(api) != std::string::npos) {
                if (seen_apis.insert(api).second) {
                    iocs.suspicious_apis.push_back(api);
                }
            }
        }

        // 7. Ransomware terminology
        for (const auto& rw : RANSOM_WORDS) {
            if (lower.find(rw) != std::string::npos) {
                if (seen_ransoms.insert(s).second) {
                    iocs.ransomware_keywords.push_back(s);
                }
                break;
            }
        }
    }
}

StringAnalysisResult StringTokenizer::extract_and_tokenize(
    const uint8_t* data, 
    size_t size, 
    size_t min_len
) {
    StringAnalysisResult result;
    result.total_strings_count = 0;
    result.ascii_strings_count = 0;
    result.unicode_strings_count = 0;
    result.average_string_length = 0.0;

    if (!data || size < min_len) return result;

    std::vector<std::string> all_strings;
    std::vector<std::string> ascii_strings;
    std::vector<std::string> unicode_strings;

    extract_ascii_strings(data, size, min_len, ascii_strings);
    extract_unicode_strings(data, size, min_len, unicode_strings);

    all_strings.insert(all_strings.end(), ascii_strings.begin(), ascii_strings.end());
    all_strings.insert(all_strings.end(), unicode_strings.begin(), unicode_strings.end());

    result.ascii_strings_count = ascii_strings.size();
    result.unicode_strings_count = unicode_strings.size();
    result.total_strings_count = all_strings.size();

    size_t total_len = 0;
    for (const auto& s : all_strings) {
        total_len += s.length();
    }
    if (result.total_strings_count > 0) {
        result.average_string_length = static_cast<double>(total_len) / result.total_strings_count;
    }

    // Sample strings preview
    size_t sample_count = std::min(all_strings.size(), MAX_SAMPLE_STRINGS);
    for (size_t i = 0; i < sample_count; ++i) {
        result.sample_strings.push_back(all_strings[i]);
    }

    // Classify IOCs
    classify_tokens(all_strings, result.iocs);

    return result;
}

} // namespace Analyzer

