#include "../include/signature_detector.hpp"
#include <algorithm>

namespace Analyzer {

static bool list_contains(const std::vector<std::string>& vec, const std::string& target) {
    for (const auto& item : vec) {
        if (item.find(target) != std::string::npos) {
            return true;
        }
    }
    return false;
}

SignatureAnalysisResult SignatureDetector::evaluate(
    const uint8_t* data, 
    size_t size, 
    const ExtractedIOCs& iocs,
    bool is_high_entropy
) {
    SignatureAnalysisResult res;
    res.has_injection_pattern = false;
    res.has_ransomware_pattern = false;
    res.has_evasion_pattern = false;
    res.has_persistence_pattern = false;
    res.has_shadow_copy_tampering = false;
    res.cumulative_threat_score = 0;

    // Rule 1: High Entropy / Packing Detection (T1027 - Obfuscated Files)
    if (is_high_entropy) {
        RuleMatch m;
        m.rule_name = "Packed_Or_Encrypted_Binary";
        m.category = "PACKER";
        m.description = "File exhibits abnormally high Shannon entropy (>7.15) indicating packing, compression, or encryption.";
        m.mitre_technique_id = "T1027";
        m.severity = 3;
        res.matches.push_back(m);
        res.cumulative_threat_score += 25;
    }

    // Rule 2: Process Injection Pattern (T1055 - Process Injection)
    bool has_alloc = list_contains(iocs.suspicious_apis, "VirtualAlloc") || 
                     list_contains(iocs.suspicious_apis, "VirtualAllocEx");
    bool has_write = list_contains(iocs.suspicious_apis, "WriteProcessMemory");
    bool has_thread = list_contains(iocs.suspicious_apis, "CreateRemoteThread") || 
                      list_contains(iocs.suspicious_apis, "QueueUserAPC") ||
                      list_contains(iocs.suspicious_apis, "SetThreadContext");

    if (has_alloc && (has_write || has_thread)) {
        res.has_injection_pattern = true;
        RuleMatch m;
        m.rule_name = "Classic_Process_Injection";
        m.category = "INJECTION";
        m.description = "Binary combines memory allocation with cross-process memory writing or thread execution.";
        m.mitre_technique_id = "T1055";
        m.severity = 4;
        res.matches.push_back(m);
        res.cumulative_threat_score += 35;
    }

    // Rule 3: Anti-Debugging / Sandbox Evasion (T1497)
    bool has_debug = list_contains(iocs.suspicious_apis, "IsDebuggerPresent") || 
                     list_contains(iocs.suspicious_apis, "CheckRemoteDebuggerPresent") ||
                     list_contains(iocs.suspicious_apis, "NtQueryInformationProcess");
    if (has_debug) {
        res.has_evasion_pattern = true;
        RuleMatch m;
        m.rule_name = "Anti_Analysis_Debugger_Check";
        m.category = "EVASION";
        m.description = "Binary queries operating system debugger status to evade sandbox dynamic analysis.";
        m.mitre_technique_id = "T1497";
        m.severity = 2;
        res.matches.push_back(m);
        res.cumulative_threat_score += 15;
    }

    // Rule 4: Ransomware Activity (T1486)
    bool has_crypto = list_contains(iocs.suspicious_apis, "CryptEncrypt") || 
                      list_contains(iocs.suspicious_apis, "CryptDecrypt");
    bool has_ransom_text = !iocs.ransomware_keywords.empty();
    if (has_crypto && has_ransom_text) {
        res.has_ransomware_pattern = true;
        RuleMatch m;
        m.rule_name = "Ransomware_Behavior_Signature";
        m.category = "RANSOMWARE";
        m.description = "Binary contains cryptographic routines coupled with extortion/ransom demand terminology.";
        m.mitre_technique_id = "T1486";
        m.severity = 4;
        res.matches.push_back(m);
        res.cumulative_threat_score += 40;
    }

    // Rule 5: Shadow Copy Deletion (T1490 - Inhibit System Recovery)
    if (list_contains(iocs.suspicious_commands, "vssadmin delete shadows") ||
        list_contains(iocs.suspicious_commands, "bcdedit")) {
        res.has_shadow_copy_tampering = true;
        RuleMatch m;
        m.rule_name = "System_Recovery_Inhibition";
        m.category = "DEFENSE_EVASION";
        m.description = "Detected destructive commands attempting to wipe Windows Volume Shadow Copies.";
        m.mitre_technique_id = "T1490";
        m.severity = 4;
        res.matches.push_back(m);
        res.cumulative_threat_score += 30;
    }

    // Rule 6: Registry Persistence (T1547.001)
    if (!iocs.registry_keys.empty()) {
        res.has_persistence_pattern = true;
        RuleMatch m;
        m.rule_name = "Registry_Persistence_Key";
        m.category = "PERSISTENCE";
        m.description = "References Run/RunOnce autostart execution keys in the Windows Registry.";
        m.mitre_technique_id = "T1547.001";
        m.severity = 3;
        res.matches.push_back(m);
        res.cumulative_threat_score += 20;
    }

    // Rule 7: C2 Network Communication (T1071)
    if (!iocs.urls.empty() || !iocs.onion_domains.empty()) {
        RuleMatch m;
        m.rule_name = "Hardcoded_C2_Endpoints";
        m.category = "COMMAND_AND_CONTROL";
        m.description = "Binary contains hardcoded remote URLs or Darknet .onion endpoints.";
        m.mitre_technique_id = "T1071";
        m.severity = 2;
        res.matches.push_back(m);
        res.cumulative_threat_score += 15;
    }

    // Rule 8: Obfuscated PowerShell Execution (T1059.001)
    if (list_contains(iocs.suspicious_commands, "-enc") || 
        list_contains(iocs.suspicious_commands, "downloadstring") ||
        list_contains(iocs.suspicious_commands, "invoke-expression")) {
        RuleMatch m;
        m.rule_name = "Obfuscated_PowerShell_Execution";
        m.category = "EXECUTION";
        m.description = "Detected suspicious in-memory encoded PowerShell execution commands.";
        m.mitre_technique_id = "T1059.001";
        m.severity = 3;
        res.matches.push_back(m);
        res.cumulative_threat_score += 25;
    }

    // Normalize cumulative threat score to 0..100
    if (res.cumulative_threat_score > 100) {
        res.cumulative_threat_score = 100;
    }

    return res;
}

} // namespace Analyzer

