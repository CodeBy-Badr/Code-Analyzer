#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../include/entropy_calculator.hpp"
#include "../include/string_tokenizer.hpp"
#include "../include/signature_detector.hpp"
#include "../include/binary_feature_extractor.hpp"

namespace py = pybind11;

static py::dict report_to_pydict(const Analyzer::CompleteBinaryReport& rep) {
    py::dict d;
    d["file_path"] = rep.file_path;
    d["file_size"] = rep.file_size;
    d["is_pe"] = rep.is_pe;
    d["is_elf"] = rep.is_elf;
    d["overall_entropy"] = rep.overall_entropy;
    d["max_window_entropy"] = rep.max_window_entropy;
    d["is_packed"] = rep.is_packed;
    d["total_strings"] = rep.total_strings;
    d["ascii_strings"] = rep.ascii_strings;
    d["unicode_strings"] = rep.unicode_strings;
    d["avg_string_len"] = rep.avg_string_len;
    d["threat_score"] = rep.signatures.cumulative_threat_score;
    d["ml_features"] = rep.ml_feature_vector;

    // IOCs
    py::dict iocs;
    iocs["urls"] = rep.iocs.urls;
    iocs["ip_addresses"] = rep.iocs.ip_addresses;
    iocs["onion_domains"] = rep.iocs.onion_domains;
    iocs["suspicious_commands"] = rep.iocs.suspicious_commands;
    iocs["suspicious_apis"] = rep.iocs.suspicious_apis;
    iocs["registry_keys"] = rep.iocs.registry_keys;
    iocs["ransomware_keywords"] = rep.iocs.ransomware_keywords;
    d["iocs"] = iocs;

    // Matches
    py::list matches;
    for (const auto& m : rep.signatures.matches) {
        py::dict md;
        md["rule_name"] = m.rule_name;
        md["category"] = m.category;
        md["mitre"] = m.mitre_technique_id;
        md["severity"] = m.severity;
        md["description"] = m.description;
        matches.append(md);
    }
    d["rule_matches"] = matches;

    return d;
}

PYBIND11_MODULE(feature_engine, m) {
    m.doc() = "High-performance C++ Malware Feature Extraction Engine";

    m.def("calculate_entropy", [](py::bytes data) {
        std::string s = data;
        return Analyzer::EntropyCalculator::calculate_buffer_entropy(
            reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }, "Calculate Shannon entropy of raw bytes");

    m.def("analyze_buffer", [](py::bytes data, const std::string& name = "memory_buffer") {
        std::string s = data;
        Analyzer::CompleteBinaryReport rep = Analyzer::BinaryFeatureExtractor::analyze_buffer(
            reinterpret_cast<const uint8_t*>(s.data()), s.size(), name);
        return report_to_pydict(rep);
    }, py::arg("data"), py::arg("name") = "memory_buffer", "Analyze raw binary buffer");

    m.def("analyze_file", [](const std::string& filepath) {
        Analyzer::CompleteBinaryReport rep = Analyzer::BinaryFeatureExtractor::analyze_file(filepath);
        return report_to_pydict(rep);
    }, py::arg("filepath"), "Analyze binary or script file on disk");

    m.def("get_feature_vector", [](const std::string& filepath) {
        Analyzer::CompleteBinaryReport rep = Analyzer::BinaryFeatureExtractor::analyze_file(filepath);
        return rep.ml_feature_vector;
    }, py::arg("filepath"), "Extract 12-dimensional normalized ML feature vector");
}

